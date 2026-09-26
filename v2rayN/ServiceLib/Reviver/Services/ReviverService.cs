using ServiceLib.Reviver.Models;
using ServiceLib.Reviver.Normalization;
using ServiceLib.Reviver.Ranking;
using ServiceLib.Reviver.Strategies;
using ServiceLib.Reviver.Validation;

namespace ServiceLib.Reviver.Services;

/// <summary>
/// Failure-guided bounded repair planner. Strategies are ordered by relevance and risk, candidates are statically
/// validated and semantically deduplicated, and both global and per-strategy budgets are enforced.
/// Runtime/core validation is the next stage and consumes only candidates that survive this planner.
/// </summary>
public sealed class ReviverService(
    ProfileNormalizer normalizer,
    ProfileInvariantRegistry invariants,
    IEnumerable<IRepairStrategy> strategies,
    RepairPolicy? policy = null,
    RepairCandidateRanker? ranker = null,
    IEnumerable<IRepairLifecycleObserver>? observers = null)
{
    private readonly IReadOnlyList<IRepairStrategy> _strategies = strategies.ToArray();
    private readonly RepairPolicy _policy = policy ?? new RepairPolicy();
    private readonly RepairCandidateRanker _ranker = ranker ?? new RepairCandidateRanker();
    private readonly IReadOnlyList<IRepairLifecycleObserver> _observers = observers?.ToArray() ?? [];

    public RepairSession StartSession(ProfileItem profile)
    {
        var normalized = normalizer.Normalize(profile);
        return new RepairSession { Original = ProfileSnapshot.Capture(normalized) };
    }

    public async Task<RepairRunResult> ReviveAsync(
        ProfileItem profile,
        IRepairBaselineDiagnostic diagnostic,
        IRepairCandidateValidator validator,
        int? maxCandidates = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(diagnostic);
        ArgumentNullException.ThrowIfNull(validator);

        var session = StartSession(profile);
        var diagnosis = await diagnostic.DiagnoseAsync(session, cancellationToken);
        session.BaselineFailure = diagnosis.FailureClass;
        session.BaselineValidation = diagnosis.RuntimeValidation;
        if (diagnosis.IsHealthy)
        {
            return new RepairRunResult { Session = session, Diagnosis = diagnosis };
        }

        var planned = await PlanAsync(session, diagnosis.FailureClass, maxCandidates, cancellationToken);
        var validated = await ValidateAsync(planned, validator, cancellationToken);
        return new RepairRunResult
        {
            Session = session,
            Diagnosis = diagnosis,
            PlannedCandidates = planned,
            ValidatedCandidates = validated,
            RecommendedCandidate = validated.FirstOrDefault(),
        };
    }

    public async Task<IReadOnlyList<RepairCandidate>> PlanAsync(
        RepairSession session,
        ERepairFailureClass failureClass,
        int? maxCandidates = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        var budget = Math.Min(maxCandidates ?? _policy.MaxCandidates, _policy.MaxCandidates);
        if (budget <= 0)
        {
            return [];
        }

        session.BaselineFailure = failureClass;
        var candidates = new List<RepairCandidate>(Math.Min(budget, 32));
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var baseline = session.Original.CreateWorkingCopy();

        var orderedStrategies = _strategies
            .Where(x => _policy.Allows(x.Confidence) && x.CanApply(baseline, failureClass))
            .OrderBy(x => x.PriorityFor(failureClass))
            .ThenBy(x => x.Confidence)
            .ThenBy(x => x.Id, StringComparer.Ordinal)
            .ToArray();

        foreach (var strategy in orderedStrategies)
        {
            var strategyCount = 0;
            await foreach (var candidate in strategy.GenerateAsync(session, failureClass, cancellationToken).WithCancellation(cancellationToken))
            {
                if (strategyCount >= _policy.MaxCandidatesPerStrategy)
                {
                    break;
                }
                if (invariants.Validate(candidate.Profile).Count > 0)
                {
                    candidate.State = ERepairCandidateState.Rejected;
                    continue;
                }
                if (!seen.Add(RepairCandidateKey.Create(candidate.Profile)))
                {
                    continue;
                }

                candidate.State = ERepairCandidateState.StaticValidated;
                candidates.Add(candidate);
                session.Candidates.Add(candidate);
                strategyCount++;
                await NotifyPlannedAsync(candidate, cancellationToken);
                if (candidates.Count >= budget)
                {
                    return candidates;
                }
            }
        }
        return candidates;
    }
    public async Task<IReadOnlyList<RepairCandidate>> ValidateAsync(
        IEnumerable<RepairCandidate> candidates,
        IRepairCandidateValidator validator,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(candidates);
        ArgumentNullException.ThrowIfNull(validator);

        var validated = new List<RepairCandidate>();
        foreach (var candidate in candidates)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (candidate.State != ERepairCandidateState.StaticValidated)
            {
                continue;
            }

            candidate.Validation = await validator.ValidateAsync(candidate, cancellationToken);
            if (candidate.Validation.MeetsQuorum(_policy.MinimumRuntimeSuccesses))
            {
                candidate.State = ERepairCandidateState.RuntimeValidated;
                validated.Add(candidate);
            }
            else
            {
                candidate.State = ERepairCandidateState.Failed;
            }
            await NotifyValidatedAsync(candidate, cancellationToken);
        }
        return _ranker.Rank(validated);
    }

    private async Task NotifyPlannedAsync(RepairCandidate candidate, CancellationToken cancellationToken)
    {
        foreach (var observer in _observers)
        {
            try
            {
                await observer.CandidatePlannedAsync(candidate, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Logging.SaveLog($"Reviver lifecycle observer planned-event failure: {ex}");
            }
        }
    }

    private async Task NotifyValidatedAsync(RepairCandidate candidate, CancellationToken cancellationToken)
    {
        foreach (var observer in _observers)
        {
            try
            {
                await observer.CandidateValidatedAsync(candidate, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Logging.SaveLog($"Reviver lifecycle observer validation-event failure: {ex}");
            }
        }
    }

}
