using ServiceLib.Manager;
using ServiceLib.Reviver.Models;
using ServiceLib.Reviver.Normalization;
using ServiceLib.Reviver.Validation;

namespace ServiceLib.Reviver.Services;

/// <summary>
/// Diagnoses in increasing cost order. It stops at the first explanatory failure instead of masking a low-level
/// endpoint/DNS error behind a later core/application failure.
/// </summary>
public sealed class RepairBaselineDiagnostic(
    ProfileInvariantRegistry invariants,
    ProfileCoreCompatibility compatibility,
    IReviverEndpointPreflight endpointPreflight,
    IRepairCandidateValidator runtimeValidator,
    RepairPolicy? policy = null,
    Func<ProfileItem, ECoreType>? coreResolver = null) : IRepairBaselineDiagnostic
{
    private readonly RepairPolicy _policy = policy ?? new RepairPolicy();
    private readonly Func<ProfileItem, ECoreType> _coreResolver =
        coreResolver ?? (profile => AppManager.Instance.GetCoreType(profile, profile.ConfigType));

    public async Task<RepairDiagnosis> DiagnoseAsync(RepairSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        var profile = session.Original.CreateWorkingCopy();
        var evidence = new List<RepairEvidence>();

        var invariantErrors = invariants.Validate(profile);
        if (invariantErrors.Count > 0)
        {
            return new RepairDiagnosis
            {
                FailureClass = ERepairFailureClass.ProfileSemanticallyInvalid,
                InvariantViolations = invariantErrors.Select(x => new ProfileInvariantViolationView(x.Code, x.Message)).ToArray(),
            };
        }

        var coreType = _coreResolver(profile);
        if ((coreType is ECoreType.Xray or ECoreType.sing_box) && !compatibility.Supports(profile, coreType))
        {
            return new RepairDiagnosis { FailureClass = ERepairFailureClass.CoreUnsupported };
        }
        var coreValidation = NodeValidator.Validate(profile, coreType);
        if (!coreValidation.Success)
        {
            return new RepairDiagnosis
            {
                FailureClass = ERepairFailureClass.CoreConfigurationInvalid,
                CoreValidationErrors = coreValidation.Errors.ToArray(),
            };
        }

        var preflight = await endpointPreflight.CheckAsync(profile, cancellationToken);
        evidence.AddRange(preflight.Evidence);
        if (preflight.Applicable && !preflight.Reachable)
        {
            return new RepairDiagnosis
            {
                FailureClass = preflight.FailureClass,
                ResolvedAddresses = preflight.ResolvedAddresses,
                Evidence = evidence,
            };
        }

        var baselineCandidate = new RepairCandidate
        {
            SessionId = session.Id,
            Profile = profile,
            Mutations = [],
            FailureClassAddressed = ERepairFailureClass.Unknown,
            State = ERepairCandidateState.StaticValidated,
            Evidence = evidence.ToArray(),
        };
        var runtime = await runtimeValidator.ValidateAsync(baselineCandidate, cancellationToken);
        if (runtime.MeetsQuorum(_policy.MinimumRuntimeSuccesses))
        {
            return new RepairDiagnosis
            {
                IsHealthy = true,
                ResolvedAddresses = preflight.ResolvedAddresses,
                RuntimeValidation = runtime,
                Evidence = evidence,
            };
        }

        return new RepairDiagnosis
        {
            FailureClass = runtime.Failures.FirstOrDefault(ERepairFailureClass.ApplicationProbeFailure),
            ResolvedAddresses = preflight.ResolvedAddresses,
            RuntimeValidation = runtime,
            Evidence = evidence,
        };
    }
}
