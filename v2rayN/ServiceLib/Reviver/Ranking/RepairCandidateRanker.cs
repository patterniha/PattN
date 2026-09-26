using ServiceLib.Reviver.Models;

namespace ServiceLib.Reviver.Ranking;

/// <summary>
/// Ranks only candidates that have already proven end-to-end runtime viability. Reliability and semantic safety
/// intentionally dominate raw speed so a fast but fragile repair cannot outrank a stable low-risk repair.
/// </summary>
public sealed class RepairCandidateRanker
{
    public RepairCandidateScore Score(RepairCandidate candidate)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        var validation = candidate.Validation
            ?? throw new InvalidOperationException("Runtime validation evidence is required before ranking a repair candidate.");

        var attempts = Math.Max(1, validation.Attempts);
        var reliability = Clamp01((double)validation.Successes / attempts);
        var stability = Clamp01((double)validation.ConsecutiveSuccesses / attempts);
        var lossQuality = Clamp01(1d - (validation.LossRate ?? (1d - reliability)));
        var latencyQuality = LatencyQuality(validation.MedianLatencyMs);
        var mutationSafety = MutationSafety(candidate.Mutations);
        var mutationSimplicity = 1d / (1d + Math.Max(0, candidate.Mutations.Count - 1) * 0.25d);
        var resolverQuality = ResolverQuality(candidate.Evidence);

        var overall01 =
            reliability * 0.42d +
            stability * 0.14d +
            lossQuality * 0.14d +
            latencyQuality * 0.10d +
            mutationSafety * 0.10d +
            mutationSimplicity * 0.05d +
            resolverQuality * 0.05d;

        return new RepairCandidateScore
        {
            Overall = Math.Round(Clamp01(overall01) * 100d, 3),
            Reliability = reliability,
            Stability = stability,
            LossQuality = lossQuality,
            LatencyQuality = latencyQuality,
            MutationSafety = mutationSafety,
            MutationSimplicity = mutationSimplicity,
            ResolverQuality = resolverQuality,
        };
    }

    public IReadOnlyList<RepairCandidate> Rank(IEnumerable<RepairCandidate> candidates)
    {
        ArgumentNullException.ThrowIfNull(candidates);
        var viable = candidates
            .Where(x => x.State == ERepairCandidateState.RuntimeValidated && x.Validation is not null)
            .ToArray();

        foreach (var candidate in viable)
        {
            candidate.ScoreBreakdown = Score(candidate);
            candidate.Score = candidate.ScoreBreakdown.Overall;
        }

        return viable
            .OrderByDescending(x => x.Score ?? 0d)
            .ThenBy(x => x.Mutations.Count)
            .ThenBy(x => x.Validation?.MedianLatencyMs ?? double.MaxValue)
            .ThenBy(x => x.Id, StringComparer.Ordinal)
            .ToArray();
    }

    private static double LatencyQuality(double? latencyMs)
    {
        if (latencyMs is null || latencyMs < 0 || double.IsNaN(latencyMs.Value) || double.IsInfinity(latencyMs.Value))
        {
            return 0.5d; // unknown latency is neutral, not a failure
        }
        return 1d / (1d + latencyMs.Value / 100d);
    }

    private static double ResolverQuality(IReadOnlyList<RepairEvidence> evidence)
    {
        var depth = evidence.LastOrDefault(x => string.Equals(
            x.Kind,
            ServiceLib.Reviver.Services.ResolverDepthRepairEvidence.EvidenceKind,
            StringComparison.Ordinal));

        if (depth is null || !depth.Data.TryGetValue("quality", out var quality))
        {
            return 0.5d;
        }

        var baseQuality = quality.Trim().ToLowerInvariant() switch
        {
            "strong" => 1.0d,
            "usable" => 0.82d,
            "degraded" => 0.58d,
            "unstable" => 0.32d,
            "suspicious" => 0.08d,
            "unusable" => 0.0d,
            _ => 0.5d,
        };

        if (depth.Data.TryGetValue("reliabilityFloor", out var rawReliability)
            && double.TryParse(rawReliability, System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out var reliability))
        {
            baseQuality = baseQuality * 0.7d + Clamp01(reliability) * 0.3d;
        }

        if (depth.Data.TryGetValue("interceptionSuspected", out var rawSuspicion)
            && bool.TryParse(rawSuspicion, out var suspicious)
            && suspicious)
        {
            baseQuality = Math.Min(baseQuality, 0.08d);
        }

        return Clamp01(baseQuality);
    }

    private static double MutationSafety(IReadOnlyList<RepairMutation> mutations)
    {
        if (mutations.Count == 0)
        {
            return 1d;
        }

        var riskiest = mutations.Max(x => x.Confidence);
        return riskiest switch
        {
            ERepairConfidence.Equivalent => 1d,
            ERepairConfidence.LowRisk => 0.92d,
            ERepairConfidence.EvidenceBacked => 0.82d,
            ERepairConfidence.Speculative => 0.45d,
            _ => 0.5d,
        };
    }

    private static double Clamp01(double value) => Math.Clamp(value, 0d, 1d);
}
