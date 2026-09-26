using ServiceLib.Reviver.Models;

namespace ServiceLib.Reviver.Services;

public static class RepairOutcomeComparer
{
    public static RepairOutcomeComparison Compare(
        RepairValidationEvidence? baseline,
        RepairValidationEvidence candidate)
    {
        ArgumentNullException.ThrowIfNull(candidate);

        var candidateReliability = Reliability(candidate);
        if (baseline is null || baseline.Attempts <= 0)
        {
            return new RepairOutcomeComparison
            {
                BaselineAvailable = false,
                CandidateReliability = candidateReliability,
                CandidateMedianLatencyMs = candidate.MedianLatencyMs,
                CandidateLossRate = candidate.LossRate,
                Verdict = "unknown",
                Reasons = ["baseline-runtime-evidence-unavailable"],
            };
        }

        var baselineReliability = Reliability(baseline);
        var reliabilityDelta = candidateReliability - baselineReliability;
        var latencyDelta = Delta(candidate.MedianLatencyMs, baseline.MedianLatencyMs);
        var lossDelta = Delta(candidate.LossRate, baseline.LossRate);

        var reasons = new List<string>();
        var improvement = 0;
        var regression = 0;

        if (reliabilityDelta >= 0.20d)
        {
            improvement++;
            reasons.Add("reliability-improved");
        }
        else if (reliabilityDelta <= -0.10d)
        {
            regression++;
            reasons.Add("reliability-regressed");
        }

        if (LatencyImproved(baseline.MedianLatencyMs, candidate.MedianLatencyMs))
        {
            improvement++;
            reasons.Add("latency-improved");
        }
        else if (LatencyRegressed(baseline.MedianLatencyMs, candidate.MedianLatencyMs))
        {
            regression++;
            reasons.Add("latency-regressed");
        }

        if (lossDelta is <= -0.20d)
        {
            improvement++;
            reasons.Add("loss-improved");
        }
        else if (lossDelta is >= 0.10d)
        {
            regression++;
            reasons.Add("loss-regressed");
        }

        var verdict = regression > 0 && regression >= improvement
            ? "regressed"
            : improvement > 0
                ? "improved"
                : "stable";

        return new RepairOutcomeComparison
        {
            BaselineAvailable = true,
            BaselineReliability = baselineReliability,
            CandidateReliability = candidateReliability,
            ReliabilityDelta = reliabilityDelta,
            BaselineMedianLatencyMs = baseline.MedianLatencyMs,
            CandidateMedianLatencyMs = candidate.MedianLatencyMs,
            LatencyDeltaMs = latencyDelta,
            BaselineLossRate = baseline.LossRate,
            CandidateLossRate = candidate.LossRate,
            LossDelta = lossDelta,
            Verdict = verdict,
            Reasons = reasons,
        };
    }

    private static double Reliability(RepairValidationEvidence value)
        => value.Attempts <= 0 ? 0d : Math.Clamp((double)value.Successes / value.Attempts, 0d, 1d);

    private static double? Delta(double? after, double? before)
        => after is null || before is null ? null : after.Value - before.Value;

    private static bool LatencyImproved(double? before, double? after)
        => before is > 0 && after is >= 0 && after <= before * 0.80d;

    private static bool LatencyRegressed(double? before, double? after)
        => before is > 0 && after is >= 0 && after >= before * 1.25d;
}
