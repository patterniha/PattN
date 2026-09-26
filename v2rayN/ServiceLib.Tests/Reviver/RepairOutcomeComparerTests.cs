using ServiceLib.Reviver.Models;
using ServiceLib.Reviver.Services;

namespace ServiceLib.Tests.Reviver;

public class RepairOutcomeComparerTests
{
    [Test]
    public async Task Compare_ShouldRemainUnknownWithoutBaselineRuntimeEvidence()
    {
        var candidate = new RepairValidationEvidence
        {
            Attempts = 3,
            Successes = 3,
            ConsecutiveSuccesses = 3,
            MedianLatencyMs = 50,
            LossRate = 0,
        };

        var result = RepairOutcomeComparer.Compare(null, candidate);

        await result.BaselineAvailable.Should().BeFalse();
        await result.Verdict.Should().BeEqualTo("unknown");
        await result.Reasons.Contains("baseline-runtime-evidence-unavailable").Should().BeTrue();
    }

    [Test]
    public async Task Compare_ShouldExplainMaterialImprovement()
    {
        var baseline = new RepairValidationEvidence
        {
            Attempts = 3,
            Successes = 1,
            ConsecutiveSuccesses = 1,
            MedianLatencyMs = 120,
            LossRate = 2d / 3d,
        };
        var candidate = new RepairValidationEvidence
        {
            Attempts = 3,
            Successes = 3,
            ConsecutiveSuccesses = 3,
            MedianLatencyMs = 60,
            LossRate = 0,
        };

        var result = RepairOutcomeComparer.Compare(baseline, candidate);

        await result.Verdict.Should().BeEqualTo("improved");
        await (result.ReliabilityDelta > 0.6).Should().BeTrue();
        await result.Reasons.Contains("reliability-improved").Should().BeTrue();
        await result.Reasons.Contains("latency-improved").Should().BeTrue();
        await result.Reasons.Contains("loss-improved").Should().BeTrue();
    }

    [Test]
    public async Task Compare_ShouldPreferRegressionWhenMaterialRegressionExists()
    {
        var baseline = new RepairValidationEvidence
        {
            Attempts = 4,
            Successes = 4,
            ConsecutiveSuccesses = 4,
            MedianLatencyMs = 40,
            LossRate = 0,
        };
        var candidate = new RepairValidationEvidence
        {
            Attempts = 4,
            Successes = 3,
            ConsecutiveSuccesses = 1,
            MedianLatencyMs = 70,
            LossRate = 0.25,
        };

        var result = RepairOutcomeComparer.Compare(baseline, candidate);

        await result.Verdict.Should().BeEqualTo("regressed");
        await result.Reasons.Contains("reliability-regressed").Should().BeTrue();
        await result.Reasons.Contains("latency-regressed").Should().BeTrue();
        await result.Reasons.Contains("loss-regressed").Should().BeTrue();
    }

    [Test]
    public async Task Compare_ShouldRemainStableForSmallNoise()
    {
        var baseline = new RepairValidationEvidence
        {
            Attempts = 5,
            Successes = 5,
            ConsecutiveSuccesses = 5,
            MedianLatencyMs = 50,
            LossRate = 0,
        };
        var candidate = new RepairValidationEvidence
        {
            Attempts = 5,
            Successes = 5,
            ConsecutiveSuccesses = 5,
            MedianLatencyMs = 55,
            LossRate = 0.02,
        };

        var result = RepairOutcomeComparer.Compare(baseline, candidate);

        await result.Verdict.Should().BeEqualTo("stable");
        await result.Reasons.Count.Should().BeEqualTo(0);
    }
}
