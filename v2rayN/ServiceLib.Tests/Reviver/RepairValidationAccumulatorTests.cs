using ServiceLib.Reviver.Models;
using ServiceLib.Reviver.Validation;

namespace ServiceLib.Tests.Reviver;

public class RepairValidationAccumulatorTests
{
    [Test]
    public async Task Build_ShouldComputeQuorumEvidenceAndMedian()
    {
        var accumulator = new RepairValidationAccumulator();
        accumulator.AddSuccess(70);
        accumulator.AddFailure(ERepairFailureClass.ApplicationProbeFailure);
        accumulator.AddSuccess(50);

        var result = accumulator.Build();
        await result.Attempts.Should().BeEqualTo(3);
        await result.Successes.Should().BeEqualTo(2);
        await result.ConsecutiveSuccesses.Should().BeEqualTo(1);
        await result.MedianLatencyMs.Should().BeEqualTo(60);
        await result.LossRate.Should().BeEqualTo(1d / 3d);
        await result.MeetsQuorum(2).Should().BeTrue();
    }
}
