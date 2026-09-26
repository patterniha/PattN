using ServiceLib.Reviver.Models;

namespace ServiceLib.Tests.Reviver;

public class RepairPolicyTests
{
    [Test]
    public async Task DefaultPolicy_ShouldAllowEvidenceBackedButNotSpeculative()
    {
        var policy = new RepairPolicy();
        await policy.Allows(ERepairConfidence.Equivalent).Should().BeTrue();
        await policy.Allows(ERepairConfidence.LowRisk).Should().BeTrue();
        await policy.Allows(ERepairConfidence.EvidenceBacked).Should().BeTrue();
        await policy.Allows(ERepairConfidence.Speculative).Should().BeFalse();
    }
}
