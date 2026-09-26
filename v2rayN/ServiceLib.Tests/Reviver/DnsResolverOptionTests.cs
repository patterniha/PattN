using ServiceLib.Discovery.Models;

namespace ServiceLib.Tests.Reviver;

public class DnsResolverOptionTests
{
    [Test]
    public async Task IsSafeToApply_ShouldRequireLiveQuorumAndNoInterception()
    {
        var healthy = Option("healthy", quorum: 3, interception: false);
        var watch = Option("watch", quorum: 1, interception: false);
        var degraded = Option("degraded", quorum: 3, interception: false);
        var suspicious = Option("healthy", quorum: 3, interception: true);
        var unavailable = Option("healthy", quorum: 0, interception: false);

        await healthy.IsSafeToApply.Should().BeTrue();
        await watch.IsSafeToApply.Should().BeTrue();
        await degraded.IsSafeToApply.Should().BeFalse();
        await suspicious.IsSafeToApply.Should().BeFalse();
        await unavailable.IsSafeToApply.Should().BeFalse();
    }

    private static DnsResolverOption Option(string health, int quorum, bool interception)
        => new()
        {
            CatalogId = "resolver",
            Provider = "provider",
            Name = "resolver",
            Policy = "neutral",
            HealthClass = health,
            Quality = "usable",
            QuorumTransportCount = quorum,
            InterceptionSuspected = interception,
        };
}
