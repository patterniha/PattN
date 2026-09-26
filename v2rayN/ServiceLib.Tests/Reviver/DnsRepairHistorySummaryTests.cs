using ServiceLib.Reviver.Models;
using ServiceLib.Reviver.Strategies;

namespace ServiceLib.Tests.Reviver;

public class DnsRepairHistorySummaryTests
{
    [Test]
    public async Task PreferredFamily_ShouldStayNeutralWithSparseHistory()
    {
        var summary = new DnsRepairHistorySummary
        {
            Host = "proxy.example",
            IPv4 = new DnsRepairFamilyHistory { Family = "ipv4", Samples = 2, RuntimeQuorumPasses = 2 },
            IPv6 = new DnsRepairFamilyHistory { Family = "ipv6", Samples = 2, RuntimeQuorumPasses = 0 },
        };

        await (summary.PreferredFamily() is null).Should().BeTrue();
    }

    [Test]
    public async Task PreferredFamily_ShouldRequireMaterialPassRateDelta()
    {
        var close = new DnsRepairHistorySummary
        {
            Host = "proxy.example",
            IPv4 = new DnsRepairFamilyHistory { Family = "ipv4", Samples = 5, RuntimeQuorumPasses = 4 },
            IPv6 = new DnsRepairFamilyHistory { Family = "ipv6", Samples = 5, RuntimeQuorumPasses = 3 },
        };
        var clear = new DnsRepairHistorySummary
        {
            Host = "proxy.example",
            IPv4 = new DnsRepairFamilyHistory { Family = "ipv4", Samples = 5, RuntimeQuorumPasses = 5 },
            IPv6 = new DnsRepairFamilyHistory { Family = "ipv6", Samples = 5, RuntimeQuorumPasses = 1 },
        };

        await (close.PreferredFamily() is null).Should().BeTrue();
        await clear.PreferredFamily().Should().BeEqualTo("ipv4");
    }

    [Test]
    public async Task BuildStrategies_ShouldUseMatureRuntimeHistoryBeforeFamilyOrderingHint()
    {
        var observation = new DnsRepairObservation
        {
            Host = "proxy.example",
            IPv4 = new DnsFamilyObservation
            {
                Family = "ipv4",
                Addresses = ["203.0.113.7"],
                DnssecAuthenticated = false,
            },
            IPv6 = new DnsFamilyObservation
            {
                Family = "ipv6",
                Addresses = ["2001:db8::7"],
                DnssecAuthenticated = true,
            },
        };
        var history = new DnsRepairHistorySummary
        {
            Host = "proxy.example",
            IPv4 = new DnsRepairFamilyHistory { Family = "ipv4", Samples = 6, RuntimeQuorumPasses = 6 },
            IPv6 = new DnsRepairFamilyHistory { Family = "ipv6", Samples = 6, RuntimeQuorumPasses = 1 },
        };

        var strategies = DnsAddressFamilyStrategy.BuildStrategies(
            observation,
            ERepairFailureClass.DnsResolutionFailure,
            history);

        await strategies[0].Should().BeEqualTo("UseIPv4v6");
        await strategies[1].Should().BeEqualTo("UseIPv6v4");
    }
}
