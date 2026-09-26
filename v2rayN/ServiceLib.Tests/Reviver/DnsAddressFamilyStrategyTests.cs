using ServiceLib.Reviver.Models;
using ServiceLib.Reviver.Normalization;
using ServiceLib.Reviver.Services;
using ServiceLib.Reviver.Strategies;

namespace ServiceLib.Tests.Reviver;

public class DnsAddressFamilyStrategyTests
{
    [Test]
    public async Task Generate_ShouldPreferOnlyObservedFamilyAndChangeOnlyTargetStrategy()
    {
        var profile = BaseProfile();
        profile.CoreType = ECoreType.Xray;
        var provider = new FakeProvider(new DnsRepairObservation
        {
            Host = "proxy.example",
            IPv4 = new DnsFamilyObservation
            {
                Family = "ipv4",
                Addresses = ["203.0.113.7"],
                TraceComplete = true,
                DnssecAuthenticated = true,
                DnssecStatus = "root-anchored-authenticated-answer",
            },
            IPv6 = new DnsFamilyObservation { Family = "ipv6", TraceComplete = true },
        });
        var strategy = new DnsAddressFamilyStrategy(provider, new ProfileCoreCompatibility());
        var session = new RepairSession { Original = ProfileSnapshot.Capture(profile) };

        var results = new List<RepairCandidate>();
        await foreach (var candidate in strategy.GenerateAsync(session, ERepairFailureClass.DnsResolutionFailure))
        {
            results.Add(candidate);
        }

        await results.Count.Should().BeEqualTo(1);
        await results[0].Profile.TargetStrategy.Should().BeEqualTo("UseIPv4");
        await ProfileMutationGuard.ChangesOnly(profile, results[0].Profile, nameof(ProfileItem.TargetStrategy)).Should().BeTrue();
        await results[0].Evidence.Any(x => x.Kind == "discovery.dns.address-family").Should().BeTrue();
    }

    [Test]
    public async Task Generate_ShouldSwitchSingBoxProfileToXrayWhenTargetStrategyNeedsXray()
    {
        var profile = BaseProfile();
        profile.CoreType = ECoreType.sing_box;
        var provider = new FakeProvider(new DnsRepairObservation
        {
            Host = "proxy.example",
            IPv4 = new DnsFamilyObservation { Family = "ipv4", Addresses = ["203.0.113.7"], TraceComplete = true },
            IPv6 = new DnsFamilyObservation { Family = "ipv6", Addresses = ["2001:db8::7"], TraceComplete = true },
        });
        var strategy = new DnsAddressFamilyStrategy(provider, new ProfileCoreCompatibility());
        var session = new RepairSession { Original = ProfileSnapshot.Capture(profile) };

        var results = new List<RepairCandidate>();
        await foreach (var candidate in strategy.GenerateAsync(session, ERepairFailureClass.NoUsableAddressFamily))
        {
            results.Add(candidate);
        }

        await results.Count.Should().BeEqualTo(4);
        await results.All(x => x.Profile.CoreType == ECoreType.Xray).Should().BeTrue();
        await results.All(x => ProfileMutationGuard.ChangesOnly(
            profile,
            x.Profile,
            nameof(ProfileItem.CoreType),
            nameof(ProfileItem.TargetStrategy))).Should().BeTrue();
    }

    [Test]
    public async Task BuildStrategies_ShouldPreferAuthenticatedIpv6WhenBothFamiliesExist()
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

        var strategies = DnsAddressFamilyStrategy.BuildStrategies(
            observation,
            ERepairFailureClass.DnsResolutionFailure);

        await strategies[0].Should().BeEqualTo("UseIPv6v4");
        await strategies[1].Should().BeEqualTo("UseIPv4v6");
    }

    [Test]
    public async Task BuildStrategies_ShouldOfferForceVariantOnlyForNoUsableFamilyFailure()
    {
        var observation = new DnsRepairObservation
        {
            Host = "proxy.example",
            IPv4 = new DnsFamilyObservation { Family = "ipv4", Addresses = ["203.0.113.7"] },
            IPv6 = new DnsFamilyObservation { Family = "ipv6" },
        };

        var resolution = DnsAddressFamilyStrategy.BuildStrategies(
            observation,
            ERepairFailureClass.DnsResolutionFailure);
        var unavailable = DnsAddressFamilyStrategy.BuildStrategies(
            observation,
            ERepairFailureClass.NoUsableAddressFamily);

        await resolution.SequenceEqual(["UseIPv4"]).Should().BeTrue();
        await unavailable.SequenceEqual(["UseIPv4", "ForceIPv4"]).Should().BeTrue();
    }

    [Test]
    public async Task Generate_ShouldNotGuessWhenNeitherAddressFamilyIsObserved()
    {
        var profile = BaseProfile();
        var strategy = new DnsAddressFamilyStrategy(
            new FakeProvider(new DnsRepairObservation
            {
                Host = "proxy.example",
                IPv4 = new DnsFamilyObservation { Family = "ipv4", Error = "no answer" },
                IPv6 = new DnsFamilyObservation { Family = "ipv6", Error = "no answer" },
            }),
            new ProfileCoreCompatibility());
        var session = new RepairSession { Original = ProfileSnapshot.Capture(profile) };

        var count = 0;
        await foreach (var _ in strategy.GenerateAsync(session, ERepairFailureClass.DnsResolutionFailure))
        {
            count++;
        }
        await count.Should().BeEqualTo(0);
    }

    [Test]
    public async Task Generate_ShouldFailClosedWhenDnsDiagnosticsAreUnavailable()
    {
        var profile = BaseProfile();
        var strategy = new DnsAddressFamilyStrategy(
            new ThrowingProvider(),
            new ProfileCoreCompatibility());
        var session = new RepairSession { Original = ProfileSnapshot.Capture(profile) };

        var count = 0;
        await foreach (var _ in strategy.GenerateAsync(session, ERepairFailureClass.DnsResolutionFailure))
        {
            count++;
        }

        await count.Should().BeEqualTo(0);
    }

    [Test]
    public async Task CanApply_ShouldRejectLiteralIpAndNonDnsFailures()
    {
        var profile = WithAddress(BaseProfile(), "203.0.113.7");
        var strategy = new DnsAddressFamilyStrategy(
            new FakeProvider(new DnsRepairObservation
            {
                Host = "203.0.113.7",
                IPv4 = new DnsFamilyObservation { Family = "ipv4", Addresses = ["203.0.113.7"] },
            }),
            new ProfileCoreCompatibility());

        await strategy.CanApply(profile, ERepairFailureClass.DnsResolutionFailure).Should().BeFalse();
        await strategy.CanApply(BaseProfile(), ERepairFailureClass.TlsHandshakeFailure).Should().BeFalse();
    }

    private static ProfileItem BaseProfile()
        => new()
        {
            ConfigType = EConfigType.VLESS,
            Address = "proxy.example",
            Port = 443,
            Password = Guid.NewGuid().ToString(),
            Network = nameof(ETransport.ws),
            StreamSecurity = Global.StreamSecurity,
        };

    private static ProfileItem WithAddress(ProfileItem profile, string address)
    {
        profile.Address = address;
        return profile;
    }

    private sealed class ThrowingProvider : IDnsRepairEvidenceProvider
    {
        public Task<DnsRepairObservation> InspectAsync(string host, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("diagnostic unavailable");
    }

    private sealed class FakeProvider(DnsRepairObservation observation) : IDnsRepairEvidenceProvider
    {
        public Task<DnsRepairObservation> InspectAsync(string host, CancellationToken cancellationToken = default)
            => Task.FromResult(observation);
    }
}
