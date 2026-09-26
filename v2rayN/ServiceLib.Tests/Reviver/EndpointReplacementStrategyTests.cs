using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;
using ServiceLib.Reviver.Models;
using ServiceLib.Reviver.Strategies;

namespace ServiceLib.Tests.Reviver;

public class EndpointReplacementStrategyTests
{
    [Test]
    public async Task Generate_ShouldChangeOnlyPhysicalAddress_AndPreserveLogicalIdentity()
    {
        var profile = new ProfileItem
        {
            IndexId = "source",
            ConfigType = EConfigType.VLESS,
            CoreType = ECoreType.Xray,
            Address = "origin.example.com",
            Port = 443,
            Password = Guid.NewGuid().ToString(),
            Network = "ws",
            StreamSecurity = Global.StreamSecurityReality,
            Sni = "logical.example.com",
            Fingerprint = "chrome",
            PublicKey = "test-public-key",
            ShortId = "abcd",
            SpiderX = "/",
            Alpn = "h2,http/1.1",
            Remarks = "source",
        };
        profile.SetProtocolExtra(new ProtocolExtraItem { Flow = string.Empty, VlessEncryption = Global.None });
        profile.SetTransportExtra(new TransportExtraItem { Host = "host.example.com", Path = "/socket" });

        var session = new RepairSession { Original = ProfileSnapshot.Capture(profile) };
        var discovery = new StubDiscoveryProvider(
        [
            new DiscoveryEndpointCandidate
            {
                Address = "203.0.113.7",
                Port = 8443,
                Source = "endpoint.pool+history.endpoint",
                Provider = "cloudflare",
                Pop = "FRA",
                Reliability = 1,
                Metadata = new Dictionary<string, string>
                {
                    ["pinned"] = "true",
                    ["historical"] = "true",
                    ["historySamples"] = "5",
                    ["historyFailureStreak"] = "0",
                    ["probeQualified"] = "true",
                    ["sources"] = "endpoint.pool,history.endpoint",
                },
            }
        ]);
        var strategy = new EndpointReplacementStrategy(discovery);

        var candidates = new List<RepairCandidate>();
        await foreach (var candidate in strategy.GenerateAsync(session, ERepairFailureClass.ConnectionTimeout))
        {
            candidates.Add(candidate);
        }

        await candidates.Count.Should().BeEqualTo(1);
        var revived = candidates[0].Profile;

        await revived.Address.Should().BeEqualTo("203.0.113.7");
        await revived.Port.Should().BeEqualTo(443); // alternate ports are a separate evidence-backed mutation
        await revived.Sni.Should().BeEqualTo(profile.Sni);
        await revived.Password.Should().BeEqualTo(profile.Password);
        await revived.Network.Should().BeEqualTo(profile.Network);
        await revived.StreamSecurity.Should().BeEqualTo(profile.StreamSecurity);
        await revived.Fingerprint.Should().BeEqualTo(profile.Fingerprint);
        await revived.PublicKey.Should().BeEqualTo(profile.PublicKey);
        await revived.ShortId.Should().BeEqualTo(profile.ShortId);
        await revived.SpiderX.Should().BeEqualTo(profile.SpiderX);
        await revived.Alpn.Should().BeEqualTo(profile.Alpn);
        await revived.GetTransportExtra().Host.Should().BeEqualTo("host.example.com");
        await revived.GetTransportExtra().Path.Should().BeEqualTo("/socket");
        await revived.GetProtocolExtra().VlessEncryption.Should().BeEqualTo(Global.None);

        var evidence = candidates[0].Evidence.Single(x => x.Kind == "discovery.endpoint");
        await evidence.Source.Should().BeEqualTo("endpoint.pool+history.endpoint");
        await evidence.Data["pinned"].Should().BeEqualTo("true");
        await evidence.Data["historical"].Should().BeEqualTo("true");
        await evidence.Data["historySamples"].Should().BeEqualTo("5");
        await evidence.Data["probeQualified"].Should().BeEqualTo("true");
        await evidence.Data["provider"].Should().BeEqualTo("cloudflare");
        await evidence.Data["pop"].Should().BeEqualTo("FRA");

        // The original snapshot/source is not modified.
        await profile.Address.Should().BeEqualTo("origin.example.com");

        await discovery.LastRequest.Should().NotBeNull();
        await discovery.LastRequest!.LogicalHost.Should().BeEqualTo("logical.example.com");
        await discovery.LastRequest.HttpHost.Should().BeEqualTo("host.example.com");
    }

    [Test]
    public async Task Generate_ShouldPinImplicitTlsAndHttpIdentity_WhenDialAddressBecomesIp()
    {
        var profile = new ProfileItem
        {
            IndexId = "implicit-identity",
            ConfigType = EConfigType.VLESS,
            CoreType = ECoreType.Xray,
            Address = "front.example.com",
            Port = 443,
            Password = Guid.NewGuid().ToString(),
            Network = nameof(ETransport.ws),
            StreamSecurity = "tls",
            Sni = string.Empty,
        };
        profile.SetProtocolExtra(new ProtocolExtraItem { Flow = string.Empty, VlessEncryption = Global.None });
        profile.SetTransportExtra(new TransportExtraItem { Path = "/socket" });

        var session = new RepairSession { Original = ProfileSnapshot.Capture(profile) };
        var strategy = new EndpointReplacementStrategy(new StubDiscoveryProvider(
        [
            new DiscoveryEndpointCandidate
            {
                Address = "203.0.113.9",
                Port = 443,
                Source = "fixture",
            }
        ]));

        var candidates = new List<RepairCandidate>();
        await foreach (var candidate in strategy.GenerateAsync(session, ERepairFailureClass.ConnectionTimeout))
        {
            candidates.Add(candidate);
        }

        await candidates.Count.Should().BeEqualTo(1);
        var revived = candidates[0].Profile;
        await revived.Address.Should().BeEqualTo("203.0.113.9");
        await revived.Sni.Should().BeEqualTo("front.example.com");
        await revived.GetTransportExtra().Host.Should().BeEqualTo("front.example.com");
        await revived.GetTransportExtra().Path.Should().BeEqualTo("/socket");
        await candidates[0].Mutations.Any(x => x.Field == nameof(ProfileItem.Sni)).Should().BeTrue();
        await candidates[0].Mutations.Any(x => x.Field == nameof(ProfileItem.TransportExtra)).Should().BeTrue();

        await profile.Sni.Should().BeEqualTo(string.Empty);
        await profile.GetTransportExtra().Host.Should().BeNull();
    }

    [Test]
    public async Task Generate_ShouldSkipEquivalentIpv6SpellingOfCurrentEndpoint()
    {
        var profile = new ProfileItem
        {
            IndexId = "source-v6",
            ConfigType = EConfigType.VLESS,
            Address = "2001:0db8:0:0:0:0:0:1",
            Port = 443,
        };
        var session = new RepairSession { Original = ProfileSnapshot.Capture(profile) };
        var strategy = new EndpointReplacementStrategy(new StubDiscoveryProvider(
        [
            new DiscoveryEndpointCandidate
            {
                Address = "2001:db8::1",
                Port = 443,
                Source = "fixture",
            }
        ]));

        var candidates = new List<RepairCandidate>();
        await foreach (var candidate in strategy.GenerateAsync(session, ERepairFailureClass.ConnectionTimeout))
        {
            candidates.Add(candidate);
        }

        await candidates.Count.Should().BeEqualTo(0);
    }

    private sealed class StubDiscoveryProvider(IReadOnlyList<DiscoveryEndpointCandidate> candidates) : IDiscoveryCandidateProvider
    {
        public DiscoveryCandidateRequest? LastRequest { get; private set; }

        public async IAsyncEnumerable<DiscoveryEndpointCandidate> GetCandidatesAsync(
            DiscoveryCandidateRequest request,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            LastRequest = request;
            foreach (var candidate in candidates)
            {
                cancellationToken.ThrowIfCancellationRequested();
                yield return candidate;
                await Task.Yield();
            }
        }
    }
}
