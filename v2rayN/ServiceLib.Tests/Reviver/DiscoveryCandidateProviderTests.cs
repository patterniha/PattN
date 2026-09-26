using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Protocol;
using ServiceLib.Discovery.Services;

namespace ServiceLib.Tests.Reviver;

public class DiscoveryCandidateProviderTests
{
    [Test]
    public async Task Provider_ShouldEnrichAndPreferQualifiedPinnedCandidate()
    {
        var source = new StubSource(
        [
            new DiscoveryEndpointCandidate { Address = "203.0.113.20", Source = "fixture" },
            new DiscoveryEndpointCandidate { Address = "203.0.113.10", Source = "fixture" },
        ]);
        var probe = new StubProbeClient(new DiscoveryEndpointProbeResponse
        {
            Results =
            [
                new DiscoveryEndpointProbeResult
                {
                    Address = "203.0.113.10",
                    Port = 443,
                    Attempts = 2,
                    Successes = 2,
                    Reliability = 1,
                    MedianLatencyMs = 42,
                    Qualified = true,
                    Edge = new DiscoveryEdgeObservation { Provider = "cloudflare", Pop = "FRA", Evidence = "cf-ray=test-FRA" },
                },
                new DiscoveryEndpointProbeResult
                {
                    Address = "203.0.113.20",
                    Port = 443,
                    Attempts = 2,
                    Successes = 0,
                    Reliability = 0,
                    Qualified = false,
                },
            ],
        });
        var provider = new DiscoveryCandidateProvider(probe, [source]);
        var request = new DiscoveryCandidateRequest
        {
            OriginalAddress = "origin.example.com",
            OriginalPort = 443,
            LogicalHost = "tls.example.com",
            HttpHost = "origin.example.com",
            Network = nameof(ETransport.ws),
            StreamSecurity = Global.StreamSecurity,
        };

        var result = new List<DiscoveryEndpointCandidate>();
        await foreach (var candidate in provider.GetCandidatesAsync(request))
        {
            result.Add(candidate);
        }

        await result.Count.Should().BeEqualTo(2);
        await result[0].Address.Should().BeEqualTo("203.0.113.10");
        await result[0].Provider.Should().BeEqualTo("cloudflare");
        await result[0].Pop.Should().BeEqualTo("FRA");
        await result[0].Reliability.Should().BeEqualTo(1);
        await result[0].Metadata["probeQualified"].Should().BeEqualTo("true");
        await result[1].Address.Should().BeEqualTo("203.0.113.20");
        await probe.Calls.Should().BeEqualTo(1);
        await probe.LastRequest.Should().NotBeNull();
        await probe.LastRequest!.ServerName.Should().BeEqualTo("tls.example.com");
        await probe.LastRequest.HttpHost.Should().BeEqualTo("origin.example.com");
        await probe.LastRequest.InsecureSkipVerify.Should().BeFalse();
    }

    [Test]
    public async Task Provider_ShouldNotTreatGenericHttpsAsRealityQualification()
    {
        var source = new StubSource(
        [
            new DiscoveryEndpointCandidate { Address = "203.0.113.10", Source = "fixture" },
        ]);
        var probe = new StubProbeClient(new DiscoveryEndpointProbeResponse());
        var provider = new DiscoveryCandidateProvider(probe, [source]);
        var request = new DiscoveryCandidateRequest
        {
            OriginalAddress = "origin.example.com",
            OriginalPort = 443,
            LogicalHost = "reality.example.com",
            HttpHost = "host.example.com",
            Network = nameof(ETransport.ws),
            StreamSecurity = Global.StreamSecurityReality,
        };

        var result = new List<DiscoveryEndpointCandidate>();
        await foreach (var candidate in provider.GetCandidatesAsync(request))
        {
            result.Add(candidate);
        }

        await result.Count.Should().BeEqualTo(1);
        await probe.Calls.Should().BeEqualTo(0);
        await result[0].Metadata.ContainsKey("probeQualified").Should().BeFalse();
    }

    [Test]
    public async Task Provider_ShouldCanonicalizeEquivalentIpv6BeforeDeduplication()
    {
        var source = new StubSource(
        [
            new DiscoveryEndpointCandidate { Address = "2001:db8::1", Source = "first" },
            new DiscoveryEndpointCandidate { Address = "2001:0db8:0:0:0:0:0:1", Source = "second" },
        ]);
        var provider = new DiscoveryCandidateProvider(
            new StubProbeClient(new DiscoveryEndpointProbeResponse()),
            [source]);
        var request = new DiscoveryCandidateRequest
        {
            OriginalAddress = "origin.example.com",
            OriginalPort = 443,
            LogicalHost = null,
        };

        var result = new List<DiscoveryEndpointCandidate>();
        await foreach (var candidate in provider.GetCandidatesAsync(request))
        {
            result.Add(candidate);
        }

        await result.Count.Should().BeEqualTo(1);
        await result[0].Address.Should().BeEqualTo("2001:db8::1");
        await result[0].Metadata["sources"].Should().Contain("first");
        await result[0].Metadata["sources"].Should().Contain("second");
    }

    [Test]
    public async Task Provider_ShouldKeepDuplicateMetricsFromOneCoherentObservation()
    {
        var older = DateTimeOffset.Parse("2026-09-24T10:00:00Z");
        var newer = older.AddMinutes(5);
        var source = new StubSource(
        [
            new DiscoveryEndpointCandidate
            {
                Address = "203.0.113.40",
                Source = "reliable",
                Reliability = 0.95,
                LossRate = 0.05,
                LatencyMs = 120,
                ObservedAt = older,
            },
            new DiscoveryEndpointCandidate
            {
                Address = "203.0.113.40",
                Source = "fast",
                Reliability = 0.60,
                LossRate = 0.40,
                LatencyMs = 10,
                ObservedAt = newer,
            },
        ]);
        var provider = new DiscoveryCandidateProvider(
            new StubProbeClient(new DiscoveryEndpointProbeResponse()),
            [source]);
        var request = new DiscoveryCandidateRequest
        {
            OriginalAddress = "origin.example.com",
            OriginalPort = 443,
            LogicalHost = null,
        };

        var result = new List<DiscoveryEndpointCandidate>();
        await foreach (var candidate in provider.GetCandidatesAsync(request))
        {
            result.Add(candidate);
        }

        await result.Count.Should().BeEqualTo(1);
        await result[0].Reliability.Should().BeEqualTo(0.95);
        await result[0].LossRate.Should().BeEqualTo(0.05);
        await result[0].LatencyMs.Should().BeEqualTo(120);
        await result[0].ObservedAt.Should().BeEqualTo(older);
        await result[0].Metadata["sources"].Should().Contain("reliable");
        await result[0].Metadata["sources"].Should().Contain("fast");
    }

    private sealed class StubSource(IReadOnlyList<DiscoveryEndpointCandidate> candidates) : IDiscoveryCandidateSource
    {
        public async IAsyncEnumerable<DiscoveryEndpointCandidate> GetCandidatesAsync(
            DiscoveryCandidateRequest request,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            foreach (var candidate in candidates)
            {
                cancellationToken.ThrowIfCancellationRequested();
                yield return candidate;
                await Task.Yield();
            }
        }
    }

    private sealed class StubProbeClient(DiscoveryEndpointProbeResponse response) : IDiscoveryEndpointProbeClient
    {
        public DiscoveryEndpointProbeRequest? LastRequest { get; private set; }
        public int Calls { get; private set; }

        public Task<DiscoveryEndpointProbeResponse> ProbeEndpointsAsync(
            DiscoveryEndpointProbeRequest request,
            CancellationToken cancellationToken = default)
        {
            Calls++;
            LastRequest = request;
            return Task.FromResult(response);
        }
    }
}
