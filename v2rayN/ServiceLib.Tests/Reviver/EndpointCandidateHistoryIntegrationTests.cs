using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Protocol;
using ServiceLib.Discovery.Services;

namespace ServiceLib.Tests.Reviver;

public class EndpointCandidateHistoryIntegrationTests
{
    [Test]
    public async Task Provider_ShouldMergeDuplicateProvenanceAndRecordLiveProbe()
    {
        var pool = new StubSource(
        [
            new DiscoveryEndpointCandidate
            {
                Address = "203.0.113.10",
                Source = "endpoint.pool",
                Metadata = new Dictionary<string, string> { ["pinned"] = "true" },
            }
        ]);
        var historySource = new StubSource(
        [
            new DiscoveryEndpointCandidate
            {
                Address = "203.0.113.10",
                Source = "history.endpoint",
                Reliability = 0.9,
            }
        ]);
        var history = new CapturingHistoryStore();
        var probe = new StubProbeClient(new DiscoveryEndpointProbeResponse
        {
            Results =
            [
                new DiscoveryEndpointProbeResult
                {
                    Address = "203.0.113.10",
                    Port = 443,
                    Attempts = 3,
                    Successes = 3,
                    ConsecutiveSuccesses = 3,
                    Reliability = 1,
                    MedianLatencyMs = 35,
                    Qualified = true,
                }
            ],
        });
        var provider = new DiscoveryCandidateProvider(probe, [pool, historySource], history);

        var result = await CollectAsync(provider, Request(maxCandidates: 4));

        await result.Count.Should().BeEqualTo(1);
        await result[0].Source!.Contains("endpoint.pool").Should().BeTrue();
        await result[0].Source!.Contains("history.endpoint").Should().BeTrue();
        await result[0].Metadata["pinned"].Should().BeEqualTo("true");
        await result[0].Metadata["sources"].Contains("endpoint.pool").Should().BeTrue();
        await history.Recorded.Count.Should().BeEqualTo(1);
        await history.Recorded[0].Observation.Qualified.Should().BeTrue();
    }

    [Test]
    public async Task Provider_ShouldPreserveLaterPinnedSourceFromLargeEarlierSource()
    {
        var bulk = new StubSource(
            Enumerable.Range(1, 20)
                .Select(i => new DiscoveryEndpointCandidate
                {
                    Address = $"203.0.113.{i}",
                    Source = "bulk",
                })
                .ToArray());
        var pinned = new StubSource(
        [
            new DiscoveryEndpointCandidate
            {
                Address = "198.51.100.77",
                Source = "endpoint.pool",
                Metadata = new Dictionary<string, string> { ["pinned"] = "true" },
            }
        ]);
        var provider = new DiscoveryCandidateProvider(
            new StubProbeClient(new DiscoveryEndpointProbeResponse()),
            [bulk, pinned]);

        var result = await CollectAsync(provider, Request(maxCandidates: 1));

        await result.Count.Should().BeEqualTo(1);
        await result[0].Address.Should().BeEqualTo("198.51.100.77");
    }

    [Test]
    public async Task HistorySource_ShouldHonorIncludeHistoricalFlag()
    {
        var store = new CapturingHistoryStore
        {
            Candidates =
            [
                new DiscoveryEndpointCandidate
                {
                    Address = "203.0.113.50",
                    Source = "history.endpoint",
                }
            ],
        };
        var source = new EndpointHistoryCandidateSource(store);

        var disabled = Request(maxCandidates: 4) with { IncludeHistorical = false };
        var values = new List<DiscoveryEndpointCandidate>();
        await foreach (var candidate in source.GetCandidatesAsync(disabled))
        {
            values.Add(candidate);
        }

        await values.Count.Should().BeEqualTo(0);
        await store.GetCalls.Should().BeEqualTo(0);
    }

    private static DiscoveryCandidateRequest Request(int maxCandidates)
        => new()
        {
            OriginalAddress = "origin.example",
            OriginalPort = 443,
            LogicalHost = "origin.example",
            Network = nameof(ETransport.ws),
            StreamSecurity = Global.StreamSecurity,
            MaxCandidates = maxCandidates,
        };

    private static async Task<List<DiscoveryEndpointCandidate>> CollectAsync(
        IDiscoveryCandidateProvider provider,
        DiscoveryCandidateRequest request)
    {
        var result = new List<DiscoveryEndpointCandidate>();
        await foreach (var candidate in provider.GetCandidatesAsync(request))
        {
            result.Add(candidate);
        }
        return result;
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
        public Task<DiscoveryEndpointProbeResponse> ProbeEndpointsAsync(
            DiscoveryEndpointProbeRequest request,
            CancellationToken cancellationToken = default)
            => Task.FromResult(response);
    }

    private sealed class CapturingHistoryStore : IEndpointHistoryStore
    {
        public List<(DiscoveryEndpointCandidate Candidate, DiscoveryEndpointProbeResult Observation)> Recorded { get; } = [];
        public IReadOnlyList<DiscoveryEndpointCandidate> Candidates { get; init; } = [];
        public int GetCalls { get; private set; }

        public Task RecordProbeAsync(
            DiscoveryCandidateRequest request,
            DiscoveryEndpointCandidate sourceCandidate,
            DiscoveryEndpointProbeResult observation,
            CancellationToken cancellationToken = default)
        {
            Recorded.Add((sourceCandidate, observation));
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<DiscoveryEndpointCandidate>> GetHistoricallyGoodAsync(
            DiscoveryCandidateRequest request,
            EndpointHistoryPolicy? policy = null,
            CancellationToken cancellationToken = default)
        {
            GetCalls++;
            return Task.FromResult(Candidates);
        }

        public Task PruneAsync(TimeSpan maxAge, CancellationToken cancellationToken = default)
            => Task.CompletedTask;
    }
}
