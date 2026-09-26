using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;
using ServiceLib.Models.Entities;

namespace ServiceLib.Tests.Reviver;

public class EndpointPoolCandidateSourceTests
{
    [Test]
    public async Task PoolSource_ShouldExposePinnedMetadataAndHonorFeatureFlag()
    {
        var store = new StubPoolStore(
        [
            new DiscoveryEndpointCandidate
            {
                Address = "203.0.113.9",
                Source = "endpoint.pool",
                Metadata = new Dictionary<string, string> { ["pinned"] = "true" },
            }
        ]);
        var source = new EndpointPoolCandidateSource(store);
        var request = new DiscoveryCandidateRequest
        {
            OriginalAddress = "origin.example",
            OriginalPort = 443,
            LogicalHost = "origin.example",
            MaxCandidates = 4,
        };

        var enabled = new List<DiscoveryEndpointCandidate>();
        await foreach (var candidate in source.GetCandidatesAsync(request))
        {
            enabled.Add(candidate);
        }

        await enabled.Count.Should().BeEqualTo(1);
        await enabled[0].Metadata["pinned"].Should().BeEqualTo("true");

        var disabled = new List<DiscoveryEndpointCandidate>();
        await foreach (var candidate in source.GetCandidatesAsync(request with { IncludeEndpointPools = false }))
        {
            disabled.Add(candidate);
        }
        await disabled.Count.Should().BeEqualTo(0);
    }

    private sealed class StubPoolStore(IReadOnlyList<DiscoveryEndpointCandidate> candidates) : IEndpointPoolStore
    {
        public Task<IReadOnlyList<DiscoveryEndpointCandidate>> GetCandidatesAsync(
            DiscoveryCandidateRequest request,
            int maxCandidates,
            CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<DiscoveryEndpointCandidate>>(candidates.Take(maxCandidates).ToArray());

        public Task<EndpointPoolItem> UpsertAsync(
            DiscoveryCandidateRequest request,
            DiscoveryEndpointCandidate candidate,
            bool pinned = false,
            string? label = null,
            CancellationToken cancellationToken = default)
            => Task.FromResult(new EndpointPoolItem());

        public Task RemoveAsync(string id, CancellationToken cancellationToken = default)
            => Task.CompletedTask;
    }
}
