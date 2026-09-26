using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;
using ServiceLib.Models.Entities;
using ServiceLib.Reviver.Promotion;

namespace ServiceLib.Tests.Reviver;

public class EndpointPoolManagementServiceTests
{
    [Test]
    public async Task Management_ShouldExpressExplicitPoolStateChanges()
    {
        var store = new FakeStore();
        var service = new EndpointPoolManagementService(store, store);

        await service.SetPinnedAsync("item", true);
        await store.LastUpdate!.Pinned.Should().BeTrue();

        await service.SetEnabledAsync("item", false);
        await store.LastUpdate!.Enabled.Should().BeFalse();

        await service.RelabelAsync("item", "primary");
        await store.LastUpdate!.Label.Should().BeEqualTo("primary");

        await service.RemoveAsync("item");
        await store.RemovedId.Should().BeEqualTo("item");
    }

    private sealed class FakeStore : IEndpointPoolStore, IEndpointPoolAdminStore
    {
        public EndpointPoolUpdate? LastUpdate { get; private set; }
        public string? RemovedId { get; private set; }

        public Task<IReadOnlyList<DiscoveryEndpointCandidate>> GetCandidatesAsync(
            DiscoveryCandidateRequest request,
            int maxCandidates,
            CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<DiscoveryEndpointCandidate>>([]);

        public Task<EndpointPoolItem> UpsertAsync(
            DiscoveryCandidateRequest request,
            DiscoveryEndpointCandidate candidate,
            bool pinned = false,
            string? label = null,
            CancellationToken cancellationToken = default)
            => Task.FromResult(new EndpointPoolItem());

        public Task RemoveAsync(string id, CancellationToken cancellationToken = default)
        {
            RemovedId = id;
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<EndpointPoolItem>> ListAsync(
            EndpointPoolQuery? query = null,
            CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<EndpointPoolItem>>([]);

        public Task<EndpointPoolItem?> UpdateAsync(
            EndpointPoolUpdate update,
            CancellationToken cancellationToken = default)
        {
            LastUpdate = update;
            return Task.FromResult<EndpointPoolItem?>(new EndpointPoolItem { Id = update.Id });
        }
    }
}
