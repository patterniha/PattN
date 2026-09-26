using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;
using ServiceLib.Models.Entities;

namespace ServiceLib.Reviver.Promotion;

public sealed class EndpointPoolManagementService(
    IEndpointPoolStore poolStore,
    IEndpointPoolAdminStore adminStore)
{
    public Task<IReadOnlyList<EndpointPoolItem>> ListAsync(
        EndpointPoolQuery? query = null,
        CancellationToken cancellationToken = default)
        => adminStore.ListAsync(query, cancellationToken);

    public Task<EndpointPoolItem?> SetPinnedAsync(
        string id,
        bool pinned,
        CancellationToken cancellationToken = default)
        => adminStore.UpdateAsync(
            new EndpointPoolUpdate { Id = id, Pinned = pinned },
            cancellationToken);

    public Task<EndpointPoolItem?> SetEnabledAsync(
        string id,
        bool enabled,
        CancellationToken cancellationToken = default)
        => adminStore.UpdateAsync(
            new EndpointPoolUpdate { Id = id, Enabled = enabled },
            cancellationToken);

    public Task<EndpointPoolItem?> RelabelAsync(
        string id,
        string label,
        CancellationToken cancellationToken = default)
        => adminStore.UpdateAsync(
            new EndpointPoolUpdate { Id = id, Label = label ?? string.Empty },
            cancellationToken);

    public Task RemoveAsync(string id, CancellationToken cancellationToken = default)
        => poolStore.RemoveAsync(id, cancellationToken);
}
