using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

public interface IProviderAsnCatalogRemoteSourceStore
{
    Task<ProviderAsnCatalogRemoteSourceItem?> GetAsync(
        string registryId,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ProviderAsnCatalogRemoteSourceItem>> ListAsync(
        int maxItems = 500,
        CancellationToken cancellationToken = default);

    Task UpsertAsync(
        ProviderAsnCatalogRemoteSourceItem item,
        CancellationToken cancellationToken = default);

    Task RemoveAsync(
        string registryId,
        CancellationToken cancellationToken = default);
}
