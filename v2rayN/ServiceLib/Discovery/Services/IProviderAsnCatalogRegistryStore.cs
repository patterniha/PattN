using ServiceLib.Discovery.Models;
using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

public interface IProviderAsnCatalogRegistryStore
{
    Task<IReadOnlyList<ProviderAsnCatalogRegistryItem>> ListAsync(
        ProviderAsnCatalogRegistryQuery? query = null,
        CancellationToken cancellationToken = default);

    Task<ProviderAsnCatalogRegistryItem?> GetAsync(
        string id,
        CancellationToken cancellationToken = default);

    Task<ProviderAsnCatalogRegistryItem?> FindByPathAsync(
        string normalizedPath,
        CancellationToken cancellationToken = default);

    Task UpsertAsync(
        ProviderAsnCatalogRegistryItem item,
        CancellationToken cancellationToken = default);

    Task RemoveAsync(
        string id,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically persists a retired registry row and optionally deletes all of its revision records.
    /// Returns the number of revisions preserved or discarded, depending on the requested policy.
    /// </summary>
    Task<int> RetireAsync(
        ProviderAsnCatalogRegistryItem item,
        bool discardRevisionHistory,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ProviderAsnCatalogRevisionItem>> ListRevisionsAsync(
        ProviderAsnCatalogRevisionQuery? query = null,
        CancellationToken cancellationToken = default);

    Task<ProviderAsnCatalogRevisionItem?> GetRevisionAsync(
        string id,
        CancellationToken cancellationToken = default);

    Task InsertRevisionAsync(
        ProviderAsnCatalogRevisionItem item,
        CancellationToken cancellationToken = default);

    Task UpdateRevisionAsync(
        ProviderAsnCatalogRevisionItem item,
        CancellationToken cancellationToken = default);
}
