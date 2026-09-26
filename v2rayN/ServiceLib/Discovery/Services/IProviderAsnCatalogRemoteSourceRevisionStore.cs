using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

public interface IProviderAsnCatalogRemoteSourceRevisionStore
{
    Task InsertAsync(
        ProviderAsnCatalogRemoteSourceRevisionItem item,
        CancellationToken cancellationToken = default);

    Task<ProviderAsnCatalogRemoteSourceRevisionItem?> GetAsync(
        string id,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ProviderAsnCatalogRemoteSourceRevisionItem>> ListAsync(
        int maxItems = 1000,
        CancellationToken cancellationToken = default);
}
