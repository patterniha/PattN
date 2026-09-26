using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

public interface IProviderAsnCatalogRemoteApplyProvenanceStore
{
    Task<ProviderAsnCatalogRemoteApplyProvenanceItem?> GetAsync(
        string revisionId,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ProviderAsnCatalogRemoteApplyProvenanceItem>> ListByRegistryAsync(
        string registryId,
        int maxItems = 5000,
        CancellationToken cancellationToken = default);

    Task UpsertAsync(
        ProviderAsnCatalogRemoteApplyProvenanceItem item,
        CancellationToken cancellationToken = default);
}
