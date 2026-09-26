using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

public sealed class SqliteProviderAsnCatalogRemoteApplyProvenanceStore
    : IProviderAsnCatalogRemoteApplyProvenanceStore
{
    public async Task<ProviderAsnCatalogRemoteApplyProvenanceItem?> GetAsync(
        string revisionId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (revisionId.IsNullOrEmpty())
        {
            return null;
        }

        return await SQLiteHelper.Instance.TableAsync<ProviderAsnCatalogRemoteApplyProvenanceItem>()
            .Where(x => x.RevisionId == revisionId)
            .FirstOrDefaultAsync();
    }

    public async Task<IReadOnlyList<ProviderAsnCatalogRemoteApplyProvenanceItem>> ListByRegistryAsync(
        string registryId,
        int maxItems = 5000,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (registryId.IsNullOrEmpty())
        {
            return [];
        }
        if (maxItems is < 1 or > 5000)
        {
            throw new ArgumentOutOfRangeException(nameof(maxItems));
        }

        return await SQLiteHelper.Instance.TableAsync<ProviderAsnCatalogRemoteApplyProvenanceItem>()
            .Where(x => x.RegistryId == registryId)
            .OrderByDescending(x => x.AppliedAtUnixMs)
            .Take(maxItems)
            .ToListAsync();
    }

    public async Task UpsertAsync(
        ProviderAsnCatalogRemoteApplyProvenanceItem item,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(item);
        cancellationToken.ThrowIfCancellationRequested();
        if (item.RevisionId.IsNullOrEmpty())
        {
            throw new ArgumentException("Remote apply provenance requires a revision ID.", nameof(item));
        }

        await SQLiteHelper.Instance.ReplaceAsync(item);
    }
}
