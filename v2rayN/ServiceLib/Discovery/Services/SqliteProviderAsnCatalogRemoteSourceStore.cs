using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

public sealed class SqliteProviderAsnCatalogRemoteSourceStore : IProviderAsnCatalogRemoteSourceStore
{
    public async Task<ProviderAsnCatalogRemoteSourceItem?> GetAsync(
        string registryId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (registryId.IsNullOrEmpty())
        {
            return null;
        }
        return await SQLiteHelper.Instance.TableAsync<ProviderAsnCatalogRemoteSourceItem>()
            .Where(x => x.RegistryId == registryId)
            .FirstOrDefaultAsync();
    }

    public async Task<IReadOnlyList<ProviderAsnCatalogRemoteSourceItem>> ListAsync(
        int maxItems = 500,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (maxItems is < 1 or > 5000)
        {
            throw new ArgumentOutOfRangeException(nameof(maxItems));
        }
        return await SQLiteHelper.Instance.TableAsync<ProviderAsnCatalogRemoteSourceItem>()
            .OrderByDescending(x => x.ConfigurationUpdatedAtUnixMs)
            .Take(maxItems)
            .ToListAsync();
    }

    public async Task UpsertAsync(
        ProviderAsnCatalogRemoteSourceItem item,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(item);
        cancellationToken.ThrowIfCancellationRequested();
        await SQLiteHelper.Instance.ReplaceAsync(item);
    }

    public async Task RemoveAsync(
        string registryId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var item = await GetAsync(registryId, cancellationToken);
        if (item is not null)
        {
            await SQLiteHelper.Instance.DeleteAsync(item);
        }
    }
}
