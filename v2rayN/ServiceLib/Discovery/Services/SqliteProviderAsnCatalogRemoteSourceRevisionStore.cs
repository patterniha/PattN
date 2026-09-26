using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

public sealed class SqliteProviderAsnCatalogRemoteSourceRevisionStore
    : IProviderAsnCatalogRemoteSourceRevisionStore
{
    public async Task InsertAsync(
        ProviderAsnCatalogRemoteSourceRevisionItem item,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(item);
        cancellationToken.ThrowIfCancellationRequested();
        await SQLiteHelper.Instance.InsertAsync(item);
    }

    public async Task<ProviderAsnCatalogRemoteSourceRevisionItem?> GetAsync(
        string id,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (id.IsNullOrEmpty())
        {
            return null;
        }
        return await SQLiteHelper.Instance.TableAsync<ProviderAsnCatalogRemoteSourceRevisionItem>()
            .Where(x => x.Id == id)
            .FirstOrDefaultAsync();
    }

    public async Task<IReadOnlyList<ProviderAsnCatalogRemoteSourceRevisionItem>> ListAsync(
        int maxItems = 1000,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (maxItems is < 1 or > 5000)
        {
            throw new ArgumentOutOfRangeException(nameof(maxItems));
        }
        return await SQLiteHelper.Instance.TableAsync<ProviderAsnCatalogRemoteSourceRevisionItem>()
            .OrderByDescending(x => x.ChangedAtUnixMs)
            .Take(maxItems)
            .ToListAsync();
    }
}
