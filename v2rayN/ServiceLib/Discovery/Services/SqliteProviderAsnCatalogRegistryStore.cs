using ServiceLib.Discovery.Models;
using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

public sealed class SqliteProviderAsnCatalogRegistryStore : IProviderAsnCatalogRegistryStore
{
    public async Task<IReadOnlyList<ProviderAsnCatalogRegistryItem>> ListAsync(
        ProviderAsnCatalogRegistryQuery? query = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        query ??= new ProviderAsnCatalogRegistryQuery();
        if (query.MaxItems is < 1 or > 1000)
        {
            throw new ArgumentOutOfRangeException(nameof(query.MaxItems));
        }

        var table = SQLiteHelper.Instance.TableAsync<ProviderAsnCatalogRegistryItem>();

        if (query.IncludeUnregistered && query.IncludeDisabled)
        {
            return await table
                .OrderByDescending(x => x.UpdatedAtUnixMs)
                .Take(query.MaxItems)
                .ToListAsync();
        }
        if (query.IncludeUnregistered)
        {
            return await table
                .Where(x => x.Enabled)
                .OrderByDescending(x => x.UpdatedAtUnixMs)
                .Take(query.MaxItems)
                .ToListAsync();
        }
        if (query.IncludeDisabled)
        {
            return await table
                .Where(x => x.UnregisteredAtUnixMs == null)
                .OrderByDescending(x => x.UpdatedAtUnixMs)
                .Take(query.MaxItems)
                .ToListAsync();
        }

        return await table
            .Where(x => x.Enabled && x.UnregisteredAtUnixMs == null)
            .OrderByDescending(x => x.UpdatedAtUnixMs)
            .Take(query.MaxItems)
            .ToListAsync();
    }

    public async Task<ProviderAsnCatalogRegistryItem?> GetAsync(
        string id,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (id.IsNullOrEmpty())
        {
            return null;
        }

        return await SQLiteHelper.Instance.TableAsync<ProviderAsnCatalogRegistryItem>()
            .Where(x => x.Id == id)
            .FirstOrDefaultAsync();
    }

    public async Task<ProviderAsnCatalogRegistryItem?> FindByPathAsync(
        string normalizedPath,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (normalizedPath.IsNullOrEmpty())
        {
            return null;
        }

        return await SQLiteHelper.Instance.TableAsync<ProviderAsnCatalogRegistryItem>()
            .Where(x => x.FilePath == normalizedPath)
            .FirstOrDefaultAsync();
    }

    public async Task UpsertAsync(
        ProviderAsnCatalogRegistryItem item,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(item);
        cancellationToken.ThrowIfCancellationRequested();
        await SQLiteHelper.Instance.ReplaceAsync(item);
    }

    public async Task RemoveAsync(
        string id,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var row = await GetAsync(id, cancellationToken);
        if (row is not null)
        {
            await SQLiteHelper.Instance.DeleteAsync(row);
        }
    }

    public async Task<int> RetireAsync(
        ProviderAsnCatalogRegistryItem item,
        bool discardRevisionHistory,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(item);
        cancellationToken.ThrowIfCancellationRequested();

        var revisionCount = 0;
        await SQLiteHelper.Instance.RunInTransactionAsync(db =>
        {
            revisionCount = db.Table<ProviderAsnCatalogRevisionItem>()
                .Count(x => x.RegistryId == item.Id);
            db.InsertOrReplace(item);
            if (discardRevisionHistory && revisionCount > 0)
            {
                db.Execute(
                    $"DELETE FROM {nameof(ProviderAsnCatalogRevisionItem)} WHERE RegistryId = ?",
                    item.Id);
            }
        });
        return revisionCount;
    }

    public async Task<IReadOnlyList<ProviderAsnCatalogRevisionItem>> ListRevisionsAsync(
        ProviderAsnCatalogRevisionQuery? query = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        query ??= new ProviderAsnCatalogRevisionQuery();
        if (query.MaxItems is < 1 or > 1000)
        {
            throw new ArgumentOutOfRangeException(nameof(query.MaxItems));
        }

        var table = SQLiteHelper.Instance.TableAsync<ProviderAsnCatalogRevisionItem>();
        if (!query.RegistryId.IsNullOrEmpty() && !query.IncludeRolledBack)
        {
            return await table
                .Where(x => x.RegistryId == query.RegistryId && x.RolledBackAtUnixMs == null)
                .OrderByDescending(x => x.AppliedAtUnixMs)
                .Take(query.MaxItems)
                .ToListAsync();
        }
        if (!query.RegistryId.IsNullOrEmpty())
        {
            return await table
                .Where(x => x.RegistryId == query.RegistryId)
                .OrderByDescending(x => x.AppliedAtUnixMs)
                .Take(query.MaxItems)
                .ToListAsync();
        }
        if (!query.IncludeRolledBack)
        {
            return await table
                .Where(x => x.RolledBackAtUnixMs == null)
                .OrderByDescending(x => x.AppliedAtUnixMs)
                .Take(query.MaxItems)
                .ToListAsync();
        }

        return await table
            .OrderByDescending(x => x.AppliedAtUnixMs)
            .Take(query.MaxItems)
            .ToListAsync();
    }

    public async Task<ProviderAsnCatalogRevisionItem?> GetRevisionAsync(
        string id,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (id.IsNullOrEmpty())
        {
            return null;
        }

        return await SQLiteHelper.Instance.TableAsync<ProviderAsnCatalogRevisionItem>()
            .Where(x => x.Id == id)
            .FirstOrDefaultAsync();
    }

    public async Task InsertRevisionAsync(
        ProviderAsnCatalogRevisionItem item,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(item);
        cancellationToken.ThrowIfCancellationRequested();
        await SQLiteHelper.Instance.InsertAsync(item);
    }

    public async Task UpdateRevisionAsync(
        ProviderAsnCatalogRevisionItem item,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(item);
        cancellationToken.ThrowIfCancellationRequested();
        await SQLiteHelper.Instance.ReplaceAsync(item);
    }
}
