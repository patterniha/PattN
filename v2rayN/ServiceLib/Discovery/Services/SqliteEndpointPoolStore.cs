using ServiceLib.Discovery.Models;
using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

public sealed class SqliteEndpointPoolStore : IEndpointPoolStore, IEndpointPoolAdminStore
{
    public async Task<IReadOnlyList<DiscoveryEndpointCandidate>> GetCandidatesAsync(
        DiscoveryCandidateRequest request,
        int maxCandidates,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        if (maxCandidates <= 0)
        {
            return [];
        }

        var logicalHost = NormalizeHost(request.LogicalHost);
        var httpHost = NormalizeHost(string.IsNullOrWhiteSpace(request.HttpHost) ? request.LogicalHost : request.HttpHost);
        if (logicalHost.IsNullOrEmpty())
        {
            return [];
        }

        var network = NormalizeToken(request.Network);
        var security = NormalizeToken(request.StreamSecurity);
        var rows = await SQLiteHelper.Instance.TableAsync<EndpointPoolItem>()
            .Where(x => x.Enabled
                        && x.LogicalHost == logicalHost
                        && x.HttpHost == httpHost
                        && x.Port == request.OriginalPort
                        && x.Network == network
                        && x.StreamSecurity == security)
            .ToListAsync();

        return rows
            .OrderByDescending(x => x.Pinned)
            .ThenByDescending(x => x.UpdatedAtUnixMs)
            .ThenBy(x => x.Address, StringComparer.OrdinalIgnoreCase)
            .Take(maxCandidates)
            .Select(x => new DiscoveryEndpointCandidate
            {
                Address = x.Address,
                Port = x.Port,
                Source = "endpoint.pool",
                Provider = x.Provider.NullIfEmpty(),
                Asn = x.Asn.NullIfEmpty(),
                Pop = x.Pop.NullIfEmpty(),
                ObservedAt = DateTimeOffset.FromUnixTimeMilliseconds(x.UpdatedAtUnixMs),
                Metadata = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["poolId"] = x.Id,
                    ["poolLabel"] = x.Label,
                    ["pinned"] = x.Pinned ? "true" : "false",
                },
            })
            .ToArray();
    }

    public async Task<EndpointPoolItem> UpsertAsync(
        DiscoveryCandidateRequest request,
        DiscoveryEndpointCandidate candidate,
        bool pinned = false,
        string? label = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(candidate);
        cancellationToken.ThrowIfCancellationRequested();

        var logicalHost = NormalizeHost(request.LogicalHost);
        var httpHost = NormalizeHost(string.IsNullOrWhiteSpace(request.HttpHost) ? request.LogicalHost : request.HttpHost);
        var address = NormalizeAddress(candidate.Address);
        if (logicalHost.IsNullOrEmpty())
        {
            throw new ArgumentException("Endpoint pool entries require a logical host.", nameof(request));
        }
        if (request.OriginalPort is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "Endpoint pool port must be between 1 and 65535.");
        }
        if (!DiscoveryEndpointAddress.TryNormalizeLiteral(address, out address))
        {
            throw new ArgumentException("Endpoint pool entries require a literal IP address.", nameof(candidate));
        }

        var network = NormalizeToken(request.Network);
        var security = NormalizeToken(request.StreamSecurity);
        var normalizedLabel = label is null ? null : EndpointPoolPolicy.NormalizeLabel(label);
        EndpointPoolItem? item = null;

        await SQLiteHelper.Instance.RunInTransactionAsync(db =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            var rows = db.Table<EndpointPoolItem>()
                .Where(x => x.LogicalHost == logicalHost
                            && x.HttpHost == httpHost
                            && x.Port == request.OriginalPort
                            && x.Network == network
                            && x.StreamSecurity == security
                            && x.Address == address)
                .ToList();

            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            item = rows
                .OrderByDescending(x => x.UpdatedAtUnixMs)
                .ThenBy(x => x.Id, StringComparer.Ordinal)
                .FirstOrDefault() ?? new EndpointPoolItem
                {
                    Id = Utils.GetGuid(false),
                    LogicalHost = logicalHost,
                    HttpHost = httpHost,
                    Port = request.OriginalPort,
                    Network = network,
                    StreamSecurity = security,
                    Address = address,
                    CreatedAtUnixMs = now,
                };

            foreach (var duplicate in rows.Where(x => !ReferenceEquals(x, item)))
            {
                db.Delete(duplicate);
            }

            item.HttpHost = httpHost;
            item.Label = normalizedLabel ?? item.Label;
            item.Enabled = true;
            item.Pinned = pinned;
            item.Provider = candidate.Provider ?? item.Provider;
            item.Asn = candidate.Asn ?? item.Asn;
            item.Pop = candidate.Pop ?? item.Pop;
            item.UpdatedAtUnixMs = now;
            db.InsertOrReplace(item);
        });

        return item ?? throw new InvalidOperationException("Endpoint pool upsert did not produce an item.");
    }

    public async Task<IReadOnlyList<EndpointPoolItem>> ListAsync(
        EndpointPoolQuery? query = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        query ??= new EndpointPoolQuery();
        if (query.MaxItems is < 1 or > EndpointPoolQuery.MaximumItems)
        {
            throw new ArgumentOutOfRangeException(
                nameof(query),
                $"Endpoint pool query must request between 1 and {EndpointPoolQuery.MaximumItems} items.");
        }

        var logicalHost = NormalizeHost(query.LogicalHost);
        var table = SQLiteHelper.Instance.TableAsync<EndpointPoolItem>();
        if (!logicalHost.IsNullOrEmpty())
        {
            table = table.Where(x => x.LogicalHost == logicalHost);
        }
        if (!query.IncludeDisabled)
        {
            table = table.Where(x => x.Enabled);
        }
        if (query.DisabledUnpinnedBeforeUnixMs is long cutoff)
        {
            table = table.Where(x => !x.Enabled
                                     && !x.Pinned
                                     && x.UpdatedAtUnixMs > 0
                                     && x.UpdatedAtUnixMs < cutoff);
        }

        var rows = query.OldestFirst
            ? await table.OrderBy(x => x.UpdatedAtUnixMs).Take(query.MaxItems).ToListAsync()
            : await table.OrderByDescending(x => x.UpdatedAtUnixMs).Take(query.MaxItems).ToListAsync();

        if (query.OldestFirst)
        {
            return rows
                .OrderBy(x => x.UpdatedAtUnixMs)
                .ThenBy(x => x.Id, StringComparer.Ordinal)
                .ToArray();
        }

        return rows
            .OrderByDescending(x => x.Pinned)
            .ThenByDescending(x => x.Enabled)
            .ThenByDescending(x => x.UpdatedAtUnixMs)
            .ToArray();
    }

    public async Task<EndpointPoolItem?> UpdateAsync(
        EndpointPoolUpdate update,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(update);
        cancellationToken.ThrowIfCancellationRequested();
        if (update.Id.IsNullOrEmpty())
        {
            throw new ArgumentException("Endpoint pool item ID is required.", nameof(update));
        }

        var item = await SQLiteHelper.Instance.TableAsync<EndpointPoolItem>()
            .Where(x => x.Id == update.Id)
            .FirstOrDefaultAsync();
        if (item is null)
        {
            return null;
        }

        if (update.Enabled is not null)
        {
            item.Enabled = update.Enabled.Value;
        }
        if (update.Pinned is not null)
        {
            item.Pinned = update.Pinned.Value;
        }
        if (update.Label is not null)
        {
            item.Label = EndpointPoolPolicy.NormalizeLabel(update.Label);
        }
        item.UpdatedAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        await SQLiteHelper.Instance.ReplaceAsync(item);
        return item;
    }

    public async Task RemoveAsync(string id, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (id.IsNullOrEmpty())
        {
            return;
        }

        var row = await SQLiteHelper.Instance.TableAsync<EndpointPoolItem>()
            .Where(x => x.Id == id)
            .FirstOrDefaultAsync();
        if (row is not null)
        {
            await SQLiteHelper.Instance.DeleteAsync(row);
        }
    }

    private static string NormalizeHost(string? value)
        => (value ?? string.Empty).Trim().Trim('[', ']').TrimEnd('.').ToLowerInvariant();

    private static string NormalizeAddress(string? value)
        => DiscoveryEndpointAddress.NormalizeIfLiteral(value);

    private static string NormalizeToken(string? value)
        => (value ?? string.Empty).Trim().ToLowerInvariant();
}
