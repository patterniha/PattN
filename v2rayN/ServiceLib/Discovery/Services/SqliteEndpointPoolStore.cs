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
        var rows = await SQLiteHelper.Instance.TableAsync<EndpointPoolItem>()
            .Where(x => x.LogicalHost == logicalHost
                        && x.HttpHost == httpHost
                        && x.Port == request.OriginalPort
                        && x.Network == network
                        && x.StreamSecurity == security
                        && x.Address == address)
            .ToListAsync();

        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var item = rows.FirstOrDefault() ?? new EndpointPoolItem
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

        item.HttpHost = httpHost;
        item.Label = label is null ? item.Label : EndpointPoolPolicy.NormalizeLabel(label);
        item.Enabled = true;
        item.Pinned = pinned;
        item.Provider = candidate.Provider ?? item.Provider;
        item.Asn = candidate.Asn ?? item.Asn;
        item.Pop = candidate.Pop ?? item.Pop;
        item.UpdatedAtUnixMs = now;

        await SQLiteHelper.Instance.ReplaceAsync(item);
        return item;
    }

    public async Task<IReadOnlyList<EndpointPoolItem>> ListAsync(
        EndpointPoolQuery? query = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        query ??= new EndpointPoolQuery();
        if (query.MaxItems is < 1 or > 2000)
        {
            throw new ArgumentOutOfRangeException(nameof(query), "Endpoint pool query must request between 1 and 2000 items.");
        }

        var logicalHost = NormalizeHost(query.LogicalHost);
        var table = SQLiteHelper.Instance.TableAsync<EndpointPoolItem>();
        if (!logicalHost.IsNullOrEmpty())
        {
            table = table.Where(x => x.LogicalHost == logicalHost);
        }
        if (!query.IncludeDisabled)
        {
            // Filter before applying MaxItems. Taking the newest mixed enabled/disabled rows
            // and filtering afterward can hide older enabled entries even when the caller
            // explicitly requested an enabled-only page.
            table = table.Where(x => x.Enabled);
        }

        var rows = await table
            .OrderByDescending(x => x.UpdatedAtUnixMs)
            .Take(query.MaxItems)
            .ToListAsync();

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
