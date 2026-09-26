using ServiceLib.Discovery.Models;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Metadata-only provider catalog audit. It never probes or expands address space and does not gate candidate
/// use by itself; callers can decide how to display or govern freshness warnings.
/// </summary>
public static class ProviderAsnCatalogAuditService
{
    public static ProviderAsnCatalogAudit Audit(
        JsonProviderAsnEndpointCatalog catalog,
        DateTimeOffset? now = null,
        ProviderAsnCatalogAuditPolicy? policy = null)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        policy ??= new ProviderAsnCatalogAuditPolicy();
        Validate(policy);

        var auditedAt = now ?? DateTimeOffset.UtcNow;
        var document = catalog.Document;
        var entries = catalog.Entries;
        var warnings = new List<string>();
        var errors = new List<string>();

        bool freshnessKnown = document.UpdatedAt is not null;
        bool stale = false;
        double? ageDays = null;
        if (document.UpdatedAt is null)
        {
            warnings.Add("catalog-updated-at-missing");
        }
        else
        {
            var age = auditedAt - document.UpdatedAt.Value;
            if (document.UpdatedAt.Value - auditedAt > policy.MaximumFutureClockSkew)
            {
                ageDays = 0;
                errors.Add("catalog-updated-at-in-future");
            }
            else
            {
                ageDays = Math.Max(0d, age.TotalDays);
                if (age > policy.MaximumAge)
                {
                    stale = true;
                    warnings.Add("catalog-stale");
                }
            }
        }

        var sourceIdDuplicates = entries
            .Where(x => !x.SourceId.IsNullOrEmpty())
            .GroupBy(x => x.SourceId, StringComparer.Ordinal)
            .Where(x => x.Count() > 1)
            .OrderByDescending(x => x.Count())
            .ThenBy(x => x.Key, StringComparer.Ordinal)
            .ToArray();

        var exactDuplicates = entries
            .GroupBy(ExactDuplicateKey, StringComparer.Ordinal)
            .Where(x => x.Count() > 1)
            .OrderByDescending(x => x.Count())
            .ThenBy(x => x.Key, StringComparer.Ordinal)
            .ToArray();

        if (sourceIdDuplicates.Length > 0)
        {
            warnings.Add("duplicate-source-ids");
        }
        if (exactDuplicates.Length > 0)
        {
            warnings.Add("exact-duplicate-entries");
        }

        var duplicates = sourceIdDuplicates
            .Select(x => new ProviderAsnCatalogDuplicate
            {
                Kind = "source-id",
                Key = x.Key,
                Count = x.Count(),
            })
            .Concat(exactDuplicates.Select(x => new ProviderAsnCatalogDuplicate
            {
                Kind = "endpoint-scope",
                Key = x.Key,
                Count = x.Count(),
            }))
            .Take(policy.MaximumDuplicateDetails)
            .ToArray();

        var ipv4 = 0;
        var ipv6 = 0;
        foreach (var entry in entries)
        {
            if (IPAddress.TryParse(entry.Address, out var ip))
            {
                if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    ipv4++;
                }
                else if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    ipv6++;
                }
            }
        }

        var broadScope = entries.Count(IsBroadScope);
        if (broadScope > 0)
        {
            warnings.Add("broad-scope-entries-present");
        }

        return new ProviderAsnCatalogAudit
        {
            CatalogId = document.Id,
            CatalogVersion = document.Version,
            Source = document.Source,
            Sha256 = catalog.Sha256,
            UpdatedAt = document.UpdatedAt,
            AuditedAt = auditedAt,
            FreshnessKnown = freshnessKnown,
            Stale = stale,
            AgeDays = ageDays,
            TotalEntries = entries.Count,
            EnabledEntries = entries.Count(x => x.Enabled),
            DisabledEntries = entries.Count(x => !x.Enabled),
            IPv4Entries = ipv4,
            IPv6Entries = ipv6,
            UniqueAddresses = entries.Select(x => NormalizeAddress(x.Address)).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
            ProviderCount = entries.Select(x => x.Provider?.Trim()).Where(x => !x.IsNullOrEmpty()).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
            AsnCount = entries.Select(x => x.Asn?.Trim()).Where(x => !x.IsNullOrEmpty()).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
            PopCount = entries.Select(x => x.Pop?.Trim()).Where(x => !x.IsNullOrEmpty()).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
            HostScopedEntries = entries.Count(x => x.LogicalHosts is { Count: > 0 }),
            BroadScopeEntries = broadScope,
            MissingProviderEntries = entries.Count(x => x.Provider.IsNullOrEmpty()),
            MissingAsnEntries = entries.Count(x => x.Asn.IsNullOrEmpty()),
            DuplicateSourceIdGroups = sourceIdDuplicates.Length,
            ExactDuplicateGroups = exactDuplicates.Length,
            Duplicates = duplicates,
            Warnings = warnings.Distinct(StringComparer.Ordinal).OrderBy(x => x, StringComparer.Ordinal).ToArray(),
            Errors = errors.Distinct(StringComparer.Ordinal).OrderBy(x => x, StringComparer.Ordinal).ToArray(),
        };
    }

    private static string ExactDuplicateKey(ProviderAsnEndpointCatalogEntry entry)
    {
        var hosts = entry.LogicalHosts is null
            ? string.Empty
            : string.Join(",", entry.LogicalHosts.Select(NormalizeHost).OrderBy(x => x, StringComparer.Ordinal));
        return string.Join("|",
            NormalizeAddress(entry.Address),
            entry.Port?.ToString() ?? "*",
            NormalizeToken(entry.Network),
            NormalizeToken(entry.StreamSecurity),
            hosts,
            entry.Enabled ? "enabled" : "disabled");
    }

    private static bool IsBroadScope(ProviderAsnEndpointCatalogEntry entry)
        => entry.Port is null
           && (entry.LogicalHosts is null || entry.LogicalHosts.Count == 0)
           && entry.Network.IsNullOrEmpty()
           && entry.StreamSecurity.IsNullOrEmpty();

    private static string NormalizeAddress(string? value)
        => (value ?? string.Empty).Trim().Trim('[', ']');

    private static string NormalizeHost(string? value)
        => (value ?? string.Empty).Trim().Trim('[', ']').TrimEnd('.').ToLowerInvariant();

    private static string NormalizeToken(string? value)
        => (value ?? string.Empty).Trim().ToLowerInvariant();

    private static void Validate(ProviderAsnCatalogAuditPolicy policy)
    {
        if (policy.MaximumAge <= TimeSpan.Zero || policy.MaximumAge > TimeSpan.FromDays(3650))
        {
            throw new ArgumentOutOfRangeException(nameof(policy.MaximumAge));
        }
        if (policy.MaximumFutureClockSkew < TimeSpan.Zero || policy.MaximumFutureClockSkew > TimeSpan.FromHours(24))
        {
            throw new ArgumentOutOfRangeException(nameof(policy.MaximumFutureClockSkew));
        }
        if (policy.MaximumDuplicateDetails is < 0 or > 10000)
        {
            throw new ArgumentOutOfRangeException(nameof(policy.MaximumDuplicateDetails));
        }
    }
}
