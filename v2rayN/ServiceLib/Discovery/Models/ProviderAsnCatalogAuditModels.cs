namespace ServiceLib.Discovery.Models;

public sealed record ProviderAsnCatalogAuditPolicy
{
    public TimeSpan MaximumAge { get; init; } = TimeSpan.FromDays(120);
    public TimeSpan MaximumFutureClockSkew { get; init; } = TimeSpan.FromMinutes(10);
    public int MaximumDuplicateDetails { get; init; } = 100;
}

public sealed record ProviderAsnCatalogDuplicate
{
    public required string Kind { get; init; }
    public required string Key { get; init; }
    public int Count { get; init; }
}

public sealed record ProviderAsnCatalogAudit
{
    public string CatalogId { get; init; } = string.Empty;
    public string CatalogVersion { get; init; } = string.Empty;
    public string Source { get; init; } = string.Empty;
    public string Sha256 { get; init; } = string.Empty;
    public DateTimeOffset? UpdatedAt { get; init; }
    public DateTimeOffset AuditedAt { get; init; }
    public bool FreshnessKnown { get; init; }
    public bool Stale { get; init; }
    public double? AgeDays { get; init; }
    public int TotalEntries { get; init; }
    public int EnabledEntries { get; init; }
    public int DisabledEntries { get; init; }
    public int IPv4Entries { get; init; }
    public int IPv6Entries { get; init; }
    public int UniqueAddresses { get; init; }
    public int ProviderCount { get; init; }
    public int AsnCount { get; init; }
    public int PopCount { get; init; }
    public int HostScopedEntries { get; init; }
    public int BroadScopeEntries { get; init; }
    public int MissingProviderEntries { get; init; }
    public int MissingAsnEntries { get; init; }
    public int DuplicateSourceIdGroups { get; init; }
    public int ExactDuplicateGroups { get; init; }
    public IReadOnlyList<ProviderAsnCatalogDuplicate> Duplicates { get; init; } = [];
    public IReadOnlyList<string> Warnings { get; init; } = [];
    public IReadOnlyList<string> Errors { get; init; } = [];
    public bool Valid => Errors.Count == 0;
}
