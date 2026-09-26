namespace ServiceLib.Discovery.Models;

public sealed record ProviderAsnCatalogRemoteHealthPolicy
{
    public TimeSpan MaximumCheckAge { get; init; } = TimeSpan.FromDays(30);
}

public sealed record ProviderAsnCatalogRemoteHealthRow
{
    public required string RegistryId { get; init; }
    public string DisplayName { get; init; } = string.Empty;
    public string CatalogId { get; init; } = string.Empty;
    public string CatalogVersion { get; init; } = string.Empty;
    public bool CatalogEnabled { get; init; }
    public bool Configured { get; init; }
    public string SourceUri { get; init; } = string.Empty;
    public ProviderAsnCatalogSignaturePolicy SignaturePolicy { get; init; }
    public DateTimeOffset? LastCheckedAt { get; init; }
    public DateTimeOffset? LastFetchedAt { get; init; }
    public bool? LastSignatureValid { get; init; }
    public string LastSignatureStatus { get; init; } = string.Empty;
    public string RemoteContentSha256 { get; init; } = string.Empty;
    public bool CatalogAuditValid { get; init; }
    public bool CatalogFreshnessKnown { get; init; }
    public bool CatalogStale { get; init; }
    public string HealthClass { get; init; } = "unconfigured";
    public bool NeedsReview { get; init; }
    public IReadOnlyList<string> Reasons { get; init; } = [];
}

public sealed record ProviderAsnCatalogRemoteHealthSummary
{
    public DateTimeOffset RefreshedAt { get; init; }
    public IReadOnlyList<ProviderAsnCatalogRemoteHealthRow> Rows { get; init; } = [];
    public int TotalCatalogs => Rows.Count;
    public int Configured => Rows.Count(x => x.Configured);
    public int Healthy => Rows.Count(x => x.HealthClass == "healthy");
    public int NeedsReview => Rows.Count(x => x.NeedsReview);
    public int Unconfigured => Rows.Count(x => !x.Configured);
}
