namespace ServiceLib.Discovery.Models;

public sealed record ProviderAsnCatalogUpdateOptions
{
    public bool RequireSameCatalogId { get; init; } = true;
    public bool RequireFreshNewCatalog { get; init; }
    public ProviderAsnCatalogAuditPolicy AuditPolicy { get; init; } = new();
}

public sealed record ProviderAsnCatalogUpdatePlan
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public required string DestinationPath { get; init; }
    public DateTimeOffset PreparedAt { get; init; }
    public bool DestinationExisted { get; init; }
    public string BeforeSha256 { get; init; } = string.Empty;
    public string AfterSha256 { get; init; } = string.Empty;
    public string BeforeCatalogId { get; init; } = string.Empty;
    public string BeforeCatalogVersion { get; init; } = string.Empty;
    public string AfterCatalogId { get; init; } = string.Empty;
    public string AfterCatalogVersion { get; init; } = string.Empty;
    public string BeforeCatalogError { get; init; } = string.Empty;
    public ProviderAsnCatalogAudit? BeforeAudit { get; init; }
    public required ProviderAsnCatalogAudit AfterAudit { get; init; }
    public ProviderAsnCatalogDiff? Diff { get; init; }
    public byte[] BeforeBytes { get; init; } = [];
    public required byte[] AfterBytes { get; init; }
}

public sealed record ProviderAsnCatalogUpdateReceipt
{
    public required string PlanId { get; init; }
    public required string DestinationPath { get; init; }
    public bool DestinationExisted { get; init; }
    public string BeforeSha256 { get; init; } = string.Empty;
    public required string AfterSha256 { get; init; }
    public byte[] BeforeBytes { get; init; } = [];
    public DateTimeOffset AppliedAt { get; init; } = DateTimeOffset.UtcNow;
}
