namespace ServiceLib.Discovery.Models;

public sealed record ProviderAsnCatalogArchiveInspection
{
    public required string SourcePath { get; init; }
    public int FormatVersion { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
    public required string RegistryId { get; init; }
    public required string CatalogId { get; init; }
    public required string CatalogVersion { get; init; }
    public required string CatalogFileName { get; init; }
    public required string CatalogFileSha256 { get; init; }
    public bool RegistryShaMatchesPayload { get; init; }
    public int CatalogBytes { get; init; }
    public int CatalogEntries { get; init; }
    public int Revisions { get; init; }
    public int RemoteProvenanceRecords { get; init; }
    public ProviderAsnCatalogArchiveSignatureValidation? ArchiveSignatureValidation { get; init; }
    public ProviderAsnCatalogAudit? CatalogAudit { get; init; }
    public IReadOnlyList<string> Warnings { get; init; } = [];
}

public sealed record ProviderAsnCatalogArchiveInspectionOptions
{
    public int MaximumArchiveBytes { get; init; } = 64 * 1024 * 1024;
    public ProviderAsnCatalogAuditPolicy AuditPolicy { get; init; } = new();
    public ProviderAsnCatalogArchiveSignatureTrust ArchiveSignatureTrust { get; init; } = new();
}
