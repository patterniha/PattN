namespace ServiceLib.Discovery.Models;

public sealed record ProviderAsnCatalogArchiveOptions
{
    public bool AllowFileDrift { get; init; }
    public int MaxRevisions { get; init; } = 1000;
}

public sealed record ProviderAsnCatalogArchiveBundle
{
    public int FormatVersion { get; init; } = 3;
    public DateTimeOffset CreatedAt { get; init; }
    public required ProviderAsnCatalogRegistryView Registry { get; init; }
    public required string CatalogFileName { get; init; }
    public required string CatalogFileSha256 { get; init; }
    public required string CatalogFileBase64 { get; init; }
    public IReadOnlyList<ProviderAsnCatalogRevisionView> Revisions { get; init; } = [];
    public IReadOnlyList<ProviderAsnCatalogRemoteApplyProvenanceView> RemoteProvenance { get; init; } = [];
    public ProviderAsnCatalogArchiveSignatureEnvelope? ArchiveSignature { get; init; }
    public string Notes { get; init; } =
        "Archive contains the current catalog file plus persisted registry/audit/revision metadata and matching remote-apply provenance. It does not contain prior revision rollback file bytes or trusted private key material.";
}
