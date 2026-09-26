namespace ServiceLib.Discovery.Models;

public sealed record ProviderAsnCatalogRemoteSourceChangeContext
{
    public string RevisionId { get; init; } = string.Empty;
    public string Reason { get; init; } = "configure";
}

public sealed record ProviderAsnCatalogRemoteSourceRevisionView
{
    public required string Id { get; init; }
    public required string RegistryId { get; init; }
    public string ChangeReason { get; init; } = string.Empty;
    public string BeforeFingerprint { get; init; } = string.Empty;
    public string AfterFingerprint { get; init; } = string.Empty;
    public string BeforeUri { get; init; } = string.Empty;
    public string AfterUri { get; init; } = string.Empty;
    public string BeforeSignatureUri { get; init; } = string.Empty;
    public string AfterSignatureUri { get; init; } = string.Empty;
    public ProviderAsnCatalogSignaturePolicy BeforeSignaturePolicy { get; init; }
    public ProviderAsnCatalogSignaturePolicy AfterSignaturePolicy { get; init; }
    public string BeforeTrustedKeyId { get; init; } = string.Empty;
    public string AfterTrustedKeyId { get; init; } = string.Empty;
    public string BeforeTrustedPublicKeySha256 { get; init; } = string.Empty;
    public string AfterTrustedPublicKeySha256 { get; init; } = string.Empty;
    public IReadOnlyList<string> BeforeTlsSpkiPinsSha256 { get; init; } = [];
    public IReadOnlyList<string> AfterTlsSpkiPinsSha256 { get; init; } = [];
    public IReadOnlyList<string> AddedTlsSpkiPinsSha256 { get; init; } = [];
    public IReadOnlyList<string> RemovedTlsSpkiPinsSha256 { get; init; } = [];
    public DateTimeOffset ChangedAt { get; init; }
}

public sealed record ProviderAsnCatalogRemoteSourceRevisionQuery
{
    public string? RegistryId { get; init; }
    public string? ChangeReason { get; init; }
    public string? TrustedKeyId { get; init; }
    public string? TlsSpkiPinSha256 { get; init; }
    public TimeSpan MaxAge { get; init; } = TimeSpan.FromDays(730);
    public int MaxItems { get; init; } = 250;
}

public sealed record ProviderAsnCatalogRemoteSourceRevisionSummary
{
    public int Total { get; init; }
    public int PinChanges { get; init; }
    public int SourceUriChanges { get; init; }
    public int SignatureTrustChanges { get; init; }
    public DateTimeOffset? LatestChangedAt { get; init; }
    public IReadOnlyList<ProviderAsnCatalogRemoteSourceRevisionView> Entries { get; init; } = [];
}

public sealed record ProviderAsnCatalogTlsPinRotationOptions
{
    public bool AllowUnpinning { get; init; }
}

public sealed record ProviderAsnCatalogTlsPinRotationPreview
{
    public required string RegistryId { get; init; }
    public required string CatalogId { get; init; }
    public IReadOnlyList<string> ExistingPinsSha256 { get; init; } = [];
    public IReadOnlyList<string> ProposedPinsSha256 { get; init; } = [];
    public required ProviderAsnCatalogRemoteSourceConfig ProposedSource { get; init; }
    public required string ExistingConfigurationFingerprint { get; init; }
    public required string ProposedConfigurationFingerprint { get; init; }
    public bool RemovesAllPins { get; init; }
    public DateTimeOffset PreparedAt { get; init; }
    public IReadOnlyList<string> Warnings { get; init; } = [];
}

public sealed record ProviderAsnCatalogTlsPinRotationReceipt
{
    public required string RevisionId { get; init; }
    public required string RegistryId { get; init; }
    public IReadOnlyList<string> BeforePinsSha256 { get; init; } = [];
    public IReadOnlyList<string> AfterPinsSha256 { get; init; } = [];
    public DateTimeOffset AppliedAt { get; init; }
    public bool RevisionRecorded { get; init; }
    public required ProviderAsnCatalogRemoteSourceView Source { get; init; }
}
