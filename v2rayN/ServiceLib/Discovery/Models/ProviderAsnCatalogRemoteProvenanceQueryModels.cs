namespace ServiceLib.Discovery.Models;

public sealed record ProviderAsnCatalogRemoteProvenanceQuery
{
    public string? RegistryId { get; init; }
    public string? RevisionId { get; init; }
    public string? SourceHost { get; init; }
    public string? TrustedKeyId { get; init; }
    public string? TlsSpkiPinSha256 { get; init; }
    public string? SignatureStatus { get; init; }
    public bool? SignatureValid { get; init; }
    public bool? SignaturePolicySatisfied { get; init; }
    public TimeSpan MaxAge { get; init; } = TimeSpan.FromDays(730);
    public int MaxItems { get; init; } = 250;
}

public sealed record ProviderAsnCatalogRemoteProvenanceSummary
{
    public int Total { get; init; }
    public int SignatureAttempted { get; init; }
    public int SignatureValid { get; init; }
    public int SignaturePolicySatisfied { get; init; }
    public int TransportPinned { get; init; }
    public int ServerNotModified { get; init; }
    public DateTimeOffset? LatestAppliedAt { get; init; }
    public IReadOnlyList<ProviderAsnCatalogRemoteApplyProvenanceView> Entries { get; init; } = [];
}
