namespace ServiceLib.Models.Entities;

[Serializable]
public class ProviderAsnCatalogRemoteApplyProvenanceItem
{
    [PrimaryKey]
    public string RevisionId { get; set; } = string.Empty;

    public string RegistryId { get; set; } = string.Empty;
    public string SourceUri { get; set; } = string.Empty;
    public string SourceFinalUri { get; set; } = string.Empty;
    public string SignatureUri { get; set; } = string.Empty;
    public string SignatureFinalUri { get; set; } = string.Empty;
    public int SignaturePolicy { get; set; }
    public string TrustedKeyId { get; set; } = string.Empty;
    public string TlsSpkiPinsSha256Json { get; set; } = string.Empty;

    public bool ServerNotModified { get; set; }
    public string ETag { get; set; } = string.Empty;
    public long? LastModifiedUnixMs { get; set; }
    public string RemoteContentSha256 { get; set; } = string.Empty;

    public bool SignatureAttempted { get; set; }
    public bool SignatureValid { get; set; }
    public bool SignaturePolicySatisfied { get; set; }
    public string SignatureStatus { get; set; } = string.Empty;
    public string SignatureKeyId { get; set; } = string.Empty;
    public string SignatureCatalogSha256 { get; set; } = string.Empty;
    public long? SignatureSignedAtUnixMs { get; set; }

    public long CheckedAtUnixMs { get; set; }
    public long AppliedAtUnixMs { get; set; }
}
