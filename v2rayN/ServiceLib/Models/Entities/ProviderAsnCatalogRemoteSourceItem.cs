namespace ServiceLib.Models.Entities;

[Serializable]
public class ProviderAsnCatalogRemoteSourceItem
{
    [PrimaryKey]
    public string RegistryId { get; set; } = string.Empty;

    public string Uri { get; set; } = string.Empty;
    public string SignatureUri { get; set; } = string.Empty;
    public int SignaturePolicy { get; set; }
    public string TrustedKeyId { get; set; } = string.Empty;
    public string TrustedPublicKeySpkiBase64 { get; set; } = string.Empty;
    public string TlsSpkiPinsSha256Json { get; set; } = string.Empty;

    public string ETag { get; set; } = string.Empty;
    public long? LastModifiedUnixMs { get; set; }
    public string RemoteContentSha256 { get; set; } = string.Empty;

    public long ConfigurationUpdatedAtUnixMs { get; set; }
    public long CacheUpdatedAtUnixMs { get; set; }
    public long LastCheckedAtUnixMs { get; set; }
    public long? LastFetchedAtUnixMs { get; set; }

    public bool? LastSignatureValid { get; set; }
    public string LastSignatureStatus { get; set; } = string.Empty;
    public string LastSignatureKeyId { get; set; } = string.Empty;
    public string LastSignatureCatalogSha256 { get; set; } = string.Empty;
    public long? LastSignatureSignedAtUnixMs { get; set; }
}
