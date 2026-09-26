namespace ServiceLib.Models.Entities;

[Serializable]
public class ProviderAsnCatalogRemoteSourceRevisionItem
{
    [PrimaryKey]
    public string Id { get; set; } = string.Empty;

    public string RegistryId { get; set; } = string.Empty;
    public string ChangeReason { get; set; } = string.Empty;
    public string BeforeFingerprint { get; set; } = string.Empty;
    public string AfterFingerprint { get; set; } = string.Empty;

    public string BeforeUri { get; set; } = string.Empty;
    public string AfterUri { get; set; } = string.Empty;
    public string BeforeSignatureUri { get; set; } = string.Empty;
    public string AfterSignatureUri { get; set; } = string.Empty;
    public int BeforeSignaturePolicy { get; set; }
    public int AfterSignaturePolicy { get; set; }
    public string BeforeTrustedKeyId { get; set; } = string.Empty;
    public string AfterTrustedKeyId { get; set; } = string.Empty;
    public string BeforeTrustedPublicKeySha256 { get; set; } = string.Empty;
    public string AfterTrustedPublicKeySha256 { get; set; } = string.Empty;

    public string BeforeTlsSpkiPinsSha256Json { get; set; } = string.Empty;
    public string AfterTlsSpkiPinsSha256Json { get; set; } = string.Empty;
    public string AddedTlsSpkiPinsSha256Json { get; set; } = string.Empty;
    public string RemovedTlsSpkiPinsSha256Json { get; set; } = string.Empty;

    public long ChangedAtUnixMs { get; set; }
}
