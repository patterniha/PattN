namespace ServiceLib.Discovery.Models;

public enum ProviderAsnCatalogSignaturePolicy
{
    None = 0,
    Optional = 1,
    Required = 2,
}

public sealed record ProviderAsnCatalogRemoteSourceConfig
{
    public required string Uri { get; init; }
    public string SignatureUri { get; init; } = string.Empty;
    public ProviderAsnCatalogSignaturePolicy SignaturePolicy { get; init; }
    public string TrustedKeyId { get; init; } = string.Empty;

    /// <summary>
    /// Base64 SubjectPublicKeyInfo encoding of the locally trusted ECDSA P-256 public key.
    /// The trusted key never comes from the fetched catalog/signature response.
    /// </summary>
    public string TrustedPublicKeySpkiBase64 { get; init; } = string.Empty;

    /// <summary>
    /// Optional SHA-256 hashes of trusted TLS SubjectPublicKeyInfo values. These pins are an additional
    /// constraint after normal TLS chain/hostname validation; they never replace platform TLS validation.
    /// </summary>
    public IReadOnlyList<string> TlsSpkiPinsSha256 { get; init; } = [];
}

public sealed record ProviderAsnCatalogRemoteSourceView
{
    public required string RegistryId { get; init; }
    public required string Uri { get; init; }
    public string SignatureUri { get; init; } = string.Empty;
    public ProviderAsnCatalogSignaturePolicy SignaturePolicy { get; init; }
    public string TrustedKeyId { get; init; } = string.Empty;
    public string TrustedPublicKeySpkiBase64 { get; init; } = string.Empty;
    public IReadOnlyList<string> TlsSpkiPinsSha256 { get; init; } = [];
    public string ETag { get; init; } = string.Empty;
    public DateTimeOffset? LastModified { get; init; }
    public string RemoteContentSha256 { get; init; } = string.Empty;
    public DateTimeOffset ConfigurationUpdatedAt { get; init; }
    public DateTimeOffset? CacheUpdatedAt { get; init; }
    public DateTimeOffset? LastCheckedAt { get; init; }
    public DateTimeOffset? LastFetchedAt { get; init; }
    public bool? LastSignatureValid { get; init; }
    public string LastSignatureStatus { get; init; } = string.Empty;
    public string LastSignatureKeyId { get; init; } = string.Empty;
    public string LastSignatureCatalogSha256 { get; init; } = string.Empty;
    public DateTimeOffset? LastSignatureSignedAt { get; init; }
}

public sealed record ProviderAsnCatalogSignatureEnvelope
{
    public const int CurrentSchemaVersion = 1;
    public const string AlgorithmEcdsaP256Sha256 = "ecdsa-p256-sha256";
    public const string SignatureEncodingP1363 = "p1363";

    [JsonPropertyName("schemaVersion")]
    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    [JsonPropertyName("algorithm")]
    public string Algorithm { get; init; } = AlgorithmEcdsaP256Sha256;

    [JsonPropertyName("signatureEncoding")]
    public string SignatureEncoding { get; init; } = SignatureEncodingP1363;

    [JsonPropertyName("keyId")]
    public string KeyId { get; init; } = string.Empty;

    [JsonPropertyName("catalogId")]
    public string CatalogId { get; init; } = string.Empty;

    [JsonPropertyName("catalogVersion")]
    public string CatalogVersion { get; init; } = string.Empty;

    [JsonPropertyName("catalogSha256")]
    public string CatalogSha256 { get; init; } = string.Empty;

    [JsonPropertyName("signedAt")]
    public DateTimeOffset SignedAt { get; init; }

    [JsonPropertyName("signature")]
    public string SignatureBase64 { get; init; } = string.Empty;
}

public sealed record ProviderAsnCatalogSignatureValidation
{
    public ProviderAsnCatalogSignaturePolicy Policy { get; init; }
    public bool Attempted { get; init; }
    public bool Valid { get; init; }
    public bool PolicySatisfied { get; init; }
    public string Status { get; init; } = string.Empty;
    public string KeyId { get; init; } = string.Empty;
    public string CatalogSha256 { get; init; } = string.Empty;
    public DateTimeOffset? SignedAt { get; init; }
    public string FinalUri { get; init; } = string.Empty;
}

public sealed record ProviderAsnCatalogRemoteFetchPreview
{
    public required string RegistryId { get; init; }
    public required ProviderAsnCatalogRemoteSourceView Source { get; init; }
    public DateTimeOffset CheckedAt { get; init; }
    public bool ServerNotModified { get; init; }
    public bool LocalAlreadyMatchesRemote { get; init; }
    public string ETag { get; init; } = string.Empty;
    public DateTimeOffset? LastModified { get; init; }
    public string RemoteContentSha256 { get; init; } = string.Empty;
    public string CatalogFinalUri { get; init; } = string.Empty;
    public ProviderAsnCatalogSignatureValidation? SignatureValidation { get; init; }
    public ProviderAsnCatalogUpdatePlan? UpdatePlan { get; init; }
    public long SourceConfigurationUpdatedAtUnixMs { get; init; }
    public string SourceConfigurationFingerprint { get; init; } = string.Empty;

    public bool HasUpdate => UpdatePlan is not null;
}

public sealed record ProviderAsnCatalogRemoteTransportRequest
{
    public required Uri Uri { get; init; }
    public bool Conditional { get; init; } = true;
    public string ETag { get; init; } = string.Empty;
    public DateTimeOffset? LastModified { get; init; }
    public int MaximumBytes { get; init; } = ProviderAsnEndpointCatalogDocument.MaximumDocumentBytes;
    public IReadOnlyList<string> TlsSpkiPinsSha256 { get; init; } = [];
}

public sealed record ProviderAsnCatalogRemoteTransportResponse
{
    public int StatusCode { get; init; }
    public required Uri FinalUri { get; init; }
    public byte[] Bytes { get; init; } = [];
    public string ETag { get; init; } = string.Empty;
    public DateTimeOffset? LastModified { get; init; }
}


public sealed record ProviderAsnCatalogRemoteApplyProvenanceView
{
    public required string RevisionId { get; init; }
    public required string RegistryId { get; init; }
    public string SourceUri { get; init; } = string.Empty;
    public string SourceFinalUri { get; init; } = string.Empty;
    public string SignatureUri { get; init; } = string.Empty;
    public string SignatureFinalUri { get; init; } = string.Empty;
    public ProviderAsnCatalogSignaturePolicy SignaturePolicy { get; init; }
    public string TrustedKeyId { get; init; } = string.Empty;
    public IReadOnlyList<string> TlsSpkiPinsSha256 { get; init; } = [];
    public bool ServerNotModified { get; init; }
    public string ETag { get; init; } = string.Empty;
    public DateTimeOffset? LastModified { get; init; }
    public string RemoteContentSha256 { get; init; } = string.Empty;
    public ProviderAsnCatalogSignatureValidation? SignatureValidation { get; init; }
    public DateTimeOffset CheckedAt { get; init; }
    public DateTimeOffset AppliedAt { get; init; }
}
