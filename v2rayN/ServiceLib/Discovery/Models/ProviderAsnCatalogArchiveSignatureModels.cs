namespace ServiceLib.Discovery.Models;

public sealed record ProviderAsnCatalogArchiveSignatureEnvelope
{
    public const int CurrentSchemaVersion = 1;
    public const string AlgorithmEcdsaP256Sha256 = "ecdsa-p256-sha256";
    public const string SignatureEncodingP1363 = "p1363";

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;
    public string Algorithm { get; init; } = AlgorithmEcdsaP256Sha256;
    public string SignatureEncoding { get; init; } = SignatureEncodingP1363;
    public string KeyId { get; init; } = string.Empty;
    public string PayloadSha256 { get; init; } = string.Empty;
    public DateTimeOffset SignedAt { get; init; }
    public string SignatureBase64 { get; init; } = string.Empty;
}

public sealed record ProviderAsnCatalogArchiveSignatureValidation
{
    public bool Present { get; init; }
    public bool Attempted { get; init; }
    public bool Valid { get; init; }
    public bool PolicySatisfied { get; init; }
    public string Status { get; init; } = string.Empty;
    public string KeyId { get; init; } = string.Empty;
    public string PayloadSha256 { get; init; } = string.Empty;
    public DateTimeOffset? SignedAt { get; init; }
}

public sealed record ProviderAsnCatalogArchiveSignatureTrust
{
    public bool Required { get; init; }
    public string TrustedKeyId { get; init; } = string.Empty;
    public string TrustedPublicKeySpkiBase64 { get; init; } = string.Empty;
}
