using System.Security.Cryptography;
using ServiceLib.Discovery.Models;

namespace ServiceLib.Discovery.Services;

public static class ProviderAsnCatalogArchiveSignatureService
{
    private const string DomainSeparator = "PattN provider catalog archive signature v1";

    public static ProviderAsnCatalogArchiveBundle Sign(
        ProviderAsnCatalogArchiveBundle bundle,
        string keyId,
        ECDsa signer,
        DateTimeOffset? signedAt = null)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        ArgumentNullException.ThrowIfNull(signer);
        keyId = keyId?.Trim() ?? string.Empty;
        if (keyId.IsNullOrEmpty())
        {
            throw new ArgumentException("Archive signing key ID is required.", nameof(keyId));
        }
        if (bundle.FormatVersion < 3)
        {
            throw new InvalidOperationException("Archive signatures require archive format version 3 or newer.");
        }
        if (!IsNistP256(signer))
        {
            throw new InvalidOperationException("Archive signing requires an ECDSA P-256 private key.");
        }

        var envelope = new ProviderAsnCatalogArchiveSignatureEnvelope
        {
            KeyId = keyId,
            PayloadSha256 = ComputePayloadSha256(bundle),
            SignedAt = signedAt ?? DateTimeOffset.UtcNow,
        };
        var signature = signer.SignData(
            BuildSignaturePayload(envelope),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        return bundle with
        {
            ArchiveSignature = envelope with
            {
                SignatureBase64 = Convert.ToBase64String(signature),
            },
        };
    }

    public static ProviderAsnCatalogArchiveSignatureValidation Verify(
        ProviderAsnCatalogArchiveBundle bundle,
        ProviderAsnCatalogArchiveSignatureTrust? trust = null)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        trust ??= new ProviderAsnCatalogArchiveSignatureTrust();

        var envelope = bundle.ArchiveSignature;
        if (envelope is null)
        {
            return new ProviderAsnCatalogArchiveSignatureValidation
            {
                Present = false,
                Attempted = false,
                Valid = false,
                PolicySatisfied = !trust.Required,
                Status = trust.Required ? "archive-signature-required" : "archive-signature-absent",
            };
        }

        if (envelope.SchemaVersion != ProviderAsnCatalogArchiveSignatureEnvelope.CurrentSchemaVersion)
        {
            return Failure(envelope, trust.Required, "archive-signature-schema-unsupported");
        }
        if (!string.Equals(
                envelope.Algorithm,
                ProviderAsnCatalogArchiveSignatureEnvelope.AlgorithmEcdsaP256Sha256,
                StringComparison.OrdinalIgnoreCase))
        {
            return Failure(envelope, trust.Required, "archive-signature-algorithm-unsupported");
        }
        if (!string.Equals(
                envelope.SignatureEncoding,
                ProviderAsnCatalogArchiveSignatureEnvelope.SignatureEncodingP1363,
                StringComparison.OrdinalIgnoreCase))
        {
            return Failure(envelope, trust.Required, "archive-signature-encoding-unsupported");
        }
        if (envelope.KeyId.IsNullOrEmpty() || envelope.SignedAt == default)
        {
            return Failure(envelope, trust.Required, "archive-signature-metadata-invalid");
        }

        var payloadHash = ComputePayloadSha256(bundle);
        if (!string.Equals(envelope.PayloadSha256, payloadHash, StringComparison.OrdinalIgnoreCase))
        {
            return Failure(envelope, trust.Required, "archive-signature-payload-hash-mismatch");
        }

        var trustConfigured = !trust.TrustedKeyId.IsNullOrEmpty()
                              || !trust.TrustedPublicKeySpkiBase64.IsNullOrEmpty();
        if (!trustConfigured)
        {
            return new ProviderAsnCatalogArchiveSignatureValidation
            {
                Present = true,
                Attempted = false,
                Valid = false,
                PolicySatisfied = !trust.Required,
                Status = trust.Required ? "archive-signature-trust-required" : "archive-signature-unverified",
                KeyId = envelope.KeyId,
                PayloadSha256 = payloadHash,
                SignedAt = envelope.SignedAt,
            };
        }
        if (trust.TrustedKeyId.IsNullOrEmpty() || trust.TrustedPublicKeySpkiBase64.IsNullOrEmpty())
        {
            return Failure(envelope, trust.Required, "archive-signature-trust-incomplete");
        }
        if (!string.Equals(envelope.KeyId, trust.TrustedKeyId, StringComparison.Ordinal))
        {
            return Failure(envelope, trust.Required, "archive-signature-key-id-mismatch");
        }

        byte[] publicKey;
        byte[] signature;
        try
        {
            publicKey = Convert.FromBase64String(trust.TrustedPublicKeySpkiBase64);
            signature = Convert.FromBase64String(envelope.SignatureBase64);
        }
        catch (FormatException)
        {
            return Failure(envelope, trust.Required, "archive-signature-encoding-invalid");
        }
        if (signature.Length != 64)
        {
            return Failure(envelope, trust.Required, "archive-signature-length-invalid");
        }

        bool valid;
        try
        {
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(publicKey, out var read);
            if (read != publicKey.Length || !IsNistP256(verifier))
            {
                return Failure(envelope, trust.Required, "archive-signature-trusted-key-invalid");
            }
            valid = verifier.VerifyData(
                BuildSignaturePayload(envelope),
                signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException)
        {
            return Failure(envelope, trust.Required, "archive-signature-trusted-key-invalid");
        }

        return new ProviderAsnCatalogArchiveSignatureValidation
        {
            Present = true,
            Attempted = true,
            Valid = valid,
            PolicySatisfied = valid,
            Status = valid ? "valid" : "archive-signature-invalid",
            KeyId = envelope.KeyId,
            PayloadSha256 = payloadHash,
            SignedAt = envelope.SignedAt,
        };
    }

    public static string ComputePayloadSha256(ProviderAsnCatalogArchiveBundle bundle)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        var registryHash = HashJson(bundle.Registry);
        var revisionHash = HashJson(bundle.Revisions
            .OrderBy(x => x.Id, StringComparer.Ordinal)
            .ToArray());
        var provenanceHash = HashJson(bundle.RemoteProvenance
            .OrderBy(x => x.RevisionId, StringComparer.Ordinal)
            .ThenBy(x => x.AppliedAt)
            .ToArray());
        var notesHash = HashText(bundle.Notes ?? string.Empty);

        var payload =
            "formatVersion=" + bundle.FormatVersion + "\n" +
            "createdAt=" + bundle.CreatedAt.ToUniversalTime().ToString("O") + "\n" +
            "registrySha256=" + registryHash + "\n" +
            "catalogFileName=" + bundle.CatalogFileName.Trim() + "\n" +
            "catalogFileSha256=" + bundle.CatalogFileSha256.Trim().ToLowerInvariant() + "\n" +
            "revisionsSha256=" + revisionHash + "\n" +
            "remoteProvenanceSha256=" + provenanceHash + "\n" +
            "notesSha256=" + notesHash + "\n";
        return HashText(payload);
    }

    public static byte[] BuildSignaturePayload(ProviderAsnCatalogArchiveSignatureEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        var payload =
            DomainSeparator + "\n" +
            "keyId=" + envelope.KeyId.Trim() + "\n" +
            "payloadSha256=" + envelope.PayloadSha256.Trim().ToLowerInvariant() + "\n" +
            "signedAt=" + envelope.SignedAt.ToUniversalTime().ToString("O") + "\n";
        return Encoding.UTF8.GetBytes(payload);
    }

    private static bool IsNistP256(ECDsa ecdsa)
    {
        var curve = ecdsa.ExportParameters(false).Curve;
        return string.Equals(
            curve.Oid.Value,
            ECCurve.NamedCurves.nistP256.Oid.Value,
            StringComparison.Ordinal);
    }

    private static string HashJson<T>(T value)
        => HashText(JsonUtils.Serialize(value, false));

    private static string HashText(string value)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static ProviderAsnCatalogArchiveSignatureValidation Failure(
        ProviderAsnCatalogArchiveSignatureEnvelope envelope,
        bool required,
        string status)
        => new()
        {
            Present = true,
            Attempted = true,
            Valid = false,
            PolicySatisfied = false,
            Status = status,
            KeyId = envelope.KeyId,
            PayloadSha256 = envelope.PayloadSha256,
            SignedAt = envelope.SignedAt == default ? null : envelope.SignedAt,
        };
}
