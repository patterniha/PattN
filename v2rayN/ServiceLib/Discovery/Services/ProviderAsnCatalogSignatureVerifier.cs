using ServiceLib.Discovery.Models;

namespace ServiceLib.Discovery.Services;

public static class ProviderAsnCatalogSignatureVerifier
{
    private const string DomainSeparator = "PattN provider catalog signature v1";

    public static ProviderAsnCatalogSignatureValidation Verify(
        JsonProviderAsnEndpointCatalog catalog,
        ProviderAsnCatalogSignatureEnvelope envelope,
        ProviderAsnCatalogRemoteSourceConfig source)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(source);

        if (source.SignaturePolicy == ProviderAsnCatalogSignaturePolicy.None)
        {
            return new ProviderAsnCatalogSignatureValidation
            {
                Policy = source.SignaturePolicy,
                Attempted = false,
                Valid = false,
                PolicySatisfied = true,
                Status = "not-required",
                CatalogSha256 = catalog.Sha256,
            };
        }

        if (source.SignatureUri.IsNullOrEmpty()
            || source.TrustedKeyId.IsNullOrEmpty()
            || source.TrustedPublicKeySpkiBase64.IsNullOrEmpty())
        {
            var optional = source.SignaturePolicy == ProviderAsnCatalogSignaturePolicy.Optional;
            return new ProviderAsnCatalogSignatureValidation
            {
                Policy = source.SignaturePolicy,
                Attempted = false,
                Valid = false,
                PolicySatisfied = optional,
                Status = optional ? "not-configured" : "signature-configuration-required",
                CatalogSha256 = catalog.Sha256,
            };
        }

        var status = ValidateEnvelope(catalog, envelope, source);
        if (status is not null)
        {
            return Failure(source.SignaturePolicy, envelope, catalog.Sha256, status);
        }

        byte[] publicKey;
        byte[] signature;
        try
        {
            publicKey = Convert.FromBase64String(source.TrustedPublicKeySpkiBase64);
            signature = Convert.FromBase64String(envelope.SignatureBase64);
        }
        catch (FormatException)
        {
            return Failure(source.SignaturePolicy, envelope, catalog.Sha256, "signature-encoding-invalid");
        }

        if (signature.Length != 64)
        {
            return Failure(source.SignaturePolicy, envelope, catalog.Sha256, "signature-length-invalid");
        }

        bool valid;
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(publicKey, out var read);
            if (read != publicKey.Length || !IsNistP256(ecdsa))
            {
                return Failure(source.SignaturePolicy, envelope, catalog.Sha256, "trusted-key-invalid");
            }

            valid = ecdsa.VerifyData(
                BuildSignedPayload(envelope),
                signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException)
        {
            return Failure(source.SignaturePolicy, envelope, catalog.Sha256, "trusted-key-invalid");
        }

        return new ProviderAsnCatalogSignatureValidation
        {
            Policy = source.SignaturePolicy,
            Attempted = true,
            Valid = valid,
            PolicySatisfied = valid,
            Status = valid ? "valid" : "signature-invalid",
            KeyId = envelope.KeyId,
            CatalogSha256 = envelope.CatalogSha256,
            SignedAt = envelope.SignedAt,
        };
    }

    public static byte[] BuildSignedPayload(ProviderAsnCatalogSignatureEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        var text =
            DomainSeparator + "\n" +
            "catalogId=" + envelope.CatalogId.Trim() + "\n" +
            "catalogVersion=" + envelope.CatalogVersion.Trim() + "\n" +
            "catalogSha256=" + envelope.CatalogSha256.Trim().ToLowerInvariant() + "\n" +
            "signedAt=" + envelope.SignedAt.ToUniversalTime().ToString("O") + "\n";
        return Encoding.UTF8.GetBytes(text);
    }

    public static void ValidateTrustedKey(ProviderAsnCatalogRemoteSourceConfig source)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (source.SignaturePolicy == ProviderAsnCatalogSignaturePolicy.None)
        {
            return;
        }

        var configured = !source.SignatureUri.IsNullOrEmpty()
                         || !source.TrustedKeyId.IsNullOrEmpty()
                         || !source.TrustedPublicKeySpkiBase64.IsNullOrEmpty();

        if (!configured && source.SignaturePolicy == ProviderAsnCatalogSignaturePolicy.Optional)
        {
            return;
        }
        if (source.SignatureUri.IsNullOrEmpty()
            || source.TrustedKeyId.IsNullOrEmpty()
            || source.TrustedPublicKeySpkiBase64.IsNullOrEmpty())
        {
            throw new InvalidOperationException(
                "Signed provider catalog verification requires signature URI, trusted key ID, and trusted public key.");
        }

        byte[] key;
        try
        {
            key = Convert.FromBase64String(source.TrustedPublicKeySpkiBase64);
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(key, out var read);
            if (read != key.Length || !IsNistP256(ecdsa))
            {
                throw new InvalidOperationException("Trusted provider catalog key must be an ECDSA P-256 SubjectPublicKeyInfo key.");
            }
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException("Trusted provider catalog public key is not valid Base64.", ex);
        }
        catch (CryptographicException ex)
        {
            throw new InvalidOperationException("Trusted provider catalog public key is invalid.", ex);
        }
    }

    private static string? ValidateEnvelope(
        JsonProviderAsnEndpointCatalog catalog,
        ProviderAsnCatalogSignatureEnvelope envelope,
        ProviderAsnCatalogRemoteSourceConfig source)
    {
        if (envelope.SchemaVersion != ProviderAsnCatalogSignatureEnvelope.CurrentSchemaVersion)
        {
            return "signature-schema-unsupported";
        }
        if (!string.Equals(
                envelope.Algorithm,
                ProviderAsnCatalogSignatureEnvelope.AlgorithmEcdsaP256Sha256,
                StringComparison.OrdinalIgnoreCase))
        {
            return "signature-algorithm-unsupported";
        }
        if (!string.Equals(
                envelope.SignatureEncoding,
                ProviderAsnCatalogSignatureEnvelope.SignatureEncodingP1363,
                StringComparison.OrdinalIgnoreCase))
        {
            return "signature-encoding-unsupported";
        }
        if (!string.Equals(envelope.KeyId, source.TrustedKeyId, StringComparison.Ordinal))
        {
            return "signature-key-id-mismatch";
        }
        if (!string.Equals(envelope.CatalogId, catalog.Document.Id, StringComparison.Ordinal)
            || !string.Equals(envelope.CatalogVersion, catalog.Document.Version, StringComparison.Ordinal))
        {
            return "signature-catalog-identity-mismatch";
        }
        if (!string.Equals(envelope.CatalogSha256, catalog.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            return "signature-catalog-hash-mismatch";
        }
        if (envelope.SignedAt == default)
        {
            return "signature-time-missing";
        }
        return null;
    }

    private static bool IsNistP256(ECDsa ecdsa)
    {
        var curve = ecdsa.ExportParameters(false).Curve;
        return string.Equals(
            curve.Oid.Value,
            ECCurve.NamedCurves.nistP256.Oid.Value,
            StringComparison.Ordinal);
    }

    private static ProviderAsnCatalogSignatureValidation Failure(
        ProviderAsnCatalogSignaturePolicy policy,
        ProviderAsnCatalogSignatureEnvelope envelope,
        string catalogSha256,
        string status)
        => new()
        {
            Policy = policy,
            Attempted = true,
            Valid = false,
            PolicySatisfied = false,
            Status = status,
            KeyId = envelope.KeyId,
            CatalogSha256 = catalogSha256,
            SignedAt = envelope.SignedAt == default ? null : envelope.SignedAt,
        };
}
