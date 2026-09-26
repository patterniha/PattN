using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;

namespace ServiceLib.Tests.Reviver;

public class ProviderAsnCatalogSignatureVerifierTests
{
    [Test]
    public async Task Verify_ShouldAcceptLocallyTrustedDetachedSignature()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var catalog = JsonProviderAsnEndpointCatalog.FromBytes(CatalogBytes("1"));
        var source = new ProviderAsnCatalogRemoteSourceConfig
        {
            Uri = "https://catalog.example/catalog.json",
            SignatureUri = "https://catalog.example/catalog.json.sig",
            SignaturePolicy = ProviderAsnCatalogSignaturePolicy.Required,
            TrustedKeyId = "release-key-1",
            TrustedPublicKeySpkiBase64 = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo()),
        };
        var envelope = Envelope(catalog, source.TrustedKeyId, DateTimeOffset.Parse("2026-09-24T09:00:00Z"));
        var signature = signer.SignData(
            ProviderAsnCatalogSignatureVerifier.BuildSignedPayload(envelope),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        envelope = envelope with { SignatureBase64 = Convert.ToBase64String(signature) };

        var result = ProviderAsnCatalogSignatureVerifier.Verify(catalog, envelope, source);

        await result.Attempted.Should().BeTrue();
        await result.Valid.Should().BeTrue();
        await result.PolicySatisfied.Should().BeTrue();
        await result.Status.Should().BeEqualTo("valid");
        await result.KeyId.Should().BeEqualTo("release-key-1");
        await result.CatalogSha256.Should().BeEqualTo(catalog.Sha256);
    }

    [Test]
    public async Task Verify_ShouldRejectTamperedIdentityHashAndSignature()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var catalog = JsonProviderAsnEndpointCatalog.FromBytes(CatalogBytes("1"));
        var source = new ProviderAsnCatalogRemoteSourceConfig
        {
            Uri = "https://catalog.example/catalog.json",
            SignatureUri = "https://catalog.example/catalog.json.sig",
            SignaturePolicy = ProviderAsnCatalogSignaturePolicy.Required,
            TrustedKeyId = "release-key-1",
            TrustedPublicKeySpkiBase64 = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo()),
        };
        var envelope = Envelope(catalog, source.TrustedKeyId, DateTimeOffset.Parse("2026-09-24T09:00:00Z"));
        var signature = signer.SignData(
            ProviderAsnCatalogSignatureVerifier.BuildSignedPayload(envelope),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        var wrongKey = ProviderAsnCatalogSignatureVerifier.Verify(
            catalog,
            envelope with { KeyId = "other", SignatureBase64 = Convert.ToBase64String(signature) },
            source);
        await wrongKey.Valid.Should().BeFalse();
        await wrongKey.Status.Should().BeEqualTo("signature-key-id-mismatch");

        var wrongHash = ProviderAsnCatalogSignatureVerifier.Verify(
            catalog,
            envelope with
            {
                CatalogSha256 = new string('0', 64),
                SignatureBase64 = Convert.ToBase64String(signature),
            },
            source);
        await wrongHash.Valid.Should().BeFalse();
        await wrongHash.Status.Should().BeEqualTo("signature-catalog-hash-mismatch");

        signature[0] ^= 0x40;
        var tamperedSignature = ProviderAsnCatalogSignatureVerifier.Verify(
            catalog,
            envelope with { SignatureBase64 = Convert.ToBase64String(signature) },
            source);
        await tamperedSignature.Valid.Should().BeFalse();
        await tamperedSignature.Status.Should().BeEqualTo("signature-invalid");
    }

    [Test]
    public async Task ValidateTrustedKey_ShouldAllowUnsignedOptionalButRejectPartialTrustConfig()
    {
        ProviderAsnCatalogSignatureVerifier.ValidateTrustedKey(
            new ProviderAsnCatalogRemoteSourceConfig
            {
                Uri = "https://catalog.example/catalog.json",
                SignaturePolicy = ProviderAsnCatalogSignaturePolicy.Optional,
            });

        var threw = false;
        try
        {
            ProviderAsnCatalogSignatureVerifier.ValidateTrustedKey(
                new ProviderAsnCatalogRemoteSourceConfig
                {
                    Uri = "https://catalog.example/catalog.json",
                    SignatureUri = "https://catalog.example/catalog.json.sig",
                    SignaturePolicy = ProviderAsnCatalogSignaturePolicy.Optional,
                });
        }
        catch (InvalidOperationException)
        {
            threw = true;
        }

        await threw.Should().BeTrue();
    }

    [Test]
    public async Task ValidateTrustedKey_ShouldRejectNonP256EcdsaKey()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var threw = false;
        try
        {
            ProviderAsnCatalogSignatureVerifier.ValidateTrustedKey(
                new ProviderAsnCatalogRemoteSourceConfig
                {
                    Uri = "https://catalog.example/catalog.json",
                    SignatureUri = "https://catalog.example/catalog.json.sig",
                    SignaturePolicy = ProviderAsnCatalogSignaturePolicy.Required,
                    TrustedKeyId = "wrong-curve",
                    TrustedPublicKeySpkiBase64 = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo()),
                });
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.Message.Contains("P-256", StringComparison.Ordinal);
        }

        await threw.Should().BeTrue();
    }

    private static ProviderAsnCatalogSignatureEnvelope Envelope(
        JsonProviderAsnEndpointCatalog catalog,
        string keyId,
        DateTimeOffset signedAt)
        => new()
        {
            KeyId = keyId,
            CatalogId = catalog.Document.Id,
            CatalogVersion = catalog.Document.Version,
            CatalogSha256 = catalog.Sha256,
            SignedAt = signedAt,
        };

    private static byte[] CatalogBytes(string version)
        => Encoding.UTF8.GetBytes(
            $$"""
            {
              "schemaVersion":1,
              "id":"catalog-a",
              "version":"{{version}}",
              "source":"test-suite",
              "updatedAt":"2026-09-24T00:00:00Z",
              "entries":[
                {
                  "address":"203.0.113.7",
                  "provider":"Example CDN",
                  "asn":"AS64500",
                  "pop":"test"
                }
              ]
            }
            """);
}
