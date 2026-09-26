using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;

namespace ServiceLib.Tests.Reviver;

public class ProviderAsnCatalogArchiveSignatureServiceTests
{
    [Test]
    public async Task SignAndVerify_ShouldAuthenticateArchivePayloadAndMetadata()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var bundle = Bundle();
        var signed = ProviderAsnCatalogArchiveSignatureService.Sign(
            bundle,
            "archive-key-1",
            signer,
            DateTimeOffset.Parse("2026-09-24T11:00:00Z"));

        var result = ProviderAsnCatalogArchiveSignatureService.Verify(
            signed,
            new ProviderAsnCatalogArchiveSignatureTrust
            {
                Required = true,
                TrustedKeyId = "archive-key-1",
                TrustedPublicKeySpkiBase64 = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo()),
            });

        await signed.FormatVersion.Should().BeEqualTo(3);
        await signed.ArchiveSignature.Should().NotBeNull();
        await result.Present.Should().BeTrue();
        await result.Attempted.Should().BeTrue();
        await result.Valid.Should().BeTrue();
        await result.PolicySatisfied.Should().BeTrue();
        await result.Status.Should().BeEqualTo("valid");
    }

    [Test]
    public async Task Verify_ShouldRejectArchiveMetadataTamper()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signed = ProviderAsnCatalogArchiveSignatureService.Sign(
            Bundle(),
            "archive-key-1",
            signer,
            DateTimeOffset.Parse("2026-09-24T11:00:00Z"));
        var tampered = signed with
        {
            CatalogFileName = "other.json",
        };

        var result = ProviderAsnCatalogArchiveSignatureService.Verify(
            tampered,
            new ProviderAsnCatalogArchiveSignatureTrust
            {
                Required = true,
                TrustedKeyId = "archive-key-1",
                TrustedPublicKeySpkiBase64 = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo()),
            });

        await result.Valid.Should().BeFalse();
        await result.PolicySatisfied.Should().BeFalse();
        await result.Status.Should().BeEqualTo("archive-signature-payload-hash-mismatch");
    }

    [Test]
    public async Task Sign_ShouldRejectNonP256EcdsaKey()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var threw = false;
        try
        {
            ProviderAsnCatalogArchiveSignatureService.Sign(
                Bundle(),
                "archive-key-384",
                signer);
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.Message.Contains("P-256", StringComparison.Ordinal);
        }

        await threw.Should().BeTrue();
    }

    [Test]
    public async Task Verify_ShouldKeepUnsignedV2ArchiveOptionalButFailRequiredPolicy()
    {
        var legacy = Bundle() with
        {
            FormatVersion = 2,
            ArchiveSignature = null,
        };

        var optional = ProviderAsnCatalogArchiveSignatureService.Verify(legacy);
        var required = ProviderAsnCatalogArchiveSignatureService.Verify(
            legacy,
            new ProviderAsnCatalogArchiveSignatureTrust { Required = true });

        await optional.PolicySatisfied.Should().BeTrue();
        await optional.Status.Should().BeEqualTo("archive-signature-absent");
        await required.PolicySatisfied.Should().BeFalse();
        await required.Status.Should().BeEqualTo("archive-signature-required");
    }

    private static ProviderAsnCatalogArchiveBundle Bundle()
    {
        var now = DateTimeOffset.Parse("2026-09-24T10:00:00Z");
        var bytes = Encoding.UTF8.GetBytes("{\"id\":\"catalog-a\"}");
        var sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        return new ProviderAsnCatalogArchiveBundle
        {
            CreatedAt = now,
            Registry = new ProviderAsnCatalogRegistryView
            {
                Id = "registry-1",
                FilePath = "/retired/catalog.json",
                DisplayName = "Catalog A",
                Enabled = false,
                CatalogId = "catalog-a",
                CatalogVersion = "2",
                CatalogSource = "test",
                Sha256 = sha,
                RegisteredAt = now.AddDays(-10),
                UpdatedAt = now.AddDays(-1),
                UnregisteredAt = now.AddHours(-1),
            },
            CatalogFileName = "catalog.json",
            CatalogFileSha256 = sha,
            CatalogFileBase64 = Convert.ToBase64String(bytes),
            Revisions =
            [
                new ProviderAsnCatalogRevisionView
                {
                    Id = "revision-1",
                    RegistryId = "registry-1",
                    AppliedAt = now.AddDays(-2),
                }
            ],
            RemoteProvenance =
            [
                new ProviderAsnCatalogRemoteApplyProvenanceView
                {
                    RevisionId = "revision-1",
                    RegistryId = "registry-1",
                    SourceUri = "https://catalog.example/catalog.json",
                    TlsSpkiPinsSha256 = [new string('a', 64)],
                    CheckedAt = now.AddDays(-2),
                    AppliedAt = now.AddDays(-2),
                }
            ],
        };
    }
}
