using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;

namespace ServiceLib.Tests.Reviver;

public class ProviderAsnCatalogArchiveSignatureInspectionTests
{
    [Test]
    public async Task Inspect_ShouldValidateRequiredArchiveSignature()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var temp = Path.Combine(Path.GetTempPath(), "pattn-signed-archive-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try
        {
            var path = Path.Combine(temp, "archive.json");
            var bundle = ProviderAsnCatalogArchiveSignatureService.Sign(
                Bundle(),
                "archive-key-1",
                signer,
                DateTimeOffset.Parse("2026-09-24T12:00:00Z"));
            await File.WriteAllTextAsync(path, JsonUtils.Serialize(bundle, true));

            var inspection = await new ProviderAsnCatalogArchiveInspectionService().InspectAsync(
                path,
                new ProviderAsnCatalogArchiveInspectionOptions
                {
                    ArchiveSignatureTrust = new ProviderAsnCatalogArchiveSignatureTrust
                    {
                        Required = true,
                        TrustedKeyId = "archive-key-1",
                        TrustedPublicKeySpkiBase64 = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo()),
                    },
                });

            await inspection.FormatVersion.Should().BeEqualTo(3);
            await inspection.ArchiveSignatureValidation.Should().NotBeNull();
            await inspection.ArchiveSignatureValidation!.Valid.Should().BeTrue();
            await inspection.ArchiveSignatureValidation.PolicySatisfied.Should().BeTrue();
        }
        finally
        {
            Directory.Delete(temp, recursive: true);
        }
    }

    [Test]
    public async Task Inspect_ShouldAcceptUnsignedV2ByDefaultButRejectWhenSignatureRequired()
    {
        var temp = Path.Combine(Path.GetTempPath(), "pattn-legacy-archive-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try
        {
            var path = Path.Combine(temp, "archive.json");
            var bundle = Bundle() with
            {
                FormatVersion = 2,
                ArchiveSignature = null,
            };
            await File.WriteAllTextAsync(path, JsonUtils.Serialize(bundle, true));

            var optional = await new ProviderAsnCatalogArchiveInspectionService().InspectAsync(path);
            await optional.ArchiveSignatureValidation.Should().NotBeNull();
            await optional.ArchiveSignatureValidation!.Status.Should().BeEqualTo("archive-signature-absent");

            using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var threw = false;
            try
            {
                await new ProviderAsnCatalogArchiveInspectionService().InspectAsync(
                    path,
                    new ProviderAsnCatalogArchiveInspectionOptions
                    {
                        ArchiveSignatureTrust = new ProviderAsnCatalogArchiveSignatureTrust
                        {
                            Required = true,
                            TrustedKeyId = "archive-key-1",
                            TrustedPublicKeySpkiBase64 = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo()),
                        },
                    });
            }
            catch (InvalidOperationException ex)
            {
                threw = ex.Message.Contains("archive-signature-required", StringComparison.OrdinalIgnoreCase);
            }

            await threw.Should().BeTrue();
        }
        finally
        {
            Directory.Delete(temp, recursive: true);
        }
    }

    private static ProviderAsnCatalogArchiveBundle Bundle()
    {
        var now = DateTimeOffset.Parse("2026-09-24T10:00:00Z");
        var bytes = Encoding.UTF8.GetBytes(
            $$"""
            {
              "schemaVersion":1,
              "id":"catalog-a",
              "version":"2",
              "source":"signed-archive-test",
              "updatedAt":"{{now.AddDays(-1):O}}",
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
        };
    }
}
