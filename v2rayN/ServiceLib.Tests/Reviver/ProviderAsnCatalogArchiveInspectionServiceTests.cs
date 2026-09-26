using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;

namespace ServiceLib.Tests.Reviver;

public class ProviderAsnCatalogArchiveInspectionServiceTests
{
    [Test]
    public async Task Inspect_ShouldVerifyEmbeddedCatalogWithoutRegisteringAnything()
    {
        var temp = Path.Combine(Path.GetTempPath(), "pattn-archive-inspect-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try
        {
            var now = DateTimeOffset.Parse("2026-09-24T10:00:00Z");
            var bytes = CatalogBytes("catalog-a", "2", now.AddDays(-1));
            var sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            var path = Path.Combine(temp, "archive.json");
            var bundle = new ProviderAsnCatalogArchiveBundle
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
                        AppliedAt = now.AddDays(-2),
                        CheckedAt = now.AddDays(-2),
                    }
                ],
            };
            await File.WriteAllTextAsync(path, JsonUtils.Serialize(bundle, true));

            var result = await new ProviderAsnCatalogArchiveInspectionService().InspectAsync(path, now: now);

            await result.RegistryId.Should().BeEqualTo("registry-1");
            await result.CatalogId.Should().BeEqualTo("catalog-a");
            await result.CatalogVersion.Should().BeEqualTo("2");
            await result.CatalogFileSha256.Should().BeEqualTo(sha);
            await result.RegistryShaMatchesPayload.Should().BeTrue();
            await result.CatalogEntries.Should().BeEqualTo(1);
            await result.Revisions.Should().BeEqualTo(1);
            await result.RemoteProvenanceRecords.Should().BeEqualTo(1);
            await result.CatalogAudit.Should().NotBeNull();
            await result.CatalogAudit!.Valid.Should().BeTrue();
        }
        finally
        {
            Directory.Delete(temp, recursive: true);
        }
    }

    [Test]
    public async Task Inspect_ShouldRejectTamperedEmbeddedBytes()
    {
        var temp = Path.Combine(Path.GetTempPath(), "pattn-archive-tamper-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try
        {
            var bytes = CatalogBytes("catalog-a", "1", DateTimeOffset.UtcNow);
            var path = Path.Combine(temp, "archive.json");
            var bundle = new ProviderAsnCatalogArchiveBundle
            {
                CreatedAt = DateTimeOffset.UtcNow,
                Registry = new ProviderAsnCatalogRegistryView
                {
                    Id = "registry-1",
                    FilePath = "/retired/catalog.json",
                    CatalogId = "catalog-a",
                    CatalogVersion = "1",
                    Sha256 = new string('0', 64),
                    RegisteredAt = DateTimeOffset.UtcNow.AddDays(-2),
                    UpdatedAt = DateTimeOffset.UtcNow.AddDays(-1),
                    UnregisteredAt = DateTimeOffset.UtcNow,
                },
                CatalogFileName = "catalog.json",
                CatalogFileSha256 = new string('f', 64),
                CatalogFileBase64 = Convert.ToBase64String(bytes),
            };
            await File.WriteAllTextAsync(path, JsonUtils.Serialize(bundle, true));

            var threw = false;
            try
            {
                await new ProviderAsnCatalogArchiveInspectionService().InspectAsync(path);
            }
            catch (InvalidOperationException ex)
            {
                threw = ex.Message.Contains("SHA-256", StringComparison.OrdinalIgnoreCase);
            }

            await threw.Should().BeTrue();
        }
        finally
        {
            Directory.Delete(temp, recursive: true);
        }
    }

    [Test]
    public async Task Inspect_ShouldRejectProvenanceForRevisionOutsideArchive()
    {
        var temp = Path.Combine(Path.GetTempPath(), "pattn-archive-provenance-inspect-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try
        {
            var now = DateTimeOffset.UtcNow;
            var bytes = CatalogBytes("catalog-a", "1", now);
            var sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            var path = Path.Combine(temp, "archive.json");
            var bundle = new ProviderAsnCatalogArchiveBundle
            {
                CreatedAt = now,
                Registry = new ProviderAsnCatalogRegistryView
                {
                    Id = "registry-1",
                    FilePath = "/retired/catalog.json",
                    CatalogId = "catalog-a",
                    CatalogVersion = "1",
                    Sha256 = sha,
                    RegisteredAt = now.AddDays(-1),
                    UpdatedAt = now,
                    UnregisteredAt = now,
                },
                CatalogFileName = "catalog.json",
                CatalogFileSha256 = sha,
                CatalogFileBase64 = Convert.ToBase64String(bytes),
                RemoteProvenance =
                [
                    new ProviderAsnCatalogRemoteApplyProvenanceView
                    {
                        RevisionId = "missing-revision",
                        RegistryId = "registry-1",
                        AppliedAt = now,
                        CheckedAt = now,
                    }
                ],
            };
            await File.WriteAllTextAsync(path, JsonUtils.Serialize(bundle, true));

            var threw = false;
            try
            {
                await new ProviderAsnCatalogArchiveInspectionService().InspectAsync(path);
            }
            catch (InvalidOperationException ex)
            {
                threw = ex.Message.Contains("revision not included", StringComparison.OrdinalIgnoreCase);
            }

            await threw.Should().BeTrue();
        }
        finally
        {
            Directory.Delete(temp, recursive: true);
        }
    }

    private static byte[] CatalogBytes(string id, string version, DateTimeOffset updatedAt)
        => Encoding.UTF8.GetBytes(
            $$"""
            {
              "schemaVersion":1,
              "id":"{{id}}",
              "version":"{{version}}",
              "source":"archive-inspection-test",
              "updatedAt":"{{updatedAt:O}}",
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
