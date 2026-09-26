using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;
using ServiceLib.Models.Entities;

namespace ServiceLib.Tests.Reviver;

public class ProviderAsnCatalogArchiveServiceTests
{
    [Test]
    public async Task Prepare_ShouldExportRetiredFileAndRevisionMetadata()
    {
        var temp = Path.Combine(Path.GetTempPath(), "pattn-archive-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try
        {
            var path = Path.Combine(temp, "catalog.json");
            var bytes = System.Text.Encoding.UTF8.GetBytes("{\"id\":\"catalog-a\"}");
            await File.WriteAllBytesAsync(path, bytes);
            var sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            var now = DateTimeOffset.UtcNow;

            var store = new FakeStore(
                new ProviderAsnCatalogRegistryItem
                {
                    Id = "registry-1",
                    FilePath = path,
                    DisplayName = "Catalog A",
                    CatalogId = "catalog-a",
                    CatalogVersion = "1",
                    CatalogSource = "test",
                    Sha256 = sha,
                    RegisteredAtUnixMs = now.AddDays(-3).ToUnixTimeMilliseconds(),
                    UpdatedAtUnixMs = now.AddDays(-1).ToUnixTimeMilliseconds(),
                    UnregisteredAtUnixMs = now.AddHours(-1).ToUnixTimeMilliseconds(),
                },
                [
                    new ProviderAsnCatalogRevisionItem
                    {
                        Id = "revision-1",
                        RegistryId = "registry-1",
                        PlanId = "plan-1",
                        DestinationPath = path,
                        BeforeSha256 = "before",
                        AfterSha256 = sha,
                        BeforeCatalogVersion = "0",
                        AfterCatalogVersion = "1",
                        AppliedAtUnixMs = now.AddDays(-2).ToUnixTimeMilliseconds(),
                    }
                ]);

            var service = new ProviderAsnCatalogArchiveService(
                new ProviderAsnCatalogRegistryService(store));

            var bundle = await service.PrepareAsync("registry-1");

            await bundle.Registry.Registered.Should().BeFalse();
            await bundle.Registry.CatalogId.Should().BeEqualTo("catalog-a");
            await bundle.CatalogFileSha256.Should().BeEqualTo(sha);
            await Convert.FromBase64String(bundle.CatalogFileBase64).Should().BeEquivalentTo(bytes);
            await bundle.Revisions.Count.Should().BeEqualTo(1);
            await bundle.Revisions[0].Id.Should().BeEqualTo("revision-1");

            var exportPath = Path.Combine(temp, "archive.json");
            await service.SaveAsync(bundle, exportPath);
            await File.Exists(exportPath).Should().BeTrue();
            var exported = JsonUtils.Deserialize<ProviderAsnCatalogArchiveBundle>(
                await File.ReadAllTextAsync(exportPath));
            await exported.Should().NotBeNull();
            await exported!.Registry.Id.Should().BeEqualTo("registry-1");
            await exported.Revisions.Count.Should().BeEqualTo(1);
        }
        finally
        {
            Directory.Delete(temp, recursive: true);
        }
    }

    [Test]
    public async Task Prepare_ShouldIncludeOnlyRemoteProvenanceForIncludedRevisions()
    {
        var temp = Path.Combine(Path.GetTempPath(), "pattn-archive-provenance-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try
        {
            var path = Path.Combine(temp, "catalog.json");
            var bytes = System.Text.Encoding.UTF8.GetBytes("{\"id\":\"catalog-a\"}");
            await File.WriteAllBytesAsync(path, bytes);
            var sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            var now = DateTimeOffset.UtcNow;

            var store = new FakeStore(
                new ProviderAsnCatalogRegistryItem
                {
                    Id = "registry-1",
                    FilePath = path,
                    DisplayName = "Catalog A",
                    CatalogId = "catalog-a",
                    CatalogVersion = "2",
                    Sha256 = sha,
                    RegisteredAtUnixMs = now.AddDays(-5).ToUnixTimeMilliseconds(),
                    UpdatedAtUnixMs = now.AddDays(-1).ToUnixTimeMilliseconds(),
                    UnregisteredAtUnixMs = now.AddHours(-1).ToUnixTimeMilliseconds(),
                },
                [
                    new ProviderAsnCatalogRevisionItem
                    {
                        Id = "revision-1",
                        RegistryId = "registry-1",
                        DestinationPath = path,
                        AfterSha256 = sha,
                        AfterCatalogVersion = "1",
                        AppliedAtUnixMs = now.AddDays(-3).ToUnixTimeMilliseconds(),
                    },
                    new ProviderAsnCatalogRevisionItem
                    {
                        Id = "revision-2",
                        RegistryId = "registry-1",
                        DestinationPath = path,
                        AfterSha256 = sha,
                        AfterCatalogVersion = "2",
                        AppliedAtUnixMs = now.AddDays(-2).ToUnixTimeMilliseconds(),
                    }
                ]);
            var provenance = new FakeProvenanceStore(
            [
                Provenance("revision-1", "registry-1", now.AddDays(-3)),
                Provenance("revision-2", "registry-1", now.AddDays(-2)),
                Provenance("not-in-archive", "registry-1", now.AddDays(-1)),
            ]);
            var service = new ProviderAsnCatalogArchiveService(
                new ProviderAsnCatalogRegistryService(store),
                provenance);

            var bundle = await service.PrepareAsync(
                "registry-1",
                new ProviderAsnCatalogArchiveOptions { MaxRevisions = 2 });

            await bundle.FormatVersion.Should().BeEqualTo(3);
            await bundle.RemoteProvenance.Count.Should().BeEqualTo(2);
            await bundle.RemoteProvenance.Select(x => x.RevisionId)
                .SequenceEqual(["revision-1", "revision-2"]).Should().BeTrue();
            await bundle.RemoteProvenance[1].SourceUri.Should().BeEqualTo("https://catalog.example/catalog.json");

            var exportPath = Path.Combine(temp, "archive.json");
            await service.SaveAsync(bundle, exportPath);
            var exported = JsonUtils.Deserialize<ProviderAsnCatalogArchiveBundle>(
                await File.ReadAllTextAsync(exportPath));
            await exported.Should().NotBeNull();
            await exported!.FormatVersion.Should().BeEqualTo(3);
            await exported.RemoteProvenance.Count.Should().BeEqualTo(2);
        }
        finally
        {
            Directory.Delete(temp, recursive: true);
        }
    }

    [Test]
    public async Task Prepare_ShouldRejectRetiredFileDriftUnlessExplicitlyAllowed()
    {
        var temp = Path.Combine(Path.GetTempPath(), "pattn-archive-drift-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try
        {
            var path = Path.Combine(temp, "catalog.json");
            var original = System.Text.Encoding.UTF8.GetBytes("original");
            await File.WriteAllBytesAsync(path, original);
            var originalSha = Convert.ToHexString(SHA256.HashData(original)).ToLowerInvariant();
            var now = DateTimeOffset.UtcNow;
            var store = new FakeStore(
                new ProviderAsnCatalogRegistryItem
                {
                    Id = "registry-1",
                    FilePath = path,
                    DisplayName = "Catalog A",
                    CatalogId = "catalog-a",
                    CatalogVersion = "1",
                    Sha256 = originalSha,
                    RegisteredAtUnixMs = now.AddDays(-2).ToUnixTimeMilliseconds(),
                    UpdatedAtUnixMs = now.AddDays(-1).ToUnixTimeMilliseconds(),
                    UnregisteredAtUnixMs = now.AddHours(-1).ToUnixTimeMilliseconds(),
                },
                []);
            var service = new ProviderAsnCatalogArchiveService(
                new ProviderAsnCatalogRegistryService(store));

            await File.WriteAllTextAsync(path, "changed");

            var rejected = false;
            try
            {
                await service.PrepareAsync("registry-1");
            }
            catch (InvalidOperationException)
            {
                rejected = true;
            }
            await rejected.Should().BeTrue();

            var allowed = await service.PrepareAsync(
                "registry-1",
                new ProviderAsnCatalogArchiveOptions { AllowFileDrift = true });
            await allowed.CatalogFileSha256.Should().NotBeEqualTo(originalSha);
        }
        finally
        {
            Directory.Delete(temp, recursive: true);
        }
    }

    [Test]
    public async Task PrepareSigned_ShouldReturnVerifiableV3ArchiveWithoutEmbeddingPrivateKey()
    {
        var temp = Path.Combine(Path.GetTempPath(), "pattn-archive-signed-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try
        {
            using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var path = Path.Combine(temp, "catalog.json");
            var bytes = Encoding.UTF8.GetBytes("{\"id\":\"catalog-a\"}");
            await File.WriteAllBytesAsync(path, bytes);
            var sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            var now = DateTimeOffset.UtcNow;
            var store = new FakeStore(
                new ProviderAsnCatalogRegistryItem
                {
                    Id = "registry-1",
                    FilePath = path,
                    DisplayName = "Catalog A",
                    CatalogId = "catalog-a",
                    CatalogVersion = "1",
                    CatalogSource = "test",
                    Sha256 = sha,
                    RegisteredAtUnixMs = now.AddDays(-2).ToUnixTimeMilliseconds(),
                    UpdatedAtUnixMs = now.AddDays(-1).ToUnixTimeMilliseconds(),
                    UnregisteredAtUnixMs = now.AddHours(-1).ToUnixTimeMilliseconds(),
                },
                []);
            var service = new ProviderAsnCatalogArchiveService(
                new ProviderAsnCatalogRegistryService(store));

            var bundle = await service.PrepareSignedAsync(
                "registry-1",
                "archive-key-1",
                signer,
                signedAt: now);

            await bundle.FormatVersion.Should().BeEqualTo(3);
            await bundle.ArchiveSignature.Should().NotBeNull();
            var validation = ProviderAsnCatalogArchiveSignatureService.Verify(
                bundle,
                new ProviderAsnCatalogArchiveSignatureTrust
                {
                    Required = true,
                    TrustedKeyId = "archive-key-1",
                    TrustedPublicKeySpkiBase64 = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo()),
                });
            await validation.Valid.Should().BeTrue();

            var json = JsonUtils.Serialize(bundle, false);
            var privateKeyBase64 = Convert.ToBase64String(signer.ExportECPrivateKey());
            await json.Contains(privateKeyBase64, StringComparison.Ordinal).Should().BeFalse();
        }
        finally
        {
            Directory.Delete(temp, recursive: true);
        }
    }

    private static ProviderAsnCatalogRemoteApplyProvenanceItem Provenance(
        string revisionId,
        string registryId,
        DateTimeOffset appliedAt)
        => new()
        {
            RevisionId = revisionId,
            RegistryId = registryId,
            SourceUri = "https://catalog.example/catalog.json",
            SignaturePolicy = (int)ProviderAsnCatalogSignaturePolicy.None,
            RemoteContentSha256 = new string('a', 64),
            SignaturePolicySatisfied = true,
            SignatureStatus = "not-required",
            CheckedAtUnixMs = appliedAt.AddMinutes(-1).ToUnixTimeMilliseconds(),
            AppliedAtUnixMs = appliedAt.ToUnixTimeMilliseconds(),
        };

    private sealed class FakeProvenanceStore(
        IReadOnlyList<ProviderAsnCatalogRemoteApplyProvenanceItem> values)
        : IProviderAsnCatalogRemoteApplyProvenanceStore
    {
        public Task<ProviderAsnCatalogRemoteApplyProvenanceItem?> GetAsync(
            string revisionId,
            CancellationToken cancellationToken = default)
            => Task.FromResult<ProviderAsnCatalogRemoteApplyProvenanceItem?>(
                values.FirstOrDefault(x => x.RevisionId == revisionId));

        public Task<IReadOnlyList<ProviderAsnCatalogRemoteApplyProvenanceItem>> ListByRegistryAsync(
            string registryId,
            int maxItems = 200,
            CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<ProviderAsnCatalogRemoteApplyProvenanceItem>>(
                values.Where(x => x.RegistryId == registryId).Take(maxItems).ToArray());

        public Task UpsertAsync(
            ProviderAsnCatalogRemoteApplyProvenanceItem item,
            CancellationToken cancellationToken = default)
            => Task.CompletedTask;
    }

    private sealed class FakeStore(
        ProviderAsnCatalogRegistryItem registry,
        IReadOnlyList<ProviderAsnCatalogRevisionItem> revisions) : IProviderAsnCatalogRegistryStore
    {
        public Task<IReadOnlyList<ProviderAsnCatalogRegistryItem>> ListAsync(
            ProviderAsnCatalogRegistryQuery? query = null,
            CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<ProviderAsnCatalogRegistryItem>>([registry]);

        public Task<ProviderAsnCatalogRegistryItem?> GetAsync(
            string id,
            CancellationToken cancellationToken = default)
            => Task.FromResult<ProviderAsnCatalogRegistryItem?>(
                string.Equals(id, registry.Id, StringComparison.Ordinal) ? registry : null);

        public Task<ProviderAsnCatalogRegistryItem?> FindByPathAsync(
            string normalizedPath,
            CancellationToken cancellationToken = default)
            => Task.FromResult<ProviderAsnCatalogRegistryItem?>(registry);

        public Task UpsertAsync(
            ProviderAsnCatalogRegistryItem item,
            CancellationToken cancellationToken = default)
            => Task.CompletedTask;

        public Task RemoveAsync(string id, CancellationToken cancellationToken = default)
            => Task.CompletedTask;

        public Task<int> RetireAsync(
            ProviderAsnCatalogRegistryItem item,
            bool discardRevisionHistory,
            CancellationToken cancellationToken = default)
            => Task.FromResult(revisions.Count);

        public Task<IReadOnlyList<ProviderAsnCatalogRevisionItem>> ListRevisionsAsync(
            ProviderAsnCatalogRevisionQuery? query = null,
            CancellationToken cancellationToken = default)
            => Task.FromResult(revisions);

        public Task<ProviderAsnCatalogRevisionItem?> GetRevisionAsync(
            string id,
            CancellationToken cancellationToken = default)
            => Task.FromResult<ProviderAsnCatalogRevisionItem?>(
                revisions.FirstOrDefault(x => x.Id == id));

        public Task InsertRevisionAsync(
            ProviderAsnCatalogRevisionItem item,
            CancellationToken cancellationToken = default)
            => Task.CompletedTask;

        public Task UpdateRevisionAsync(
            ProviderAsnCatalogRevisionItem item,
            CancellationToken cancellationToken = default)
            => Task.CompletedTask;
    }
}
