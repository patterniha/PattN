using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;
using ServiceLib.Models.Entities;

namespace ServiceLib.Tests.Reviver;

public class ProviderAsnCatalogRemoteSourcePortabilityServiceTests
{
    [Test]
    public async Task Export_ShouldContainOnlyPortableSourceAndPublicTrustMaterial()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var registry = Registry();
        var tlsPin = new string('c', 64);
        var source = new ProviderAsnCatalogRemoteSourceItem
        {
            RegistryId = registry.Id,
            Uri = "https://catalog.example/catalog.json",
            SignatureUri = "https://catalog.example/catalog.json.sig",
            SignaturePolicy = (int)ProviderAsnCatalogSignaturePolicy.Required,
            TrustedKeyId = "release-key-1",
            TrustedPublicKeySpkiBase64 = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo()),
            TlsSpkiPinsSha256Json = ProviderAsnCatalogTransportPinning.SerializePins([tlsPin]),
            ETag = "\"cache-v2\"",
            RemoteContentSha256 = new string('a', 64),
            LastCheckedAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        };
        var store = new FakeSourceStore(source);
        var service = CreateService(registry, store);

        var bundle = await service.ExportAsync(
            registry.Id,
            DateTimeOffset.Parse("2026-09-24T10:00:00Z"));

        await bundle.FormatVersion.Should().BeEqualTo(1);
        await bundle.CatalogId.Should().BeEqualTo("catalog-a");
        await bundle.CatalogVersion.Should().BeEqualTo("2");
        await bundle.Source.Uri.Should().BeEqualTo(source.Uri);
        await bundle.Source.SignatureUri.Should().BeEqualTo(source.SignatureUri);
        await bundle.Source.TrustedKeyId.Should().BeEqualTo("release-key-1");
        await bundle.Source.TrustedPublicKeySpkiBase64.Should().BeEqualTo(source.TrustedPublicKeySpkiBase64);
        await bundle.Source.TlsSpkiPinsSha256.SequenceEqual([tlsPin]).Should().BeTrue();
        await bundle.TrustedPublicKeySha256.Length.Should().BeEqualTo(64);

        var json = JsonUtils.Serialize(bundle, false);
        await json.Contains("cache-v2").Should().BeFalse();
        await json.Contains(source.RemoteContentSha256).Should().BeFalse();
        await json.Contains("lastChecked", StringComparison.OrdinalIgnoreCase).Should().BeFalse();
    }


    [Test]
    public async Task Export_ShouldRejectInvalidStoredSignaturePolicy_InsteadOfDowngradingTrust()
    {
        var registry = Registry();
        var store = new FakeSourceStore(new ProviderAsnCatalogRemoteSourceItem
        {
            RegistryId = registry.Id,
            Uri = "https://catalog.example/catalog.json",
            SignaturePolicy = int.MaxValue,
        });
        var service = CreateService(registry, store);

        var threw = false;
        try
        {
            await service.ExportAsync(registry.Id);
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.Message.Contains("signature policy", StringComparison.OrdinalIgnoreCase);
        }

        await threw.Should().BeTrue();
    }

    [Test]
    public async Task SaveAndLoad_ShouldRoundTripPortableBundleWithoutRuntimeCacheState()
    {
        var registry = Registry();
        var store = new FakeSourceStore(new ProviderAsnCatalogRemoteSourceItem
        {
            RegistryId = registry.Id,
            Uri = "https://catalog.example/catalog.json",
            SignaturePolicy = (int)ProviderAsnCatalogSignaturePolicy.None,
            ETag = "\"runtime-cache\"",
            RemoteContentSha256 = new string('b', 64),
            LastCheckedAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        });
        var service = CreateService(registry, store);
        var temp = Path.Combine(Path.GetTempPath(), "pattn-remote-source-" + Guid.NewGuid().ToString("N") + ".json");

        try
        {
            var bundle = await service.ExportAsync(registry.Id);
            await service.SaveAsync(bundle, temp);
            var loaded = await service.LoadAsync(temp);

            await loaded.CatalogId.Should().BeEqualTo(registry.CatalogId);
            await loaded.Source.Uri.Should().BeEqualTo("https://catalog.example/catalog.json");

            var json = await File.ReadAllTextAsync(temp);
            await json.Contains("runtime-cache").Should().BeFalse();
            await json.Contains(store.Item!.RemoteContentSha256).Should().BeFalse();
        }
        finally
        {
            if (File.Exists(temp))
            {
                File.Delete(temp);
            }
        }
    }

    [Test]
    public async Task PrepareImport_ShouldRejectCatalogIdentityMismatch()
    {
        var registry = Registry();
        var store = new FakeSourceStore(null);
        var service = CreateService(registry, store);
        var bundle = new ProviderAsnCatalogRemoteSourcePortableBundle
        {
            CatalogId = "other-catalog",
            CatalogVersion = "1",
            Source = new ProviderAsnCatalogRemoteSourceConfig
            {
                Uri = "https://catalog.example/catalog.json",
            },
        };

        var threw = false;
        try
        {
            await service.PrepareImportAsync(registry.Id, bundle);
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.Message.Contains("catalog ID", StringComparison.OrdinalIgnoreCase);
        }

        await threw.Should().BeTrue();
        await (store.Item is null).Should().BeTrue();
    }

    [Test]
    public async Task PrepareImport_ShouldRejectPublicKeyFingerprintMismatch()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var registry = Registry();
        var store = new FakeSourceStore(null);
        var service = CreateService(registry, store);
        var bundle = new ProviderAsnCatalogRemoteSourcePortableBundle
        {
            CatalogId = registry.CatalogId,
            CatalogVersion = registry.CatalogVersion,
            Source = new ProviderAsnCatalogRemoteSourceConfig
            {
                Uri = "https://catalog.example/catalog.json",
                SignatureUri = "https://catalog.example/catalog.json.sig",
                SignaturePolicy = ProviderAsnCatalogSignaturePolicy.Required,
                TrustedKeyId = "release-key-1",
                TrustedPublicKeySpkiBase64 = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo()),
            },
            TrustedPublicKeySha256 = new string('f', 64),
        };

        var threw = false;
        try
        {
            await service.PrepareImportAsync(registry.Id, bundle);
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.Message.Contains("fingerprint", StringComparison.OrdinalIgnoreCase);
        }

        await threw.Should().BeTrue();
        await (store.Item is null).Should().BeTrue();
    }

    [Test]
    public async Task ApplyImport_ShouldRejectWhenCurrentConfigurationChangedAfterPreview()
    {
        var registry = Registry();
        var existing = new ProviderAsnCatalogRemoteSourceItem
        {
            RegistryId = registry.Id,
            Uri = "https://old.example/catalog.json",
            SignaturePolicy = (int)ProviderAsnCatalogSignaturePolicy.None,
            ConfigurationUpdatedAtUnixMs = DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeMilliseconds(),
        };
        var store = new FakeSourceStore(existing);
        var service = CreateService(registry, store);
        var bundle = new ProviderAsnCatalogRemoteSourcePortableBundle
        {
            CatalogId = registry.CatalogId,
            CatalogVersion = registry.CatalogVersion,
            Source = new ProviderAsnCatalogRemoteSourceConfig
            {
                Uri = "https://new.example/catalog.json",
            },
        };

        var preview = await service.PrepareImportAsync(registry.Id, bundle);

        await store.UpsertAsync(new ProviderAsnCatalogRemoteSourceItem
        {
            RegistryId = registry.Id,
            Uri = "https://user-changed.example/catalog.json",
            SignaturePolicy = (int)ProviderAsnCatalogSignaturePolicy.None,
            ConfigurationUpdatedAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        });

        var threw = false;
        try
        {
            await service.ApplyImportAsync(preview);
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.Message.Contains("changed after import preview", StringComparison.OrdinalIgnoreCase);
        }

        await threw.Should().BeTrue();
        await store.Item!.Uri.Should().BeEqualTo("https://user-changed.example/catalog.json");
    }

    [Test]
    public async Task ApplyImport_ShouldRejectWhenTlsPinsChangedAfterPreview()
    {
        var registry = Registry();
        var oldPin = new string('1', 64);
        var changedPin = new string('2', 64);
        var importedPin = new string('3', 64);
        var existing = new ProviderAsnCatalogRemoteSourceItem
        {
            RegistryId = registry.Id,
            Uri = "https://catalog.example/catalog.json",
            SignaturePolicy = (int)ProviderAsnCatalogSignaturePolicy.None,
            TlsSpkiPinsSha256Json = ProviderAsnCatalogTransportPinning.SerializePins([oldPin]),
            ConfigurationUpdatedAtUnixMs = DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeMilliseconds(),
        };
        var store = new FakeSourceStore(existing);
        var service = CreateService(registry, store);
        var bundle = new ProviderAsnCatalogRemoteSourcePortableBundle
        {
            CatalogId = registry.CatalogId,
            CatalogVersion = registry.CatalogVersion,
            Source = new ProviderAsnCatalogRemoteSourceConfig
            {
                Uri = "https://catalog.example/catalog.json",
                TlsSpkiPinsSha256 = [importedPin],
            },
        };

        var preview = await service.PrepareImportAsync(registry.Id, bundle);

        await store.UpsertAsync(new ProviderAsnCatalogRemoteSourceItem
        {
            RegistryId = registry.Id,
            Uri = existing.Uri,
            SignaturePolicy = existing.SignaturePolicy,
            TlsSpkiPinsSha256Json = ProviderAsnCatalogTransportPinning.SerializePins([changedPin]),
            ConfigurationUpdatedAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        });

        var threw = false;
        try
        {
            await service.ApplyImportAsync(preview);
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.Message.Contains("changed after import preview", StringComparison.OrdinalIgnoreCase);
        }

        await threw.Should().BeTrue();
        await ProviderAsnCatalogTransportPinning.DeserializePins(store.Item!.TlsSpkiPinsSha256Json)
            .SequenceEqual([changedPin]).Should().BeTrue();
    }

    [Test]
    public async Task ApplyImport_ShouldPersistConfigurationWithoutFetchingRemoteBytes()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var registry = Registry();
        var store = new FakeSourceStore(null);
        var service = CreateService(registry, store);
        var tlsPin = new string('d', 64);
        var bundle = new ProviderAsnCatalogRemoteSourcePortableBundle
        {
            CatalogId = registry.CatalogId,
            CatalogVersion = "1",
            DisplayName = "Portable catalog source",
            Source = new ProviderAsnCatalogRemoteSourceConfig
            {
                Uri = "https://catalog.example/catalog.json",
                SignatureUri = "https://catalog.example/catalog.json.sig",
                SignaturePolicy = ProviderAsnCatalogSignaturePolicy.Required,
                TrustedKeyId = "release-key-1",
                TrustedPublicKeySpkiBase64 = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo()),
                TlsSpkiPinsSha256 = [tlsPin],
            },
        };

        var preview = await service.PrepareImportAsync(
            registry.Id,
            bundle,
            DateTimeOffset.Parse("2026-09-24T10:00:00Z"));
        await preview.Warnings.Contains("bundle-catalog-version-differs-from-current").Should().BeTrue();

        var applied = await service.ApplyImportAsync(preview);

        await applied.RegistryId.Should().BeEqualTo(registry.Id);
        await applied.Uri.Should().BeEqualTo(bundle.Source.Uri);
        await applied.SignaturePolicy.Should().BeEqualTo(ProviderAsnCatalogSignaturePolicy.Required);
        await applied.TrustedKeyId.Should().BeEqualTo("release-key-1");
        await (store.Item is not null).Should().BeTrue();
        await store.Item!.ETag.Should().BeEqualTo(string.Empty);
        await store.Item.RemoteContentSha256.Should().BeEqualTo(string.Empty);
        await store.Item.LastCheckedAtUnixMs.Should().BeEqualTo(0);
        await ProviderAsnCatalogTransportPinning.DeserializePins(store.Item.TlsSpkiPinsSha256Json)
            .SequenceEqual([tlsPin]).Should().BeTrue();
    }

    private static ProviderAsnCatalogRemoteSourcePortabilityService CreateService(
        ProviderAsnCatalogRegistryItem registry,
        FakeSourceStore sources)
    {
        var catalogs = new ProviderAsnCatalogRegistryService(new FakeRegistryStore(registry));
        var remote = new ProviderAsnCatalogRemoteUpdateService(catalogs, sources);
        return new ProviderAsnCatalogRemoteSourcePortabilityService(catalogs, sources, remote);
    }

    private static ProviderAsnCatalogRegistryItem Registry()
    {
        var now = DateTimeOffset.UtcNow;
        return new ProviderAsnCatalogRegistryItem
        {
            Id = "registry-1",
            FilePath = "/catalogs/catalog-a.json",
            DisplayName = "Catalog A",
            Enabled = true,
            CatalogId = "catalog-a",
            CatalogVersion = "2",
            CatalogSource = "test",
            Sha256 = new string('a', 64),
            RegisteredAtUnixMs = now.AddDays(-2).ToUnixTimeMilliseconds(),
            UpdatedAtUnixMs = now.AddHours(-1).ToUnixTimeMilliseconds(),
        };
    }

    private sealed class FakeSourceStore(ProviderAsnCatalogRemoteSourceItem? item)
        : IProviderAsnCatalogRemoteSourceStore
    {
        public ProviderAsnCatalogRemoteSourceItem? Item { get; private set; } = item;

        public Task<ProviderAsnCatalogRemoteSourceItem?> GetAsync(
            string registryId,
            CancellationToken cancellationToken = default)
            => Task.FromResult(
                Item is not null && Item.RegistryId == registryId ? Item : null);

        public Task<IReadOnlyList<ProviderAsnCatalogRemoteSourceItem>> ListAsync(
            int maxItems = 500,
            CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<ProviderAsnCatalogRemoteSourceItem>>(
                Item is null ? [] : [Item]);

        public Task UpsertAsync(
            ProviderAsnCatalogRemoteSourceItem value,
            CancellationToken cancellationToken = default)
        {
            Item = value;
            return Task.CompletedTask;
        }

        public Task RemoveAsync(string registryId, CancellationToken cancellationToken = default)
        {
            if (Item?.RegistryId == registryId)
            {
                Item = null;
            }
            return Task.CompletedTask;
        }
    }

    private sealed class FakeRegistryStore(ProviderAsnCatalogRegistryItem registry)
        : IProviderAsnCatalogRegistryStore
    {
        private ProviderAsnCatalogRegistryItem _registry = registry;

        public Task<IReadOnlyList<ProviderAsnCatalogRegistryItem>> ListAsync(
            ProviderAsnCatalogRegistryQuery? query = null,
            CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<ProviderAsnCatalogRegistryItem>>([_registry]);

        public Task<ProviderAsnCatalogRegistryItem?> GetAsync(
            string id,
            CancellationToken cancellationToken = default)
            => Task.FromResult<ProviderAsnCatalogRegistryItem?>(id == _registry.Id ? _registry : null);

        public Task<ProviderAsnCatalogRegistryItem?> FindByPathAsync(
            string normalizedPath,
            CancellationToken cancellationToken = default)
            => Task.FromResult<ProviderAsnCatalogRegistryItem?>(_registry);

        public Task UpsertAsync(ProviderAsnCatalogRegistryItem item, CancellationToken cancellationToken = default)
        {
            _registry = item;
            return Task.CompletedTask;
        }

        public Task RemoveAsync(string id, CancellationToken cancellationToken = default)
            => Task.CompletedTask;

        public Task<int> RetireAsync(
            ProviderAsnCatalogRegistryItem item,
            bool discardRevisionHistory,
            CancellationToken cancellationToken = default)
            => Task.FromResult(0);

        public Task<IReadOnlyList<ProviderAsnCatalogRevisionItem>> ListRevisionsAsync(
            ProviderAsnCatalogRevisionQuery? query = null,
            CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<ProviderAsnCatalogRevisionItem>>([]);

        public Task<ProviderAsnCatalogRevisionItem?> GetRevisionAsync(
            string id,
            CancellationToken cancellationToken = default)
            => Task.FromResult<ProviderAsnCatalogRevisionItem?>(null);

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
