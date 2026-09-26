using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;
using ServiceLib.Models.Entities;

namespace ServiceLib.Tests.Reviver;

public class ProviderAsnCatalogRemoteSourceRevisionTests
{
    [Test]
    public async Task ConfigureAndRemove_ShouldPersistOnlyEffectiveTrustChanges()
    {
        var registry = Registry();
        var sources = new FakeSourceStore(null);
        var revisions = new FakeRevisionStore();
        var catalogs = new ProviderAsnCatalogRegistryService(new FakeRegistryStore(registry));
        var service = new ProviderAsnCatalogRemoteUpdateService(
            catalogs,
            sources,
            provenanceStore: null,
            sourceRevisionStore: revisions);

        var pinA = new string('a', 64);
        var pinB = new string('b', 64);
        var first = new ProviderAsnCatalogRemoteSourceConfig
        {
            Uri = "https://catalog.example/catalog.json",
            TlsSpkiPinsSha256 = [pinA],
        };

        await service.ConfigureAsync(
            registry.Id,
            first,
            DateTimeOffset.Parse("2026-09-24T10:00:00Z"),
            changeContext: new ProviderAsnCatalogRemoteSourceChangeContext
            {
                Reason = "manual",
            });
        var firstConfigurationTimestamp = sources.Item!.ConfigurationUpdatedAtUnixMs;

        await service.ConfigureAsync(
            registry.Id,
            first,
            DateTimeOffset.Parse("2026-09-24T10:05:00Z"),
            changeContext: new ProviderAsnCatalogRemoteSourceChangeContext
            {
                Reason = "duplicate-save",
            });

        await sources.Item!.ConfigurationUpdatedAtUnixMs.Should().BeEqualTo(firstConfigurationTimestamp);

        var rotated = first with { TlsSpkiPinsSha256 = [pinA, pinB] };
        await service.ConfigureAsync(
            registry.Id,
            rotated,
            DateTimeOffset.Parse("2026-09-24T10:10:00Z"),
            changeContext: new ProviderAsnCatalogRemoteSourceChangeContext
            {
                RevisionId = "rotation-revision",
                Reason = "tls-pin-rotation",
            });

        await service.RemoveAsync(registry.Id);

        await revisions.Items.Count.Should().BeEqualTo(3);
        await revisions.Items[0].ChangeReason.Should().BeEqualTo("manual");
        await revisions.Items[1].Id.Should().BeEqualTo("rotation-revision");
        await ProviderAsnCatalogTransportPinning.DeserializePins(revisions.Items[1].AddedTlsSpkiPinsSha256Json)
            .SequenceEqual([pinB]).Should().BeTrue();
        await revisions.Items[2].ChangeReason.Should().BeEqualTo("remove");
        await revisions.Items[2].AfterFingerprint.Should().BeEqualTo(string.Empty);
        await (sources.Item is null).Should().BeTrue();
    }

    [Test]
    public async Task Configure_ShouldRollbackTrustChangeWhenRevisionPersistenceFails()
    {
        var registry = Registry();
        var sources = new FakeSourceStore(null);
        var catalogs = new ProviderAsnCatalogRegistryService(new FakeRegistryStore(registry));
        var service = new ProviderAsnCatalogRemoteUpdateService(
            catalogs,
            sources,
            provenanceStore: null,
            sourceRevisionStore: new ThrowingRevisionStore());

        var threw = false;
        try
        {
            await service.ConfigureAsync(
                registry.Id,
                new ProviderAsnCatalogRemoteSourceConfig
                {
                    Uri = "https://catalog.example/catalog.json",
                    TlsSpkiPinsSha256 = [new string('a', 64)],
                });
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.Message.Contains("rolled back", StringComparison.OrdinalIgnoreCase);
        }

        await threw.Should().BeTrue();
        await (sources.Item is null).Should().BeTrue();
    }

    [Test]
    public async Task Remove_ShouldRestoreTrustConfigurationWhenRevisionPersistenceFails()
    {
        var registry = Registry();
        var original = new ProviderAsnCatalogRemoteSourceItem
        {
            RegistryId = registry.Id,
            Uri = "https://catalog.example/catalog.json",
            SignaturePolicy = (int)ProviderAsnCatalogSignaturePolicy.None,
            TlsSpkiPinsSha256Json = ProviderAsnCatalogTransportPinning.SerializePins([new string('a', 64)]),
            ConfigurationUpdatedAtUnixMs = DateTimeOffset.Parse("2026-09-24T10:00:00Z").ToUnixTimeMilliseconds(),
        };
        var sources = new FakeSourceStore(original);
        var catalogs = new ProviderAsnCatalogRegistryService(new FakeRegistryStore(registry));
        var service = new ProviderAsnCatalogRemoteUpdateService(
            catalogs,
            sources,
            provenanceStore: null,
            sourceRevisionStore: new ThrowingRevisionStore());

        var threw = false;
        try
        {
            await service.RemoveAsync(registry.Id);
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.Message.Contains("rolled back", StringComparison.OrdinalIgnoreCase);
        }

        await threw.Should().BeTrue();
        await sources.Item.Should().NotBeNull();
        await sources.Item!.Uri.Should().BeEqualTo(original.Uri);
        await sources.Item.RegistryId.Should().BeEqualTo(original.RegistryId);
    }

    [Test]
    public async Task RevisionProjection_ShouldRejectCorruptedTrustFields()
    {
        var row = new ProviderAsnCatalogRemoteSourceRevisionItem
        {
            Id = "revision",
            RegistryId = "registry-1",
            BeforeSignaturePolicy = 999,
            AfterSignaturePolicy = (int)ProviderAsnCatalogSignaturePolicy.None,
            ChangedAtUnixMs = DateTimeOffset.Parse("2026-09-24T11:00:00Z").ToUnixTimeMilliseconds(),
        };

        var invalidPolicyRejected = false;
        try
        {
            _ = ProviderAsnCatalogRemoteSourceRevisionProjector.Project(row);
        }
        catch (InvalidOperationException ex)
        {
            invalidPolicyRejected = ex.Message.Contains("signature policy", StringComparison.OrdinalIgnoreCase);
        }
        await invalidPolicyRejected.Should().BeTrue();

        row.BeforeSignaturePolicy = (int)ProviderAsnCatalogSignaturePolicy.None;
        row.BeforeTlsSpkiPinsSha256Json = "{broken";

        var invalidPinsRejected = false;
        try
        {
            _ = ProviderAsnCatalogRemoteSourceRevisionProjector.Project(row);
        }
        catch
        {
            invalidPinsRejected = true;
        }
        await invalidPinsRejected.Should().BeTrue();
    }

    [Test]
    public async Task Query_ShouldFilterRevisionReasonAndPin()
    {
        var pinA = new string('a', 64);
        var pinB = new string('b', 64);
        var now = DateTimeOffset.UtcNow;
        var store = new FakeRevisionStore();
        await store.InsertAsync(new ProviderAsnCatalogRemoteSourceRevisionItem
        {
            Id = "r1",
            RegistryId = "registry-1",
            ChangeReason = "configure",
            AfterTrustedKeyId = "key-a",
            AfterTlsSpkiPinsSha256Json = ProviderAsnCatalogTransportPinning.SerializePins([pinA]),
            AddedTlsSpkiPinsSha256Json = ProviderAsnCatalogTransportPinning.SerializePins([pinA]),
            ChangedAtUnixMs = now.AddMinutes(-2).ToUnixTimeMilliseconds(),
        });
        await store.InsertAsync(new ProviderAsnCatalogRemoteSourceRevisionItem
        {
            Id = "r2",
            RegistryId = "registry-1",
            ChangeReason = "tls-pin-rotation",
            BeforeTlsSpkiPinsSha256Json = ProviderAsnCatalogTransportPinning.SerializePins([pinA]),
            AfterTlsSpkiPinsSha256Json = ProviderAsnCatalogTransportPinning.SerializePins([pinA, pinB]),
            AddedTlsSpkiPinsSha256Json = ProviderAsnCatalogTransportPinning.SerializePins([pinB]),
            ChangedAtUnixMs = now.AddMinutes(-1).ToUnixTimeMilliseconds(),
        });

        var summary = await new ProviderAsnCatalogRemoteSourceRevisionQueryService(store).QueryAsync(
            new ProviderAsnCatalogRemoteSourceRevisionQuery
            {
                RegistryId = "registry-1",
                ChangeReason = "TLS-PIN-ROTATION",
                TlsSpkiPinSha256 = pinB.ToUpperInvariant(),
            });

        await summary.Total.Should().BeEqualTo(1);
        await summary.PinChanges.Should().BeEqualTo(1);
        await summary.Entries[0].Id.Should().BeEqualTo("r2");
        await summary.Entries[0].AddedTlsSpkiPinsSha256.SequenceEqual([pinB]).Should().BeTrue();
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
            => Task.FromResult(Item?.RegistryId == registryId ? Item : null);

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

    private sealed class FakeRevisionStore : IProviderAsnCatalogRemoteSourceRevisionStore
    {
        public List<ProviderAsnCatalogRemoteSourceRevisionItem> Items { get; } = [];

        public Task InsertAsync(ProviderAsnCatalogRemoteSourceRevisionItem item, CancellationToken cancellationToken = default)
        {
            Items.Add(item);
            return Task.CompletedTask;
        }

        public Task<ProviderAsnCatalogRemoteSourceRevisionItem?> GetAsync(string id, CancellationToken cancellationToken = default)
            => Task.FromResult<ProviderAsnCatalogRemoteSourceRevisionItem?>(Items.FirstOrDefault(x => x.Id == id));

        public Task<IReadOnlyList<ProviderAsnCatalogRemoteSourceRevisionItem>> ListAsync(
            int maxItems = 1000,
            CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<ProviderAsnCatalogRemoteSourceRevisionItem>>(
                Items.OrderByDescending(x => x.ChangedAtUnixMs).Take(maxItems).ToArray());
    }

    private sealed class ThrowingRevisionStore : IProviderAsnCatalogRemoteSourceRevisionStore
    {
        public Task InsertAsync(ProviderAsnCatalogRemoteSourceRevisionItem item, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("history unavailable");

        public Task<ProviderAsnCatalogRemoteSourceRevisionItem?> GetAsync(string id, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("history unavailable");

        public Task<IReadOnlyList<ProviderAsnCatalogRemoteSourceRevisionItem>> ListAsync(
            int maxItems = 1000,
            CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("history unavailable");
    }

    private sealed class FakeRegistryStore(ProviderAsnCatalogRegistryItem registry)
        : IProviderAsnCatalogRegistryStore
    {
        public Task<IReadOnlyList<ProviderAsnCatalogRegistryItem>> ListAsync(
            ProviderAsnCatalogRegistryQuery? query = null,
            CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<ProviderAsnCatalogRegistryItem>>([registry]);

        public Task<ProviderAsnCatalogRegistryItem?> GetAsync(string id, CancellationToken cancellationToken = default)
            => Task.FromResult<ProviderAsnCatalogRegistryItem?>(id == registry.Id ? registry : null);

        public Task<ProviderAsnCatalogRegistryItem?> FindByPathAsync(
            string normalizedPath,
            CancellationToken cancellationToken = default)
            => Task.FromResult<ProviderAsnCatalogRegistryItem?>(registry);

        public Task UpsertAsync(ProviderAsnCatalogRegistryItem item, CancellationToken cancellationToken = default)
            => Task.CompletedTask;

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

        public Task<ProviderAsnCatalogRevisionItem?> GetRevisionAsync(string id, CancellationToken cancellationToken = default)
            => Task.FromResult<ProviderAsnCatalogRevisionItem?>(null);

        public Task InsertRevisionAsync(ProviderAsnCatalogRevisionItem item, CancellationToken cancellationToken = default)
            => Task.CompletedTask;

        public Task UpdateRevisionAsync(ProviderAsnCatalogRevisionItem item, CancellationToken cancellationToken = default)
            => Task.CompletedTask;
    }
}
