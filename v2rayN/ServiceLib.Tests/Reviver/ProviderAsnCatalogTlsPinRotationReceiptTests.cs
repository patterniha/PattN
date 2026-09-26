using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;
using ServiceLib.Models.Entities;

namespace ServiceLib.Tests.Reviver;

public class ProviderAsnCatalogTlsPinRotationReceiptTests
{
    [Test]
    public async Task Rotation_ShouldPersistLinkedReceiptAcrossTwoStepReplacement()
    {
        var pinA = new string('a', 64);
        var pinB = new string('b', 64);
        var registry = Registry();
        var sources = new FakeSourceStore(Source(registry.Id, [pinA]));
        var revisions = new FakeRevisionStore();
        var catalogs = new ProviderAsnCatalogRegistryService(new FakeRegistryStore(registry));
        var updates = new ProviderAsnCatalogRemoteUpdateService(
            catalogs,
            sources,
            provenanceStore: null,
            sourceRevisionStore: revisions);
        var service = new ProviderAsnCatalogTlsPinRotationService(
            catalogs,
            sources,
            updates,
            revisions);

        var addPreview = await service.PrepareAsync(registry.Id, [pinA, pinB]);
        var addReceipt = await service.ApplyAsync(addPreview);
        await addReceipt.RevisionRecorded.Should().BeTrue();
        await addReceipt.Source.TlsSpkiPinsSha256.SequenceEqual([pinA, pinB]).Should().BeTrue();
        await revisions.Items.Single(x => x.Id == addReceipt.RevisionId)
            .ChangeReason.Should().BeEqualTo("tls-pin-rotation");

        var retirePreview = await service.PrepareAsync(registry.Id, [pinB]);
        var retireReceipt = await service.ApplyAsync(retirePreview);
        await retireReceipt.RevisionRecorded.Should().BeTrue();
        await retireReceipt.BeforePinsSha256.SequenceEqual([pinA, pinB]).Should().BeTrue();
        await retireReceipt.AfterPinsSha256.SequenceEqual([pinB]).Should().BeTrue();
        await revisions.Items.Count.Should().BeEqualTo(2);
    }

    [Test]
    public async Task Rotation_ShouldRejectDisjointReplacementAndImplicitUnpinning()
    {
        var pinA = new string('a', 64);
        var pinB = new string('b', 64);
        var registry = Registry();
        var sources = new FakeSourceStore(Source(registry.Id, [pinA]));
        var revisions = new FakeRevisionStore();
        var catalogs = new ProviderAsnCatalogRegistryService(new FakeRegistryStore(registry));
        var updates = new ProviderAsnCatalogRemoteUpdateService(
            catalogs,
            sources,
            provenanceStore: null,
            sourceRevisionStore: revisions);
        var service = new ProviderAsnCatalogTlsPinRotationService(catalogs, sources, updates, revisions);

        var disjointRejected = false;
        try
        {
            await service.PrepareAsync(registry.Id, [pinB]);
        }
        catch (InvalidOperationException)
        {
            disjointRejected = true;
        }

        var unpinRejected = false;
        try
        {
            await service.PrepareAsync(registry.Id, []);
        }
        catch (InvalidOperationException)
        {
            unpinRejected = true;
        }

        await disjointRejected.Should().BeTrue();
        await unpinRejected.Should().BeTrue();
        await revisions.Items.Count.Should().BeEqualTo(0);
    }

    [Test]
    public async Task Rotation_ShouldRejectStalePreview()
    {
        var pinA = new string('a', 64);
        var pinB = new string('b', 64);
        var pinC = new string('c', 64);
        var registry = Registry();
        var sources = new FakeSourceStore(Source(registry.Id, [pinA]));
        var revisions = new FakeRevisionStore();
        var catalogs = new ProviderAsnCatalogRegistryService(new FakeRegistryStore(registry));
        var updates = new ProviderAsnCatalogRemoteUpdateService(
            catalogs,
            sources,
            provenanceStore: null,
            sourceRevisionStore: revisions);
        var service = new ProviderAsnCatalogTlsPinRotationService(catalogs, sources, updates, revisions);

        var preview = await service.PrepareAsync(registry.Id, [pinA, pinB]);
        await sources.UpsertAsync(Source(registry.Id, [pinA, pinC]));

        var threw = false;
        try
        {
            await service.ApplyAsync(preview);
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.Message.Contains("changed after TLS pin rotation preview", StringComparison.OrdinalIgnoreCase);
        }

        await threw.Should().BeTrue();
        await revisions.Items.Count.Should().BeEqualTo(0);
    }

    private static ProviderAsnCatalogRemoteSourceItem Source(string registryId, IReadOnlyList<string> pins)
        => new()
        {
            RegistryId = registryId,
            Uri = "https://catalog.example/catalog.json",
            SignaturePolicy = (int)ProviderAsnCatalogSignaturePolicy.None,
            TlsSpkiPinsSha256Json = ProviderAsnCatalogTransportPinning.SerializePins(pins),
            ETag = "\"cache\"",
            RemoteContentSha256 = new string('f', 64),
            ConfigurationUpdatedAtUnixMs = DateTimeOffset.UtcNow.AddMinutes(-10).ToUnixTimeMilliseconds(),
        };

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

    private sealed class FakeSourceStore(ProviderAsnCatalogRemoteSourceItem item)
        : IProviderAsnCatalogRemoteSourceStore
    {
        public ProviderAsnCatalogRemoteSourceItem Item { get; private set; } = item;

        public Task<ProviderAsnCatalogRemoteSourceItem?> GetAsync(string registryId, CancellationToken cancellationToken = default)
            => Task.FromResult<ProviderAsnCatalogRemoteSourceItem?>(Item.RegistryId == registryId ? Item : null);

        public Task<IReadOnlyList<ProviderAsnCatalogRemoteSourceItem>> ListAsync(
            int maxItems = 500,
            CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<ProviderAsnCatalogRemoteSourceItem>>([Item]);

        public Task UpsertAsync(ProviderAsnCatalogRemoteSourceItem value, CancellationToken cancellationToken = default)
        {
            Item = value;
            return Task.CompletedTask;
        }

        public Task RemoveAsync(string registryId, CancellationToken cancellationToken = default)
            => Task.CompletedTask;
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
            => Task.FromResult<IReadOnlyList<ProviderAsnCatalogRemoteSourceRevisionItem>>(Items.Take(maxItems).ToArray());
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
        public Task<int> RetireAsync(ProviderAsnCatalogRegistryItem item, bool discardRevisionHistory, CancellationToken cancellationToken = default)
            => Task.FromResult(0);
        public Task<IReadOnlyList<ProviderAsnCatalogRevisionItem>> ListRevisionsAsync(ProviderAsnCatalogRevisionQuery? query = null, CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<ProviderAsnCatalogRevisionItem>>([]);
        public Task<ProviderAsnCatalogRevisionItem?> GetRevisionAsync(string id, CancellationToken cancellationToken = default)
            => Task.FromResult<ProviderAsnCatalogRevisionItem?>(null);
        public Task InsertRevisionAsync(ProviderAsnCatalogRevisionItem item, CancellationToken cancellationToken = default)
            => Task.CompletedTask;
        public Task UpdateRevisionAsync(ProviderAsnCatalogRevisionItem item, CancellationToken cancellationToken = default)
            => Task.CompletedTask;
    }
}
