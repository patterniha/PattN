using System.Text;
using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;
using ServiceLib.Models.Entities;

namespace ServiceLib.Tests.Reviver;

public class ProviderAsnCatalogCrashRecoveryTests
{
    [Test]
    public async Task RecoverWithLease_ShouldRemainReadOnlyWhenNoRecoveryArtifactsExist()
    {
        var logicalPath = Path.Combine(
            Path.GetTempPath(),
            "pattn-missing-catalog-parent-" + Guid.NewGuid().ToString("N"),
            "catalog.json");
        var registry = new ProviderAsnCatalogRegistryItem
        {
            Id = "registry-read-only",
            FilePath = logicalPath,
            DisplayName = "catalog",
            Enabled = true,
            CatalogId = "catalog",
            CatalogVersion = "v1",
            CatalogSource = "test",
            Sha256 = new string('a', 64),
            RegisteredAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            UpdatedAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        };
        var store = new MemoryStore();
        await store.UpsertAsync(registry);

        var recovered = await ProviderAsnCatalogApplyRecovery.RecoverWithLeaseAsync(
            registry,
            store,
            new ProviderAsnCatalogUpdateService(),
            CancellationToken.None);

        await recovered.Id.Should().BeEqualTo(registry.Id);
        await Directory.Exists(Path.GetDirectoryName(logicalPath)!).Should().BeFalse();
        await File.Exists(ProviderAsnCatalogApplyRecovery.OperationLeasePath(logicalPath)).Should().BeFalse();
    }

    [Test]
    public async Task Recover_ShouldRollbackFileOnlyCrash()
    {
        var state = await CreateStateAsync();
        try
        {
            await ProviderAsnCatalogApplyRecovery.WriteAsync(state.Journal, CancellationToken.None);
            _ = await state.Updates.ApplyAsync(state.Plan);

            var recovered = await ProviderAsnCatalogApplyRecovery.RecoverIfNeededAsync(
                state.Registry,
                state.Store,
                state.Updates,
                CancellationToken.None);

            await (await File.ReadAllBytesAsync(state.Path)).SequenceEqual(state.Before).Should().BeTrue();
            await recovered.CatalogVersion.Should().BeEqualTo("v1");
            await recovered.ActiveRevisionId.Should().BeEqualTo(string.Empty);
            await File.Exists(ProviderAsnCatalogApplyRecovery.JournalPath(state.Path)).Should().BeFalse();
        }
        finally
        {
            Directory.Delete(state.Root, recursive: true);
        }
    }

    [Test]
    public async Task Recover_ShouldRollbackInsertedRevisionWhenRegistryWasNotCommitted()
    {
        var state = await CreateStateAsync();
        try
        {
            await ProviderAsnCatalogApplyRecovery.WriteAsync(state.Journal, CancellationToken.None);
            var receipt = await state.Updates.ApplyAsync(state.Plan);
            var partial = CreateRevision(state, receipt);
            await state.Store.InsertRevisionAsync(partial);

            _ = await ProviderAsnCatalogApplyRecovery.RecoverIfNeededAsync(
                state.Registry,
                state.Store,
                state.Updates,
                CancellationToken.None);

            var stored = await state.Store.GetRevisionAsync(state.RevisionId);
            await stored.Should().NotBeNull();
            await stored!.RolledBackAtUnixMs.HasValue.Should().BeTrue();
            await (await File.ReadAllBytesAsync(state.Path)).SequenceEqual(state.Before).Should().BeTrue();
        }
        finally
        {
            Directory.Delete(state.Root, recursive: true);
        }
    }

    [Test]
    public async Task Recover_ShouldAcceptCompletedCommitAndOnlyRemoveJournal()
    {
        var state = await CreateStateAsync();
        try
        {
            await ProviderAsnCatalogApplyRecovery.WriteAsync(state.Journal, CancellationToken.None);
            var receipt = await state.Updates.ApplyAsync(state.Plan);
            var revision = CreateRevision(state, receipt);
            await state.Store.InsertRevisionAsync(revision);

            var afterCatalog = JsonProviderAsnEndpointCatalog.FromBytes(state.After);
            var committed = Clone(state.Registry);
            committed.CatalogVersion = "v2";
            committed.Sha256 = afterCatalog.Sha256;
            committed.ActiveRevisionId = state.RevisionId;
            committed.UpdatedAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            await state.Store.UpsertAsync(committed);

            var recovered = await ProviderAsnCatalogApplyRecovery.RecoverIfNeededAsync(
                committed,
                state.Store,
                state.Updates,
                CancellationToken.None);

            await recovered.ActiveRevisionId.Should().BeEqualTo(state.RevisionId);
            await (await File.ReadAllBytesAsync(state.Path)).SequenceEqual(state.After).Should().BeTrue();
            var stored = await state.Store.GetRevisionAsync(state.RevisionId);
            await stored!.RolledBackAtUnixMs.HasValue.Should().BeFalse();
            await File.Exists(ProviderAsnCatalogApplyRecovery.JournalPath(state.Path)).Should().BeFalse();
        }
        finally
        {
            Directory.Delete(state.Root, recursive: true);
        }
    }

    [Test]
    public async Task Recover_ShouldFinishRollbackAfterFileWasRestored()
    {
        var state = await CreateStateAsync();
        try
        {
            var receipt = await state.Updates.ApplyAsync(state.Plan);
            var revision = CreateRevision(state, receipt);
            await state.Store.InsertRevisionAsync(revision);

            var afterCatalog = JsonProviderAsnEndpointCatalog.FromBytes(state.After);
            var committed = Clone(state.Registry);
            committed.CatalogVersion = "v2";
            committed.Sha256 = afterCatalog.Sha256;
            committed.ActiveRevisionId = state.RevisionId;
            committed.UpdatedAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            await state.Store.UpsertAsync(committed);

            var targetRegistry = Clone(state.Registry);
            targetRegistry.ActiveRevisionId = string.Empty;
            var targetRevision = JsonUtils.DeepCopy(revision)!;
            targetRevision.RolledBackAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            var journal = await ProviderAsnCatalogApplyRecovery.CreateRollbackAsync(
                committed,
                revision,
                targetRegistry,
                targetRevision,
                CancellationToken.None);
            await ProviderAsnCatalogApplyRecovery.WriteRollbackAsync(journal, CancellationToken.None);

            await state.Updates.RollbackAsync(receipt, force: false);

            var recovered = await ProviderAsnCatalogApplyRecovery.RecoverIfNeededAsync(
                committed,
                state.Store,
                state.Updates,
                CancellationToken.None);

            await (await File.ReadAllBytesAsync(state.Path)).SequenceEqual(state.Before).Should().BeTrue();
            await recovered.CatalogVersion.Should().BeEqualTo("v1");
            await recovered.ActiveRevisionId.Should().BeEqualTo(string.Empty);
            var stored = await state.Store.GetRevisionAsync(state.RevisionId);
            await stored.Should().NotBeNull();
            await stored!.RolledBackAtUnixMs.HasValue.Should().BeTrue();
            await File.Exists(ProviderAsnCatalogApplyRecovery.RollbackJournalPath(state.Path)).Should().BeFalse();
        }
        finally
        {
            Directory.Delete(state.Root, recursive: true);
        }
    }

    [Test]
    public async Task Recover_ShouldAbortRollbackJournalWhenFileAndLedgerNeverChanged()
    {
        var state = await CreateStateAsync();
        try
        {
            var receipt = await state.Updates.ApplyAsync(state.Plan);
            var revision = CreateRevision(state, receipt);
            await state.Store.InsertRevisionAsync(revision);

            var afterCatalog = JsonProviderAsnEndpointCatalog.FromBytes(state.After);
            var committed = Clone(state.Registry);
            committed.CatalogVersion = "v2";
            committed.Sha256 = afterCatalog.Sha256;
            committed.ActiveRevisionId = state.RevisionId;
            committed.UpdatedAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            await state.Store.UpsertAsync(committed);

            var targetRegistry = Clone(state.Registry);
            targetRegistry.ActiveRevisionId = string.Empty;
            var targetRevision = JsonUtils.DeepCopy(revision)!;
            targetRevision.RolledBackAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            var journal = await ProviderAsnCatalogApplyRecovery.CreateRollbackAsync(
                committed,
                revision,
                targetRegistry,
                targetRevision,
                CancellationToken.None);
            await ProviderAsnCatalogApplyRecovery.WriteRollbackAsync(journal, CancellationToken.None);

            var recovered = await ProviderAsnCatalogApplyRecovery.RecoverIfNeededAsync(
                committed,
                state.Store,
                state.Updates,
                CancellationToken.None);

            await (await File.ReadAllBytesAsync(state.Path)).SequenceEqual(state.After).Should().BeTrue();
            await recovered.CatalogVersion.Should().BeEqualTo("v2");
            await recovered.ActiveRevisionId.Should().BeEqualTo(state.RevisionId);
            var stored = await state.Store.GetRevisionAsync(state.RevisionId);
            await stored!.RolledBackAtUnixMs.HasValue.Should().BeFalse();
            await File.Exists(ProviderAsnCatalogApplyRecovery.RollbackJournalPath(state.Path)).Should().BeFalse();
        }
        finally
        {
            Directory.Delete(state.Root, recursive: true);
        }
    }

    private static async Task<State> CreateStateAsync()
    {
        var root = Path.Combine(Path.GetTempPath(), "pattn-catalog-crash-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "catalog.json");
        var before = Catalog("catalog", "v1", "203.0.113.10");
        var after = Catalog("catalog", "v2", "203.0.113.20");
        await File.WriteAllBytesAsync(path, before);

        var beforeCatalog = JsonProviderAsnEndpointCatalog.FromBytes(before);
        var now = DateTimeOffset.UtcNow;
        var registry = new ProviderAsnCatalogRegistryItem
        {
            Id = "registry-1",
            FilePath = path,
            DisplayName = "catalog",
            Enabled = true,
            CatalogId = "catalog",
            CatalogVersion = "v1",
            CatalogSource = "fault-test",
            Sha256 = beforeCatalog.Sha256,
            RegisteredAtUnixMs = now.ToUnixTimeMilliseconds(),
            UpdatedAtUnixMs = now.ToUnixTimeMilliseconds(),
        };
        var store = new MemoryStore();
        await store.UpsertAsync(registry);
        var updates = new ProviderAsnCatalogUpdateService();
        var plan = await updates.PrepareAsync(path, after);
        const string revisionId = "revision-crash-1";
        var journal = ProviderAsnCatalogApplyRecovery.Create(registry, plan, revisionId);
        return new State(root, path, before, after, registry, store, updates, plan, journal, revisionId);
    }

    private static ProviderAsnCatalogRevisionItem CreateRevision(
        State state,
        ProviderAsnCatalogUpdateReceipt receipt)
        => new()
        {
            Id = state.RevisionId,
            RegistryId = state.Registry.Id,
            PlanId = receipt.PlanId,
            DestinationPath = receipt.DestinationPath,
            DestinationExisted = receipt.DestinationExisted,
            BeforeSha256 = receipt.BeforeSha256,
            AfterSha256 = receipt.AfterSha256,
            BeforeCatalogId = state.Plan.BeforeCatalogId,
            BeforeCatalogVersion = state.Plan.BeforeCatalogVersion,
            AfterCatalogId = state.Plan.AfterCatalogId,
            AfterCatalogVersion = state.Plan.AfterCatalogVersion,
            BeforeBytes = receipt.BeforeBytes.ToArray(),
            AppliedAtUnixMs = receipt.AppliedAt.ToUnixTimeMilliseconds(),
        };

    private static ProviderAsnCatalogRegistryItem Clone(ProviderAsnCatalogRegistryItem item)
        => JsonUtils.DeepCopy(item)!;

    private static byte[] Catalog(string id, string version, string address)
        => Encoding.UTF8.GetBytes(
            $$"""
            {
              "schemaVersion":1,
              "id":"{{id}}",
              "version":"{{version}}",
              "source":"fault-test",
              "updatedAt":"2026-09-25T09:00:00Z",
              "entries":[
                {
                  "address":"{{address}}",
                  "sourceId":"edge-1",
                  "logicalHosts":["front.example"]
                }
              ]
            }
            """);

    private sealed record State(
        string Root,
        string Path,
        byte[] Before,
        byte[] After,
        ProviderAsnCatalogRegistryItem Registry,
        MemoryStore Store,
        ProviderAsnCatalogUpdateService Updates,
        ProviderAsnCatalogUpdatePlan Plan,
        ProviderAsnCatalogPendingApplyJournal Journal,
        string RevisionId);

    private sealed class MemoryStore : IProviderAsnCatalogRegistryStore
    {
        private readonly Dictionary<string, ProviderAsnCatalogRegistryItem> _registry = new(StringComparer.Ordinal);
        private readonly Dictionary<string, ProviderAsnCatalogRevisionItem> _revisions = new(StringComparer.Ordinal);

        public Task<IReadOnlyList<ProviderAsnCatalogRegistryItem>> ListAsync(
            ProviderAsnCatalogRegistryQuery? query = null,
            CancellationToken cancellationToken = default)
        {
            query ??= new ProviderAsnCatalogRegistryQuery();
            return Task.FromResult<IReadOnlyList<ProviderAsnCatalogRegistryItem>>(
                _registry.Values.Take(query.MaxItems).ToArray());
        }

        public Task<ProviderAsnCatalogRegistryItem?> GetAsync(string id, CancellationToken cancellationToken = default)
            => Task.FromResult(_registry.TryGetValue(id, out var value) ? value : null);

        public Task<ProviderAsnCatalogRegistryItem?> FindByPathAsync(
            string normalizedPath,
            CancellationToken cancellationToken = default)
            => Task.FromResult(_registry.Values.FirstOrDefault(x => x.FilePath == normalizedPath));

        public Task UpsertAsync(ProviderAsnCatalogRegistryItem item, CancellationToken cancellationToken = default)
        {
            _registry[item.Id] = Clone(item);
            return Task.CompletedTask;
        }

        public Task RemoveAsync(string id, CancellationToken cancellationToken = default)
        {
            _registry.Remove(id);
            return Task.CompletedTask;
        }

        public Task<int> RetireAsync(
            ProviderAsnCatalogRegistryItem item,
            bool discardRevisionHistory,
            CancellationToken cancellationToken = default)
        {
            _registry[item.Id] = Clone(item);
            var count = _revisions.Values.Count(x => x.RegistryId == item.Id);
            if (discardRevisionHistory)
            {
                foreach (var id in _revisions.Values.Where(x => x.RegistryId == item.Id).Select(x => x.Id).ToArray())
                {
                    _revisions.Remove(id);
                }
            }
            return Task.FromResult(count);
        }

        public Task<IReadOnlyList<ProviderAsnCatalogRevisionItem>> ListRevisionsAsync(
            ProviderAsnCatalogRevisionQuery? query = null,
            CancellationToken cancellationToken = default)
        {
            query ??= new ProviderAsnCatalogRevisionQuery();
            return Task.FromResult<IReadOnlyList<ProviderAsnCatalogRevisionItem>>(
                _revisions.Values
                    .Where(x => query.RegistryId.IsNullOrEmpty() || x.RegistryId == query.RegistryId)
                    .Take(query.MaxItems)
                    .ToArray());
        }

        public Task<ProviderAsnCatalogRevisionItem?> GetRevisionAsync(
            string id,
            CancellationToken cancellationToken = default)
            => Task.FromResult(_revisions.TryGetValue(id, out var value) ? value : null);

        public Task InsertRevisionAsync(
            ProviderAsnCatalogRevisionItem item,
            CancellationToken cancellationToken = default)
        {
            _revisions[item.Id] = item;
            return Task.CompletedTask;
        }

        public Task UpdateRevisionAsync(
            ProviderAsnCatalogRevisionItem item,
            CancellationToken cancellationToken = default)
        {
            _revisions[item.Id] = item;
            return Task.CompletedTask;
        }
    }
}
