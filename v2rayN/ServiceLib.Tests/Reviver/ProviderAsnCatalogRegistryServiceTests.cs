using System.Text;
using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;
using ServiceLib.Models.Entities;

namespace ServiceLib.Tests.Reviver;

public class ProviderAsnCatalogRegistryServiceTests
{
    [Test]
    public async Task Register_ShouldPersistAuditAndRejectDuplicateEnabledCatalogId()
    {
        var root = CreateTempDirectory();
        try
        {
            var first = Path.Combine(root, "first.json");
            var second = Path.Combine(root, "second.json");
            await File.WriteAllBytesAsync(first, Catalog("catalog", "v1", "203.0.113.10"));
            await File.WriteAllBytesAsync(second, Catalog("catalog", "v2", "203.0.113.20"));

            var store = new MemoryStore();
            var service = new ProviderAsnCatalogRegistryService(store);

            var registered = await service.RegisterAsync(first);
            await registered.Enabled.Should().BeTrue();
            await registered.CatalogId.Should().BeEqualTo("catalog");
            await registered.CatalogVersion.Should().BeEqualTo("v1");
            await registered.LastAudit.Should().NotBeNull();
            await registered.LastAudit!.Valid.Should().BeTrue();

            var threw = false;
            try
            {
                await service.RegisterAsync(second);
            }
            catch (InvalidOperationException)
            {
                threw = true;
            }
            await threw.Should().BeTrue();

            var disabled = await service.RegisterAsync(
                second,
                new ProviderAsnCatalogRegistrationOptions { Enabled = false });
            await disabled.Enabled.Should().BeFalse();

            threw = false;
            try
            {
                await service.SetEnabledAsync(disabled.Id, true);
            }
            catch (InvalidOperationException)
            {
                threw = true;
            }
            await threw.Should().BeTrue();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Test]
    public async Task ApplyThenRestartRollback_ShouldRestoreExactPriorCatalogFromPersistedRevision()
    {
        var root = CreateTempDirectory();
        try
        {
            var path = Path.Combine(root, "catalog.json");
            var before = Catalog("catalog", "v1", "203.0.113.10");
            var after = Catalog("catalog", "v2", "203.0.113.20");
            await File.WriteAllBytesAsync(path, before);

            var store = new MemoryStore();
            var service = new ProviderAsnCatalogRegistryService(store);
            var registered = await service.RegisterAsync(path);

            var plan = await service.PrepareUpdateAsync(registered.Id, after);
            var revision = await service.ApplyUpdateAsync(registered.Id, plan);

            await revision.Active.Should().BeTrue();
            await revision.BeforeCatalogVersion.Should().BeEqualTo("v1");
            await revision.AfterCatalogVersion.Should().BeEqualTo("v2");
            await (await File.ReadAllBytesAsync(path)).SequenceEqual(after).Should().BeTrue();

            var current = await service.GetAsync(registered.Id);
            await current.CatalogVersion.Should().BeEqualTo("v2");
            await current.ActiveRevisionId.Should().BeEqualTo(revision.Id);

            // Simulate app restart: new service object, same persisted store.
            var restarted = new ProviderAsnCatalogRegistryService(store);
            var rolledBack = await restarted.RollbackRevisionAsync(revision.Id);

            await rolledBack.Active.Should().BeFalse();
            await rolledBack.RolledBackAt.HasValue.Should().BeTrue();
            await (await File.ReadAllBytesAsync(path)).SequenceEqual(before).Should().BeTrue();

            var restored = await restarted.GetAsync(registered.Id);
            await restored.CatalogVersion.Should().BeEqualTo("v1");
            await restored.ActiveRevisionId.Should().BeEqualTo(string.Empty);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Test]
    public async Task Rollback_ShouldSurfacePersistenceFailureAfterFileWasRestored()
    {
        var root = CreateTempDirectory();
        try
        {
            var path = Path.Combine(root, "catalog.json");
            var before = Catalog("catalog", "v1", "203.0.113.10");
            var after = Catalog("catalog", "v2", "203.0.113.20");
            await File.WriteAllBytesAsync(path, before);

            var store = new MemoryStore();
            var service = new ProviderAsnCatalogRegistryService(store);
            var registered = await service.RegisterAsync(path);
            var plan = await service.PrepareUpdateAsync(registered.Id, after);
            var revision = await service.ApplyUpdateAsync(registered.Id, plan);

            store.FailUpsert = true;
            var threw = false;
            try
            {
                await service.RollbackRevisionAsync(revision.Id);
            }
            catch (InvalidOperationException ex)
            {
                threw = ex.Message.Contains("persistence failed", StringComparison.OrdinalIgnoreCase)
                        && ex.Message.Contains("reconciliation", StringComparison.OrdinalIgnoreCase);
            }

            await threw.Should().BeTrue();
            await (await File.ReadAllBytesAsync(path)).SequenceEqual(before).Should().BeTrue();
            await File.Exists(ProviderAsnCatalogApplyRecovery.RollbackJournalPath(path)).Should().BeTrue();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Test]
    public async Task LoadEnabledCatalogs_ShouldRejectUnreconciledOnDiskDrift()
    {
        var root = CreateTempDirectory();
        try
        {
            var path = Path.Combine(root, "catalog.json");
            await File.WriteAllBytesAsync(path, Catalog("catalog", "v1", "203.0.113.10"));

            var store = new MemoryStore();
            var service = new ProviderAsnCatalogRegistryService(store);
            await service.RegisterAsync(path);

            await File.WriteAllBytesAsync(path, Catalog("catalog", "external", "203.0.113.99"));

            var threw = false;
            try
            {
                await service.LoadEnabledCatalogsAsync();
            }
            catch (InvalidOperationException)
            {
                threw = true;
            }

            await threw.Should().BeTrue();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Test]
    public async Task RegistryAggregate_ShouldDeduplicateSameEndpointAcrossDifferentCatalogs()
    {
        var root = CreateTempDirectory();
        try
        {
            var first = Path.Combine(root, "first.json");
            var second = Path.Combine(root, "second.json");
            await File.WriteAllBytesAsync(first, Catalog("catalog-a", "v1", "203.0.113.10"));
            await File.WriteAllBytesAsync(second, Catalog("catalog-b", "v1", "203.0.113.10"));

            var store = new MemoryStore();
            var service = new ProviderAsnCatalogRegistryService(store);
            await service.RegisterAsync(first);
            await service.RegisterAsync(second);

            var aggregate = new RegistryProviderAsnEndpointCatalog(service);
            var values = await aggregate.ListAsync(
                new DiscoveryCandidateRequest
                {
                    OriginalAddress = "origin.example",
                    OriginalPort = 443,
                    LogicalHost = "front.example",
                    MaxCandidates = 10,
                },
                10);

            await values.Count.Should().BeEqualTo(1);
            await values[0].Address.Should().BeEqualTo("203.0.113.10");
            await values[0].Metadata["catalogAuditValid"].Should().BeEqualTo("true");
            await values[0].Metadata.ContainsKey("catalogAuditedAt").Should().BeTrue();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Test]
    public async Task SetEnabled_ShouldRejectFileDriftWhileResourceWasDisabled()
    {
        var root = CreateTempDirectory();
        try
        {
            var path = Path.Combine(root, "catalog.json");
            await File.WriteAllBytesAsync(path, Catalog("catalog", "v1", "203.0.113.10"));

            var store = new MemoryStore();
            var service = new ProviderAsnCatalogRegistryService(store);
            var registered = await service.RegisterAsync(
                path,
                new ProviderAsnCatalogRegistrationOptions { Enabled = false });

            await File.WriteAllBytesAsync(path, Catalog("catalog", "external", "203.0.113.99"));

            var threw = false;
            try
            {
                await service.SetEnabledAsync(registered.Id, true);
            }
            catch (InvalidOperationException)
            {
                threw = true;
            }

            await threw.Should().BeTrue();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Test]
    public async Task Register_ShouldRejectSamePathCatalogIdentityChange()
    {
        var root = CreateTempDirectory();
        try
        {
            var path = Path.Combine(root, "catalog.json");
            await File.WriteAllBytesAsync(path, Catalog("catalog-a", "v1", "203.0.113.10"));

            var store = new MemoryStore();
            var service = new ProviderAsnCatalogRegistryService(store);
            await service.RegisterAsync(path);

            await File.WriteAllBytesAsync(path, Catalog("catalog-b", "v1", "203.0.113.10"));

            var threw = false;
            try
            {
                await service.RegisterAsync(path);
            }
            catch (InvalidOperationException)
            {
                threw = true;
            }

            await threw.Should().BeTrue();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Test]
    public async Task PrepareUpdate_ShouldRejectRegistryCatalogIdentityMismatch()
    {
        var root = CreateTempDirectory();
        try
        {
            var path = Path.Combine(root, "catalog.json");
            await File.WriteAllBytesAsync(path, Catalog("catalog-a", "v1", "203.0.113.10"));

            var store = new MemoryStore();
            var service = new ProviderAsnCatalogRegistryService(store);
            var registered = await service.RegisterAsync(path);

            var threw = false;
            try
            {
                await service.PrepareUpdateAsync(
                    registered.Id,
                    Catalog("catalog-b", "v2", "203.0.113.20"),
                    new ProviderAsnCatalogUpdateOptions { RequireSameCatalogId = false });
            }
            catch (InvalidOperationException)
            {
                threw = true;
            }

            await threw.Should().BeTrue();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Test]
    public async Task Projection_ShouldRejectCorruptedStoredAuditEvidence()
    {
        var root = CreateTempDirectory();
        try
        {
            var path = Path.Combine(root, "catalog.json");
            await File.WriteAllBytesAsync(path, Catalog("catalog", "v1", "203.0.113.10"));

            var store = new MemoryStore();
            var service = new ProviderAsnCatalogRegistryService(store);
            var registered = await service.RegisterAsync(path);

            var storedRegistry = await store.GetAsync(registered.Id);
            storedRegistry!.LastAuditJson = "{broken";

            var registryRejected = false;
            try
            {
                _ = await service.GetAsync(registered.Id);
            }
            catch (InvalidOperationException ex)
            {
                registryRejected = ex.Message.Contains(
                    nameof(ProviderAsnCatalogRegistryItem.LastAuditJson),
                    StringComparison.Ordinal);
            }
            await registryRejected.Should().BeTrue();

            storedRegistry.LastAuditJson = string.Empty;
            var plan = await service.PrepareUpdateAsync(
                registered.Id,
                Catalog("catalog", "v2", "203.0.113.20"));
            var revision = await service.ApplyUpdateAsync(registered.Id, plan);
            var storedRevision = await store.GetRevisionAsync(revision.Id);
            storedRevision!.AuditJson = "{broken";

            var revisionRejected = false;
            try
            {
                _ = await service.ListRevisionsAsync(new ProviderAsnCatalogRevisionQuery
                {
                    RegistryId = registered.Id,
                    IncludeRolledBack = true,
                });
            }
            catch (InvalidOperationException ex)
            {
                revisionRejected = ex.Message.Contains(
                    nameof(ProviderAsnCatalogRevisionItem.AuditJson),
                    StringComparison.Ordinal);
            }
            await revisionRejected.Should().BeTrue();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Test]
    public async Task Unregister_ShouldRetireWithoutDeletingFileAndPreserveRevisionHistory()
    {
        var root = CreateTempDirectory();
        try
        {
            var path = Path.Combine(root, "catalog.json");
            var before = Catalog("catalog", "v1", "203.0.113.10");
            var after = Catalog("catalog", "v2", "203.0.113.20");
            await File.WriteAllBytesAsync(path, before);

            var store = new MemoryStore();
            var service = new ProviderAsnCatalogRegistryService(store);
            var registered = await service.RegisterAsync(path);
            var plan = await service.PrepareUpdateAsync(registered.Id, after);
            var revision = await service.ApplyUpdateAsync(registered.Id, plan);

            var retiredAt = new DateTimeOffset(2026, 9, 24, 9, 0, 0, TimeSpan.Zero);
            var receipt = await service.UnregisterAsync(registered.Id, now: retiredAt);

            await receipt.RegistryId.Should().BeEqualTo(registered.Id);
            await receipt.RevisionHistoryDiscarded.Should().BeFalse();
            await receipt.RevisionCount.Should().BeEqualTo(1);
            await receipt.UnregisteredAt.Should().BeEqualTo(retiredAt);
            await File.Exists(path).Should().BeTrue();
            await (await File.ReadAllBytesAsync(path)).SequenceEqual(after).Should().BeTrue();

            var active = await service.ListAsync();
            await active.Count.Should().BeEqualTo(0);

            var all = await service.ListAsync(new ProviderAsnCatalogRegistryQuery
            {
                IncludeDisabled = true,
                IncludeUnregistered = true,
            });
            await all.Count.Should().BeEqualTo(1);
            await all[0].Registered.Should().BeFalse();
            await all[0].UnregisteredAt.HasValue.Should().BeTrue();
            await all[0].ActiveRevisionId.Should().BeEqualTo(revision.Id);

            var revisionsWhileRetired = await service.ListRevisionsAsync(new ProviderAsnCatalogRevisionQuery
            {
                RegistryId = registered.Id,
                IncludeRolledBack = true,
            });
            await revisionsWhileRetired.Count.Should().BeEqualTo(1);
            await revisionsWhileRetired[0].Active.Should().BeFalse();

            var enableThrew = false;
            try
            {
                await service.SetEnabledAsync(registered.Id, true);
            }
            catch (InvalidOperationException)
            {
                enableThrew = true;
            }
            await enableThrew.Should().BeTrue();

            var reRegistered = await service.RegisterAsync(path);
            await reRegistered.Id.Should().BeEqualTo(registered.Id);
            await reRegistered.Registered.Should().BeTrue();
            await reRegistered.ActiveRevisionId.Should().BeEqualTo(revision.Id);

            var revisionsAfterReregister = await service.ListRevisionsAsync(new ProviderAsnCatalogRevisionQuery
            {
                RegistryId = registered.Id,
                IncludeRolledBack = true,
            });
            await revisionsAfterReregister[0].Active.Should().BeTrue();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Test]
    public async Task ReregisterRetiredCatalogWithDifferentBytes_ShouldPreserveLedgerButClearActiveRevision()
    {
        var root = CreateTempDirectory();
        try
        {
            var path = Path.Combine(root, "catalog.json");
            await File.WriteAllBytesAsync(path, Catalog("catalog", "v1", "203.0.113.10"));

            var store = new MemoryStore();
            var service = new ProviderAsnCatalogRegistryService(store);
            var registered = await service.RegisterAsync(path);
            var plan = await service.PrepareUpdateAsync(
                registered.Id,
                Catalog("catalog", "v2", "203.0.113.20"));
            await service.ApplyUpdateAsync(registered.Id, plan);
            await service.UnregisterAsync(registered.Id);

            await File.WriteAllBytesAsync(path, Catalog("catalog", "v3-external", "203.0.113.30"));
            var reRegistered = await service.RegisterAsync(path);

            await reRegistered.CatalogVersion.Should().BeEqualTo("v3-external");
            await reRegistered.ActiveRevisionId.Should().BeEqualTo(string.Empty);

            var revisions = await service.ListRevisionsAsync(new ProviderAsnCatalogRevisionQuery
            {
                RegistryId = registered.Id,
                IncludeRolledBack = true,
            });
            await revisions.Count.Should().BeEqualTo(1);
            await revisions[0].Active.Should().BeFalse();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Test]
    public async Task UnregisterDiscardHistory_ShouldAllowDifferentCatalogIdentityOnSamePath()
    {
        var root = CreateTempDirectory();
        try
        {
            var path = Path.Combine(root, "catalog.json");
            var before = Catalog("catalog-a", "v1", "203.0.113.10");
            var after = Catalog("catalog-a", "v2", "203.0.113.20");
            await File.WriteAllBytesAsync(path, before);

            var store = new MemoryStore();
            var service = new ProviderAsnCatalogRegistryService(store);
            var registered = await service.RegisterAsync(path);
            var plan = await service.PrepareUpdateAsync(registered.Id, after);
            await service.ApplyUpdateAsync(registered.Id, plan);

            var receipt = await service.UnregisterAsync(
                registered.Id,
                new ProviderAsnCatalogUnregisterOptions { DiscardRevisionHistory = true });

            await receipt.RevisionHistoryDiscarded.Should().BeTrue();
            await receipt.RevisionCount.Should().BeEqualTo(1);
            await (await service.ListRevisionsAsync(new ProviderAsnCatalogRevisionQuery
            {
                RegistryId = registered.Id,
                IncludeRolledBack = true,
            })).Count.Should().BeEqualTo(0);

            await File.WriteAllBytesAsync(path, Catalog("catalog-b", "v1", "203.0.113.30"));
            var reRegistered = await service.RegisterAsync(path);

            await reRegistered.Id.Should().BeEqualTo(registered.Id);
            await reRegistered.CatalogId.Should().BeEqualTo("catalog-b");
            await reRegistered.ActiveRevisionId.Should().BeEqualTo(string.Empty);
            await reRegistered.Registered.Should().BeTrue();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Test]
    public async Task UnregisterPreservedHistory_ShouldBlockIdentityChangeUntilHistoryIsDiscarded()
    {
        var root = CreateTempDirectory();
        try
        {
            var path = Path.Combine(root, "catalog.json");
            await File.WriteAllBytesAsync(path, Catalog("catalog-a", "v1", "203.0.113.10"));

            var store = new MemoryStore();
            var service = new ProviderAsnCatalogRegistryService(store);
            var registered = await service.RegisterAsync(path);
            var plan = await service.PrepareUpdateAsync(
                registered.Id,
                Catalog("catalog-a", "v2", "203.0.113.20"));
            await service.ApplyUpdateAsync(registered.Id, plan);
            await service.UnregisterAsync(registered.Id);

            await File.WriteAllBytesAsync(path, Catalog("catalog-b", "v1", "203.0.113.30"));

            var threw = false;
            try
            {
                await service.RegisterAsync(path);
            }
            catch (InvalidOperationException)
            {
                threw = true;
            }

            await threw.Should().BeTrue();

            var discard = await service.DiscardRetiredRevisionHistoryAsync(registered.Id);
            await discard.RevisionHistoryDiscarded.Should().BeTrue();
            await discard.RevisionCount.Should().BeEqualTo(1);

            var reRegistered = await service.RegisterAsync(path);
            await reRegistered.Id.Should().BeEqualTo(registered.Id);
            await reRegistered.CatalogId.Should().BeEqualTo("catalog-b");
            await reRegistered.ActiveRevisionId.Should().BeEqualTo(string.Empty);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static string CreateTempDirectory()
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            "pattn-provider-registry-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static byte[] Catalog(string id, string version, string address)
        => Encoding.UTF8.GetBytes(
            $$"""
            {
              "schemaVersion":1,
              "id":"{{id}}",
              "version":"{{version}}",
              "source":"unit-test",
              "updatedAt":"2026-09-23T12:00:00Z",
              "entries":[
                {
                  "address":"{{address}}",
                  "sourceId":"edge-1",
                  "logicalHosts":["front.example"]
                }
              ]
            }
            """);

    private sealed class MemoryStore : IProviderAsnCatalogRegistryStore
    {
        private readonly Dictionary<string, ProviderAsnCatalogRegistryItem> _registry = new(StringComparer.Ordinal);
        private readonly Dictionary<string, ProviderAsnCatalogRevisionItem> _revisions = new(StringComparer.Ordinal);

        public bool FailUpsert { get; set; }

        public Task<IReadOnlyList<ProviderAsnCatalogRegistryItem>> ListAsync(
            ProviderAsnCatalogRegistryQuery? query = null,
            CancellationToken cancellationToken = default)
        {
            query ??= new ProviderAsnCatalogRegistryQuery();
            var rows = _registry.Values
                .Where(x => query.IncludeUnregistered || x.UnregisteredAtUnixMs is null)
                .Where(x => query.IncludeDisabled || x.Enabled)
                .OrderByDescending(x => x.UpdatedAtUnixMs)
                .Take(query.MaxItems)
                .ToArray();
            return Task.FromResult<IReadOnlyList<ProviderAsnCatalogRegistryItem>>(rows);
        }

        public Task<ProviderAsnCatalogRegistryItem?> GetAsync(
            string id,
            CancellationToken cancellationToken = default)
            => Task.FromResult(_registry.TryGetValue(id, out var value) ? value : null);

        public Task<ProviderAsnCatalogRegistryItem?> FindByPathAsync(
            string normalizedPath,
            CancellationToken cancellationToken = default)
            => Task.FromResult(
                _registry.Values.FirstOrDefault(
                    x => string.Equals(x.FilePath, normalizedPath, StringComparison.Ordinal)));

        public Task UpsertAsync(
            ProviderAsnCatalogRegistryItem item,
            CancellationToken cancellationToken = default)
        {
            if (FailUpsert)
            {
                throw new InvalidOperationException("registry persistence unavailable");
            }
            _registry[item.Id] = item;
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
            var revisions = _revisions.Values.Count(x => x.RegistryId == item.Id);
            _registry[item.Id] = item;
            if (discardRevisionHistory)
            {
                foreach (var id in _revisions.Values
                             .Where(x => x.RegistryId == item.Id)
                             .Select(x => x.Id)
                             .ToArray())
                {
                    _revisions.Remove(id);
                }
            }
            return Task.FromResult(revisions);
        }

        public Task<IReadOnlyList<ProviderAsnCatalogRevisionItem>> ListRevisionsAsync(
            ProviderAsnCatalogRevisionQuery? query = null,
            CancellationToken cancellationToken = default)
        {
            query ??= new ProviderAsnCatalogRevisionQuery();
            var rows = _revisions.Values
                .Where(x => query.RegistryId.IsNullOrEmpty() || x.RegistryId == query.RegistryId)
                .Where(x => query.IncludeRolledBack || x.RolledBackAtUnixMs is null)
                .OrderByDescending(x => x.AppliedAtUnixMs)
                .Take(query.MaxItems)
                .ToArray();
            return Task.FromResult<IReadOnlyList<ProviderAsnCatalogRevisionItem>>(rows);
        }

        public Task<ProviderAsnCatalogRevisionItem?> GetRevisionAsync(
            string id,
            CancellationToken cancellationToken = default)
            => Task.FromResult(_revisions.TryGetValue(id, out var value) ? value : null);

        public Task InsertRevisionAsync(
            ProviderAsnCatalogRevisionItem item,
            CancellationToken cancellationToken = default)
        {
            if (!_revisions.TryAdd(item.Id, item))
            {
                throw new InvalidOperationException("duplicate revision");
            }
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
