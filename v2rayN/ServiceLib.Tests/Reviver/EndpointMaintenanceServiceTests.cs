using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;
using ServiceLib.Models.Entities;

namespace ServiceLib.Tests.Reviver;

public class EndpointMaintenanceServiceTests
{
    [Test]
    public async Task Run_ShouldRemoveOnlyOldDisabledUnpinnedEntries()
    {
        var now = new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero);
        var store = new FakePoolStore(
        [
            Item("old-disabled", now.AddDays(-200), enabled: false, pinned: false),
            Item("old-pinned", now.AddDays(-300), enabled: false, pinned: true),
            Item("old-enabled", now.AddDays(-300), enabled: true, pinned: false),
            Item("recent-disabled", now.AddDays(-30), enabled: false, pinned: false),
        ]);

        var result = await new EndpointMaintenanceService(store, store).RunAsync(
            new EndpointMaintenancePolicy
            {
                DisabledPoolRetention = TimeSpan.FromDays(180),
                MaximumPoolRemovalsPerRun = 10,
                MaximumPoolScanItems = 100,
            },
            now);

        await result.RemovedPoolEntries.Should().BeEqualTo(1);
        await result.RemovedPoolEntryIds[0].Should().BeEqualTo("old-disabled");
        await store.Removed.SequenceEqual(["old-disabled"]).Should().BeTrue();
    }

    [Test]
    public async Task Run_ShouldBoundPoolRemovalCountOldestFirst()
    {
        var now = new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero);
        var store = new FakePoolStore(
        [
            Item("newer", now.AddDays(-200), false, false),
            Item("oldest", now.AddDays(-400), false, false),
            Item("middle", now.AddDays(-300), false, false),
        ]);

        var result = await new EndpointMaintenanceService(store, store).RunAsync(
            new EndpointMaintenancePolicy
            {
                DisabledPoolRetention = TimeSpan.FromDays(180),
                MaximumPoolRemovalsPerRun = 2,
                MaximumPoolScanItems = 100,
            },
            now);

        await result.RemovedPoolEntryIds.SequenceEqual(["oldest", "middle"]).Should().BeTrue();
    }

    [Test]
    public async Task Preview_ShouldNotMutatePool()
    {
        var now = new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero);
        var store = new FakePoolStore(
        [
            Item("old-disabled", now.AddDays(-200), enabled: false, pinned: false),
        ]);

        var plan = await new EndpointMaintenanceService(store, store).PreviewAsync(
            new EndpointMaintenancePolicy
            {
                DisabledPoolRetention = TimeSpan.FromDays(180),
                MaximumPoolRemovalsPerRun = 10,
                MaximumPoolScanItems = 100,
            },
            now);

        await plan.PoolEntriesToRemove.Count.Should().BeEqualTo(1);
        await plan.PoolEntriesToRemove[0].Id.Should().BeEqualTo("old-disabled");
        await store.Removed.Count.Should().BeEqualTo(0);
    }

    [Test]
    public async Task Apply_ShouldSkipEntryChangedAfterPreview()
    {
        var now = new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero);
        var store = new FakePoolStore(
        [
            Item("old-disabled", now.AddDays(-200), enabled: false, pinned: false),
        ]);
        var service = new EndpointMaintenanceService(store, store);

        var plan = await service.PreviewAsync(
            new EndpointMaintenancePolicy
            {
                DisabledPoolRetention = TimeSpan.FromDays(180),
                MaximumPoolRemovalsPerRun = 10,
                MaximumPoolScanItems = 100,
            },
            now);

        var current = store.Items.Single(x => x.Id == "old-disabled");
        current.Pinned = true;
        current.UpdatedAtUnixMs = now.AddMinutes(1).ToUnixTimeMilliseconds();

        var result = await service.ApplyAsync(plan);

        await result.PlannedPoolEntries.Should().BeEqualTo(1);
        await result.RemovedPoolEntries.Should().BeEqualTo(0);
        await result.SkippedChangedPoolEntryIds.SequenceEqual(["old-disabled"]).Should().BeTrue();
        await store.Removed.Count.Should().BeEqualTo(0);
    }

    [Test]
    public async Task Apply_ShouldRejectTamperedCutoffBeforeMutatingPool()
    {
        var now = new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero);
        var store = new FakePoolStore(
        [
            Item("old-disabled", now.AddDays(-200), enabled: false, pinned: false),
        ]);
        var service = new EndpointMaintenanceService(store, store);
        var valid = await service.PreviewAsync(
            new EndpointMaintenancePolicy
            {
                DisabledPoolRetention = TimeSpan.FromDays(180),
                MaximumPoolRemovalsPerRun = 10,
                MaximumPoolScanItems = 100,
            },
            now);
        var tampered = valid with
        {
            DisabledPoolCutoffUnixMs = now.AddDays(30).ToUnixTimeMilliseconds(),
        };

        var threw = false;
        try
        {
            await service.ApplyAsync(tampered);
        }
        catch (InvalidOperationException)
        {
            threw = true;
        }

        await threw.Should().BeTrue();
        await store.Removed.Count.Should().BeEqualTo(0);
    }

    [Test]
    public async Task Preview_ShouldFilterOldDisabledRowsBeforeApplyingScanLimit()
    {
        var now = new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero);
        var store = new FakePoolStore(
        [
            Item("recent-1", now.AddDays(-1), enabled: true, pinned: false),
            Item("recent-2", now.AddDays(-2), enabled: true, pinned: false),
            Item("recent-3", now.AddDays(-3), enabled: false, pinned: false),
            Item("oldest", now.AddDays(-400), enabled: false, pinned: false),
            Item("old", now.AddDays(-300), enabled: false, pinned: false),
        ]);

        var plan = await new EndpointMaintenanceService(store, store).PreviewAsync(
            new EndpointMaintenancePolicy
            {
                DisabledPoolRetention = TimeSpan.FromDays(180),
                MaximumPoolRemovalsPerRun = 2,
                MaximumPoolScanItems = 2,
            },
            now);

        await plan.PoolEntriesToRemove.Select(x => x.Id)
            .SequenceEqual(["oldest", "old"])
            .Should().BeTrue();
    }

    private static EndpointPoolItem Item(string id, DateTimeOffset updated, bool enabled, bool pinned)
        => new()
        {
            Id = id,
            LogicalHost = "front.example",
            Port = 443,
            Address = "203.0.113.10",
            Enabled = enabled,
            Pinned = pinned,
            UpdatedAtUnixMs = updated.ToUnixTimeMilliseconds(),
        };

    private sealed class FakePoolStore(
        IReadOnlyList<EndpointPoolItem> items) : IEndpointPoolStore, IEndpointPoolAdminStore
    {
        public List<EndpointPoolItem> Items { get; } = items.ToList();
        public List<string> Removed { get; } = [];

        public Task<IReadOnlyList<DiscoveryEndpointCandidate>> GetCandidatesAsync(
            DiscoveryCandidateRequest request,
            int maxCandidates,
            CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<DiscoveryEndpointCandidate>>([]);

        public Task<EndpointPoolItem> UpsertAsync(
            DiscoveryCandidateRequest request,
            DiscoveryEndpointCandidate candidate,
            bool pinned = false,
            string? label = null,
            CancellationToken cancellationToken = default)
            => Task.FromResult(new EndpointPoolItem());

        public Task RemoveAsync(string id, CancellationToken cancellationToken = default)
        {
            Removed.Add(id);
            Items.RemoveAll(x => x.Id == id);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<EndpointPoolItem>> ListAsync(
            EndpointPoolQuery? query = null,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            query ??= new EndpointPoolQuery();

            IEnumerable<EndpointPoolItem> rows = Items;
            if (!string.IsNullOrWhiteSpace(query.LogicalHost))
            {
                rows = rows.Where(x => string.Equals(x.LogicalHost, query.LogicalHost, StringComparison.OrdinalIgnoreCase));
            }
            if (!query.IncludeDisabled)
            {
                rows = rows.Where(x => x.Enabled);
            }
            if (query.DisabledUnpinnedBeforeUnixMs is long cutoff)
            {
                rows = rows.Where(x => !x.Enabled
                                       && !x.Pinned
                                       && x.UpdatedAtUnixMs > 0
                                       && x.UpdatedAtUnixMs < cutoff);
            }

            rows = query.OldestFirst
                ? rows.OrderBy(x => x.UpdatedAtUnixMs).ThenBy(x => x.Id, StringComparer.Ordinal)
                : rows.OrderByDescending(x => x.UpdatedAtUnixMs);

            return Task.FromResult<IReadOnlyList<EndpointPoolItem>>(
                rows.Take(query.MaxItems).ToArray());
        }

        public Task<EndpointPoolItem?> UpdateAsync(
            EndpointPoolUpdate update,
            CancellationToken cancellationToken = default)
            => Task.FromResult<EndpointPoolItem?>(Items.FirstOrDefault(x => x.Id == update.Id));
    }
}
