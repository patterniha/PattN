using ServiceLib.Discovery.Models;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Explicit low-frequency endpoint-pool maintenance. History retention is owned separately by
/// LifecycleRetentionService so there is only one pruning path for append-only evidence.
/// </summary>
public sealed class EndpointMaintenanceService(
    IEndpointPoolStore pool,
    IEndpointPoolAdminStore admin)
{
    public async Task<EndpointMaintenancePlan> PreviewAsync(
        EndpointMaintenancePolicy? policy = null,
        DateTimeOffset? now = null,
        CancellationToken cancellationToken = default)
    {
        policy ??= new EndpointMaintenancePolicy();
        Validate(policy);
        cancellationToken.ThrowIfCancellationRequested();

        var createdAt = now ?? DateTimeOffset.UtcNow;
        var cutoff = createdAt
            .Subtract(policy.DisabledPoolRetention)
            .ToUnixTimeMilliseconds();

        var rows = await admin.ListAsync(
            new EndpointPoolQuery
            {
                IncludeDisabled = true,
                DisabledUnpinnedBeforeUnixMs = cutoff,
                OldestFirst = true,
                MaxItems = policy.MaximumPoolScanItems,
            },
            cancellationToken);

        var removable = rows
            .Take(policy.MaximumPoolRemovalsPerRun)
            .Select(x => new EndpointMaintenanceCandidate
            {
                Id = x.Id,
                LogicalHost = x.LogicalHost,
                Address = x.Address,
                UpdatedAtUnixMs = x.UpdatedAtUnixMs,
            })
            .ToArray();

        return new EndpointMaintenancePlan
        {
            CreatedAt = createdAt,
            Policy = policy,
            ScannedPoolEntries = rows.Count,
            DisabledPoolCutoffUnixMs = cutoff,
            PoolEntriesToRemove = removable,
        };
    }

    public async Task<EndpointMaintenanceResult> ApplyAsync(
        EndpointMaintenancePlan plan,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plan);
        Validate(plan.Policy);
        ValidatePlan(plan);
        cancellationToken.ThrowIfCancellationRequested();

        var currentRows = await admin.ListAsync(
            new EndpointPoolQuery
            {
                IncludeDisabled = true,
                DisabledUnpinnedBeforeUnixMs = plan.DisabledPoolCutoffUnixMs,
                OldestFirst = true,
                MaxItems = plan.Policy.MaximumPoolScanItems,
            },
            cancellationToken);
        var byId = currentRows.ToDictionary(x => x.Id, StringComparer.Ordinal);

        var removed = new List<string>();
        var skipped = new List<string>();
        foreach (var candidate in plan.PoolEntriesToRemove)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!byId.TryGetValue(candidate.Id, out var current)
                || current.UpdatedAtUnixMs != candidate.UpdatedAtUnixMs
                || !IsRemovable(
                    current.Enabled,
                    current.Pinned,
                    current.UpdatedAtUnixMs,
                    plan.DisabledPoolCutoffUnixMs))
            {
                skipped.Add(candidate.Id);
                continue;
            }

            await pool.RemoveAsync(candidate.Id, cancellationToken);
            removed.Add(candidate.Id);
        }

        return new EndpointMaintenanceResult
        {
            PlannedPoolEntries = plan.PoolEntriesToRemove.Count,
            RemovedPoolEntries = removed.Count,
            RemovedPoolEntryIds = removed,
            SkippedChangedPoolEntryIds = skipped,
        };
    }

    public async Task<EndpointMaintenanceResult> RunAsync(
        EndpointMaintenancePolicy? policy = null,
        DateTimeOffset? now = null,
        CancellationToken cancellationToken = default)
    {
        var plan = await PreviewAsync(policy, now, cancellationToken);
        return await ApplyAsync(plan, cancellationToken);
    }

    private static bool IsRemovable(
        bool enabled,
        bool pinned,
        long updatedAtUnixMs,
        long cutoffUnixMs)
        => !enabled
           && !pinned
           && updatedAtUnixMs > 0
           && updatedAtUnixMs < cutoffUnixMs;

    private static void ValidatePlan(EndpointMaintenancePlan plan)
    {
        if (plan.CreatedAt == default)
        {
            throw new InvalidOperationException("Endpoint maintenance plan is missing its creation timestamp.");
        }
        var expectedCutoff = plan.CreatedAt
            .Subtract(plan.Policy.DisabledPoolRetention)
            .ToUnixTimeMilliseconds();
        if (plan.DisabledPoolCutoffUnixMs != expectedCutoff)
        {
            throw new InvalidOperationException("Endpoint maintenance cutoff does not match the frozen plan policy.");
        }
        if (plan.PoolEntriesToRemove.Count > plan.Policy.MaximumPoolRemovalsPerRun)
        {
            throw new InvalidOperationException("Endpoint maintenance plan exceeds its removal budget.");
        }
        if (plan.PoolEntriesToRemove.Any(x => x.Id.IsNullOrEmpty())
            || plan.PoolEntriesToRemove.Select(x => x.Id).Distinct(StringComparer.Ordinal).Count()
               != plan.PoolEntriesToRemove.Count)
        {
            throw new InvalidOperationException("Endpoint maintenance plan contains invalid or duplicate entry IDs.");
        }
    }

    private static void Validate(EndpointMaintenancePolicy policy)
    {
        if (policy.DisabledPoolRetention <= TimeSpan.Zero
            || policy.DisabledPoolRetention > TimeSpan.FromDays(3650))
        {
            throw new ArgumentOutOfRangeException(nameof(policy.DisabledPoolRetention));
        }
        if (policy.MaximumPoolRemovalsPerRun is < 1 or > 10000)
        {
            throw new ArgumentOutOfRangeException(nameof(policy.MaximumPoolRemovalsPerRun));
        }
        if (policy.MaximumPoolScanItems is < 1 or > EndpointPoolQuery.MaximumItems)
        {
            throw new ArgumentOutOfRangeException(nameof(policy.MaximumPoolScanItems));
        }
    }
}
