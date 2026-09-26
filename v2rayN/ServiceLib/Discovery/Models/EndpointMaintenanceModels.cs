namespace ServiceLib.Discovery.Models;

public sealed record EndpointMaintenancePolicy
{
    public TimeSpan DisabledPoolRetention { get; init; } = TimeSpan.FromDays(180);
    public int MaximumPoolRemovalsPerRun { get; init; } = 100;
    public int MaximumPoolScanItems { get; init; } = 2000;
}

public sealed record EndpointMaintenanceCandidate
{
    public required string Id { get; init; }
    public string LogicalHost { get; init; } = string.Empty;
    public string Address { get; init; } = string.Empty;
    public long UpdatedAtUnixMs { get; init; }
}

public sealed record EndpointMaintenancePlan
{
    public DateTimeOffset CreatedAt { get; init; }
    public EndpointMaintenancePolicy Policy { get; init; } = new();
    public int ScannedPoolEntries { get; init; }
    public long DisabledPoolCutoffUnixMs { get; init; }
    public IReadOnlyList<EndpointMaintenanceCandidate> PoolEntriesToRemove { get; init; } = [];
}

public sealed record EndpointMaintenanceResult
{
    public int PlannedPoolEntries { get; init; }
    public int RemovedPoolEntries { get; init; }
    public IReadOnlyList<string> RemovedPoolEntryIds { get; init; } = [];
    public IReadOnlyList<string> SkippedChangedPoolEntryIds { get; init; } = [];
}
