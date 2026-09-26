namespace ServiceLib.Discovery.Models;

public sealed record LifecycleRetentionPolicy
{
    public TimeSpan DnsRepairHistoryRetention { get; init; } = TimeSpan.FromDays(180);
    public TimeSpan ResolverTelemetryRetention { get; init; } = TimeSpan.FromDays(90);
    public TimeSpan PromotionHistoryRetention { get; init; } = TimeSpan.FromDays(365);
    public TimeSpan EndpointObservationRetention { get; init; } = TimeSpan.FromDays(90);
    public TimeSpan RemoteCatalogProvenanceRetention { get; init; } = TimeSpan.FromDays(730);
    public TimeSpan RemoteSourceRevisionRetention { get; init; } = TimeSpan.FromDays(730);
    public int MaximumDeletesPerTable { get; init; } = 5000;
}

public sealed record LifecycleRetentionTablePlan
{
    public required string Table { get; init; }
    public long CutoffUnixMs { get; init; }
    public IReadOnlyList<string> CandidateIds { get; init; } = [];
    public int CandidateCount => CandidateIds.Count;
}

public sealed record LifecycleRetentionPlan
{
    public DateTimeOffset CreatedAt { get; init; }
    public LifecycleRetentionPolicy Policy { get; init; } = new();
    public IReadOnlyList<LifecycleRetentionTablePlan> Tables { get; init; } = [];
    public int TotalCandidates => Tables.Sum(x => x.CandidateCount);
}

public sealed record LifecycleRetentionTableResult
{
    public required string Table { get; init; }
    public int Planned { get; init; }
    public int Deleted { get; init; }
    public int AlreadyMissing { get; init; }
}

public sealed record LifecycleRetentionResult
{
    public int Planned { get; init; }
    public int Deleted { get; init; }
    public int AlreadyMissing { get; init; }
    public IReadOnlyList<LifecycleRetentionTableResult> Tables { get; init; } = [];
}
