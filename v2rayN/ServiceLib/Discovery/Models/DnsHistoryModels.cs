namespace ServiceLib.Discovery.Models;

public sealed record DnsResolverTrendPoint
{
    public DateTimeOffset ObservedAt { get; init; }
    public string HealthClass { get; init; } = string.Empty;
    public string Quality { get; init; } = string.Empty;
    public double HealthScore { get; init; }
    public double Reliability { get; init; }
    public double? MedianLatencyMs { get; init; }
    public int QuorumTransportCount { get; init; }
    public bool InterceptionSuspected { get; init; }
    public string Error { get; init; } = string.Empty;
}

public sealed record DnsResolverTrend
{
    public string CatalogId { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    public string Provider { get; init; } = string.Empty;
    public IReadOnlyList<DnsResolverTrendPoint> Points { get; init; } = [];
    public string Direction { get; init; } = "insufficient";

    public DnsResolverTrendPoint? Latest => Points.FirstOrDefault();

    public string DisplayLine
    {
        get
        {
            var latest = Latest;
            if (latest is null)
            {
                return $"{Name}: no telemetry history";
            }
            var latency = latest.MedianLatencyMs is >= 0 ? $" · {latest.MedianLatencyMs:0.#} ms" : string.Empty;
            return $"{Name}: {Direction} · {Points.Count} samples · latest {latest.HealthClass} {latest.HealthScore:P0}{latency}";
        }
    }
}

public sealed record DnsHistoryEvent
{
    public DateTimeOffset ObservedAt { get; init; }
    public string Kind { get; init; } = string.Empty;
    public string Summary { get; init; } = string.Empty;

    public string DisplayLine
        => $"{ObservedAt.ToLocalTime():yyyy-MM-dd HH:mm:ss} · {Summary}";
}

public sealed record DnsHistorySnapshot
{
    public IReadOnlyList<DnsResolverTrend> ResolverTrends { get; init; } = [];
    public IReadOnlyList<DnsHistoryEvent> Events { get; init; } = [];
    public DateTimeOffset? NewestAt { get; init; }
}
