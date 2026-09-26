namespace ServiceLib.Discovery.Models;

public sealed record EndpointHistoryPoint
{
    public DateTimeOffset ObservedAt { get; init; }
    public bool Qualified { get; init; }
    public int Attempts { get; init; }
    public int Successes { get; init; }
    public int ConsecutiveSuccesses { get; init; }
    public double Reliability { get; init; }
    public double? MedianLatencyMs { get; init; }
    public string Source { get; init; } = string.Empty;
    public string Provider { get; init; } = string.Empty;
    public string Asn { get; init; } = string.Empty;
    public string Pop { get; init; } = string.Empty;
    public IReadOnlyList<string> Errors { get; init; } = [];
}

public sealed record EndpointHistoryDetail
{
    public required string LogicalHost { get; init; }
    public int Port { get; init; }
    public string Network { get; init; } = string.Empty;
    public string StreamSecurity { get; init; } = string.Empty;
    public required string Address { get; init; }
    public IReadOnlyList<EndpointHistoryPoint> Points { get; init; } = [];
    public EndpointHistorySummary? Summary { get; init; }
}
