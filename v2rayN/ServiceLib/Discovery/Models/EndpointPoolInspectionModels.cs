namespace ServiceLib.Discovery.Models;

public sealed record EndpointPoolInspectionQuery
{
    public string? LogicalHost { get; init; }
    public bool IncludeDisabled { get; init; } = true;
    public int MaxItems { get; init; } = 100;
    public TimeSpan HistoryAge { get; init; } = TimeSpan.FromDays(30);
    public int HistoryPoints { get; init; } = 12;
    public EndpointHistoryPolicy HistoryPolicy { get; init; } = new();
}

public sealed record EndpointPoolInspectionRow
{
    public required string Id { get; init; }
    public required string LogicalHost { get; init; }
    public string HttpHost { get; init; } = string.Empty;
    public int Port { get; init; }
    public string Network { get; init; } = string.Empty;
    public string StreamSecurity { get; init; } = string.Empty;
    public required string Address { get; init; }
    public string Label { get; init; } = string.Empty;
    public bool Enabled { get; init; }
    public bool Pinned { get; init; }
    public string Provider { get; init; } = string.Empty;
    public string Asn { get; init; } = string.Empty;
    public string Pop { get; init; } = string.Empty;
    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset UpdatedAt { get; init; }
    public EndpointHistorySummary? History { get; init; }
    public EndpointHistoryPoint? LatestObservation { get; init; }
    public bool HistoricallyGood { get; init; }

    public string CurrentObservationState
        => LatestObservation is null
            ? "unknown"
            : LatestObservation.Qualified
                ? "qualified"
                : "failed";
}
