namespace ServiceLib.Discovery.Models;

public sealed record EndpointHistoryPolicy
{
    public TimeSpan HistoryWindow { get; init; } = TimeSpan.FromDays(30);
    public TimeSpan HalfLife { get; init; } = TimeSpan.FromDays(7);
    public int MinimumQualifiedObservations { get; init; } = 2;
    public int MaximumRecentFailureStreak { get; init; } = 1;
    public double MinimumDecayedReliability { get; init; } = 0.67d;
    public int MaximumCandidates { get; init; } = 16;
}

public sealed record EndpointHistorySummary
{
    public required string Address { get; init; }
    public int Samples { get; init; }
    public int QualifiedObservations { get; init; }
    public int RecentFailureStreak { get; init; }
    public double DecayedReliability { get; init; }
    public double? DecayedLatencyMs { get; init; }
    public DateTimeOffset LastObservedAt { get; init; }
    public string Provider { get; init; } = string.Empty;
    public string Asn { get; init; } = string.Empty;
    public string Pop { get; init; } = string.Empty;

    public bool IsHistoricallyGood(EndpointHistoryPolicy policy)
        => QualifiedObservations >= policy.MinimumQualifiedObservations
           && RecentFailureStreak <= policy.MaximumRecentFailureStreak
           && DecayedReliability >= policy.MinimumDecayedReliability;
}
