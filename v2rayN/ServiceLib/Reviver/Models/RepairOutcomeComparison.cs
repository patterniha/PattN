namespace ServiceLib.Reviver.Models;

public sealed record RepairOutcomeComparison
{
    public bool BaselineAvailable { get; init; }
    public double? BaselineReliability { get; init; }
    public double CandidateReliability { get; init; }
    public double? ReliabilityDelta { get; init; }
    public double? BaselineMedianLatencyMs { get; init; }
    public double? CandidateMedianLatencyMs { get; init; }
    public double? LatencyDeltaMs { get; init; }
    public double? BaselineLossRate { get; init; }
    public double? CandidateLossRate { get; init; }
    public double? LossDelta { get; init; }
    public string Verdict { get; init; } = "unknown";
    public IReadOnlyList<string> Reasons { get; init; } = [];
}
