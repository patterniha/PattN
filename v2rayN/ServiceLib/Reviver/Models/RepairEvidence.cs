namespace ServiceLib.Reviver.Models;

public sealed record RepairEvidence
{
    public required string Kind { get; init; }
    public required string Summary { get; init; }
    public string? Source { get; init; }
    public DateTimeOffset ObservedAt { get; init; } = DateTimeOffset.UtcNow;
    public IReadOnlyDictionary<string, string> Data { get; init; } = new Dictionary<string, string>();
}

public sealed record RepairValidationEvidence
{
    public int Attempts { get; init; }
    public int Successes { get; init; }
    public int ConsecutiveSuccesses { get; init; }
    public double? MedianLatencyMs { get; init; }
    public double? LossRate { get; init; }
    public double? ThroughputMbps { get; init; }
    public IReadOnlyList<ERepairFailureClass> Failures { get; init; } = [];

    public bool MeetsQuorum(int minimumSuccesses = 2)
        => Attempts > 0 && Successes >= minimumSuccesses;
}
