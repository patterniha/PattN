namespace ServiceLib.Reviver.Models;

public sealed record RepairPromotionHistoryQuery
{
    public string? ProfileId { get; init; }
    public string? SessionId { get; init; }
    public string? CandidateId { get; init; }
    public string? EventKind { get; init; }
    public TimeSpan MaxAge { get; init; } = TimeSpan.FromDays(180);
    public int MaxItems { get; init; } = 200;
}

public sealed record RepairPromotionHistoryEntry
{
    public required string Id { get; init; }
    public required string EventKind { get; init; }
    public string SessionId { get; init; } = string.Empty;
    public string CandidateId { get; init; } = string.Empty;
    public string OriginalProfileId { get; init; } = string.Empty;
    public string PromotedProfileId { get; init; } = string.Empty;
    public string PreviousDefaultProfileId { get; init; } = string.Empty;
    public bool BecameDefault { get; init; }
    public double? Score { get; init; }
    public string OutcomeVerdict { get; init; } = "unknown";
    public IReadOnlyList<RepairMutation> Mutations { get; init; } = [];
    public RepairValidationEvidence? BaselineValidation { get; init; }
    public RepairValidationEvidence? CandidateValidation { get; init; }
    public RepairOutcomeComparison? OutcomeComparison { get; init; }
    public DateTimeOffset ObservedAt { get; init; }
}

public sealed record RepairPromotionHistorySummary
{
    public int TotalEvents { get; init; }
    public int Promotions { get; init; }
    public int Rollbacks { get; init; }
    public int Improved { get; init; }
    public int Stable { get; init; }
    public int Regressed { get; init; }
    public int Unknown { get; init; }
    public DateTimeOffset? LatestEventAt { get; init; }
    public IReadOnlyList<RepairPromotionHistoryEntry> Entries { get; init; } = [];
}
