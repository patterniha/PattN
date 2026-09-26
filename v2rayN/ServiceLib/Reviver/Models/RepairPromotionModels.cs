namespace ServiceLib.Reviver.Models;

public sealed record RepairPromotionPlan
{
    public required string SessionId { get; init; }
    public required string CandidateId { get; init; }
    public required string OriginalProfileId { get; init; }
    public required ProfileItem ChildProfile { get; init; }
    public required IReadOnlyList<RepairMutation> Mutations { get; init; }
    public RepairValidationEvidence? BaselineValidation { get; init; }
    public RepairValidationEvidence? Validation { get; init; }
    public RepairOutcomeComparison? OutcomeComparison { get; init; }
    public double? Score { get; init; }
}

public sealed record RepairPromotionReceipt
{
    public required string SessionId { get; init; }
    public required string CandidateId { get; init; }
    public required string OriginalProfileId { get; init; }
    public required string PromotedProfileId { get; init; }
    public string? PreviousDefaultProfileId { get; init; }
    public bool BecameDefault { get; init; }
    public DateTimeOffset PromotedAt { get; init; } = DateTimeOffset.UtcNow;
}
