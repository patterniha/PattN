namespace ServiceLib.Reviver.Models;

public sealed record RepairMutation
{
    public required ERepairMutationKind Kind { get; init; }
    public required string Field { get; init; }
    public string? From { get; init; }
    public string? To { get; init; }
    public required string Reason { get; init; }
    public ERepairConfidence Confidence { get; init; } = ERepairConfidence.LowRisk;
}
