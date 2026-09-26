namespace ServiceLib.Reviver.Models;

public sealed class RepairCandidate
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public required string SessionId { get; init; }
    public required ProfileItem Profile { get; init; }
    public required IReadOnlyList<RepairMutation> Mutations { get; init; }
    public IReadOnlyList<RepairEvidence> Evidence { get; init; } = [];
    public ERepairFailureClass FailureClassAddressed { get; init; } = ERepairFailureClass.Unknown;
    public ERepairCandidateState State { get; set; } = ERepairCandidateState.Planned;
    public RepairValidationEvidence? Validation { get; set; }
    public double? Score { get; set; }
    public RepairCandidateScore? ScoreBreakdown { get; set; }
}
