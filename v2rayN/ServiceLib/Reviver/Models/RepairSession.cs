namespace ServiceLib.Reviver.Models;

public sealed class RepairSession
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public required ProfileSnapshot Original { get; init; }
    public DateTimeOffset StartedAt { get; init; } = DateTimeOffset.UtcNow;
    public ERepairFailureClass BaselineFailure { get; set; } = ERepairFailureClass.Unknown;
    public RepairValidationEvidence? BaselineValidation { get; set; }
    public List<RepairCandidate> Candidates { get; } = [];
}
