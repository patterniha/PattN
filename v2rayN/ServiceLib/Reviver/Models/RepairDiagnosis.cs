namespace ServiceLib.Reviver.Models;

public sealed record RepairDiagnosis
{
    public bool IsHealthy { get; init; }
    public ERepairFailureClass FailureClass { get; init; } = ERepairFailureClass.Unknown;
    public IReadOnlyList<ProfileInvariantViolationView> InvariantViolations { get; init; } = [];
    public IReadOnlyList<string> CoreValidationErrors { get; init; } = [];
    public IReadOnlyList<string> ResolvedAddresses { get; init; } = [];
    public RepairValidationEvidence? RuntimeValidation { get; init; }
    public IReadOnlyList<RepairEvidence> Evidence { get; init; } = [];
}

/// <summary>
/// Stable model-layer projection so callers do not need to depend on the normalization implementation type.
/// </summary>
public sealed record ProfileInvariantViolationView(string Code, string Message);

public sealed record RepairRunResult
{
    public required RepairSession Session { get; init; }
    public required RepairDiagnosis Diagnosis { get; init; }
    public IReadOnlyList<RepairCandidate> PlannedCandidates { get; init; } = [];
    public IReadOnlyList<RepairCandidate> ValidatedCandidates { get; init; } = [];
    public RepairCandidate? RecommendedCandidate { get; init; }
}
