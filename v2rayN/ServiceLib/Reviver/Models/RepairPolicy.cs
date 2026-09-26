namespace ServiceLib.Reviver.Models;

/// <summary>
/// Hard bounds for repair planning. Reviver is intentionally a constrained search, never a Cartesian fuzzer.
/// </summary>
public sealed record RepairPolicy
{
    public int MaxCandidates { get; init; } = 32;
    public int MaxCandidatesPerStrategy { get; init; } = 8;
    public int RuntimeAttempts { get; init; } = 3;
    public int MinimumRuntimeSuccesses { get; init; } = 2;
    public ERepairConfidence MaximumAutomaticConfidence { get; init; } = ERepairConfidence.EvidenceBacked;
    public bool AllowSpeculative { get; init; }

    public bool Allows(ERepairConfidence confidence)
        => confidence <= MaximumAutomaticConfidence || (AllowSpeculative && confidence == ERepairConfidence.Speculative);
}
