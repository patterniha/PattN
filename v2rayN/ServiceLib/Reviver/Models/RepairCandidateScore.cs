namespace ServiceLib.Reviver.Models;

/// <summary>
/// Explainable score components for a candidate that already passed runtime validation.
/// Components are normalized to 0..1; Overall is exposed as 0..100 for UI use.
/// </summary>
public sealed record RepairCandidateScore
{
    public double Overall { get; init; }
    public double Reliability { get; init; }
    public double Stability { get; init; }
    public double LossQuality { get; init; }
    public double LatencyQuality { get; init; }
    public double MutationSafety { get; init; }
    public double MutationSimplicity { get; init; }
    public double ResolverQuality { get; init; }
}
