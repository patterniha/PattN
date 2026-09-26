using ServiceLib.Reviver.Models;

namespace ServiceLib.Reviver.Strategies;

public interface IRepairStrategy
{
    string Id { get; }
    ERepairConfidence Confidence { get; }
    int PriorityFor(ERepairFailureClass failureClass);

    bool CanApply(ProfileItem profile, ERepairFailureClass failureClass);

    IAsyncEnumerable<RepairCandidate> GenerateAsync(
        RepairSession session,
        ERepairFailureClass failureClass,
        CancellationToken cancellationToken = default);
}
