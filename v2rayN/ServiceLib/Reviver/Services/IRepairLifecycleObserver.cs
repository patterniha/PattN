using ServiceLib.Reviver.Models;

namespace ServiceLib.Reviver.Services;

public interface IRepairLifecycleObserver
{
    Task CandidatePlannedAsync(
        RepairCandidate candidate,
        CancellationToken cancellationToken = default);

    Task CandidateValidatedAsync(
        RepairCandidate candidate,
        CancellationToken cancellationToken = default);
}
