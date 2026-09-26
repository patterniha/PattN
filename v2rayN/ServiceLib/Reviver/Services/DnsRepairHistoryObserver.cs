using ServiceLib.Reviver.Models;

namespace ServiceLib.Reviver.Services;

public sealed class DnsRepairHistoryObserver(IDnsRepairHistoryStore history) : IRepairLifecycleObserver
{
    public Task CandidatePlannedAsync(
        RepairCandidate candidate,
        CancellationToken cancellationToken = default)
        => Task.CompletedTask;

    public Task CandidateValidatedAsync(
        RepairCandidate candidate,
        CancellationToken cancellationToken = default)
        => history.RecordCandidateAsync(candidate, cancellationToken);
}
