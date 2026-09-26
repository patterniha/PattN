using ServiceLib.Reviver.Models;

namespace ServiceLib.Reviver.Services;

public interface IDnsRepairHistoryStore
{
    Task RecordObservationAsync(
        string profileId,
        string sessionId,
        DnsRepairObservation observation,
        CancellationToken cancellationToken = default);

    Task RecordCandidateAsync(
        RepairCandidate candidate,
        CancellationToken cancellationToken = default);

    Task<DnsRepairHistorySummary> SummarizeAsync(
        string host,
        TimeSpan? maxAge = null,
        CancellationToken cancellationToken = default);

    Task PruneAsync(
        TimeSpan maxAge,
        CancellationToken cancellationToken = default);
}
