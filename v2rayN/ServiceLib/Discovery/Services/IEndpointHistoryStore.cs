using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Protocol;

namespace ServiceLib.Discovery.Services;

public interface IEndpointHistoryStore
{
    Task RecordProbeAsync(
        DiscoveryCandidateRequest request,
        DiscoveryEndpointCandidate sourceCandidate,
        DiscoveryEndpointProbeResult observation,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<DiscoveryEndpointCandidate>> GetHistoricallyGoodAsync(
        DiscoveryCandidateRequest request,
        EndpointHistoryPolicy? policy = null,
        CancellationToken cancellationToken = default);

    Task PruneAsync(
        TimeSpan maxAge,
        CancellationToken cancellationToken = default);
}
