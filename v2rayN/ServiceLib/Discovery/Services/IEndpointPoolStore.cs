using ServiceLib.Discovery.Models;
using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

public interface IEndpointPoolStore
{
    Task<IReadOnlyList<DiscoveryEndpointCandidate>> GetCandidatesAsync(
        DiscoveryCandidateRequest request,
        int maxCandidates,
        CancellationToken cancellationToken = default);

    Task<EndpointPoolItem> UpsertAsync(
        DiscoveryCandidateRequest request,
        DiscoveryEndpointCandidate candidate,
        bool pinned = false,
        string? label = null,
        CancellationToken cancellationToken = default);

    Task RemoveAsync(
        string id,
        CancellationToken cancellationToken = default);
}
