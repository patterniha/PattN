using ServiceLib.Discovery.Models;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Narrow seam between Reviver and Discovery. Implementations may use pattn-discovery RPC, endpoint pools,
/// historical observations, or a deterministic test provider.
/// </summary>
public interface IDiscoveryCandidateProvider
{
    IAsyncEnumerable<DiscoveryEndpointCandidate> GetCandidatesAsync(
        DiscoveryCandidateRequest request,
        CancellationToken cancellationToken = default);
}
