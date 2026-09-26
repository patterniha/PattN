using ServiceLib.Discovery.Models;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Supplies candidate physical endpoints without owning PattN profile mutation. Sources may represent DNS,
/// endpoint pools, historical observations, curated provider datasets, or user input.
/// </summary>
public interface IDiscoveryCandidateSource
{
    IAsyncEnumerable<DiscoveryEndpointCandidate> GetCandidatesAsync(
        DiscoveryCandidateRequest request,
        CancellationToken cancellationToken = default);
}
