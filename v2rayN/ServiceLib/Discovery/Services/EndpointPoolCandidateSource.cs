using ServiceLib.Discovery.Models;

namespace ServiceLib.Discovery.Services;

public sealed class EndpointPoolCandidateSource(
    IEndpointPoolStore pool,
    int maxCandidates = 32) : IDiscoveryCandidateSource
{
    public async IAsyncEnumerable<DiscoveryEndpointCandidate> GetCandidatesAsync(
        DiscoveryCandidateRequest request,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!request.IncludeEndpointPools)
        {
            yield break;
        }

        var candidates = await pool.GetCandidatesAsync(
            request,
            Math.Min(Math.Max(1, maxCandidates), Math.Max(1, request.MaxCandidates * 2)),
            cancellationToken);
        foreach (var candidate in candidates)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return candidate;
        }
    }
}
