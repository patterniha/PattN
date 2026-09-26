using ServiceLib.Discovery.Models;

namespace ServiceLib.Discovery.Services;

public sealed class EndpointHistoryCandidateSource(
    IEndpointHistoryStore history,
    EndpointHistoryPolicy? policy = null) : IDiscoveryCandidateSource
{
    private readonly EndpointHistoryPolicy _policy = policy ?? new EndpointHistoryPolicy();

    public async IAsyncEnumerable<DiscoveryEndpointCandidate> GetCandidatesAsync(
        DiscoveryCandidateRequest request,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!request.IncludeHistorical)
        {
            yield break;
        }

        var candidates = await history.GetHistoricallyGoodAsync(request, _policy, cancellationToken);
        foreach (var candidate in candidates)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return candidate;
        }
    }
}
