using ServiceLib.Discovery.Models;

namespace ServiceLib.Discovery.Services;

public interface IEndpointHistoryQueryService
{
    Task<EndpointHistoryDetail> GetAsync(
        DiscoveryCandidateRequest request,
        string address,
        TimeSpan? maxAge = null,
        int maxPoints = 50,
        CancellationToken cancellationToken = default);
}
