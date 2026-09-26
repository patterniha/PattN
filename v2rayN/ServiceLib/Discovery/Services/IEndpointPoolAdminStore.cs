using ServiceLib.Discovery.Models;
using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

public interface IEndpointPoolAdminStore
{
    Task<IReadOnlyList<EndpointPoolItem>> ListAsync(
        EndpointPoolQuery? query = null,
        CancellationToken cancellationToken = default);

    Task<EndpointPoolItem?> UpdateAsync(
        EndpointPoolUpdate update,
        CancellationToken cancellationToken = default);
}
