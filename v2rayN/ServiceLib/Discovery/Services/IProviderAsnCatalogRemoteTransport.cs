using ServiceLib.Discovery.Models;

namespace ServiceLib.Discovery.Services;

public interface IProviderAsnCatalogRemoteTransport
{
    Task<ProviderAsnCatalogRemoteTransportResponse> FetchAsync(
        ProviderAsnCatalogRemoteTransportRequest request,
        CancellationToken cancellationToken = default);
}
