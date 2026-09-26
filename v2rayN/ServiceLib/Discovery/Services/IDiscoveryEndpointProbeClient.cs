using ServiceLib.Discovery.Protocol;

namespace ServiceLib.Discovery.Services;

public interface IDiscoveryEndpointProbeClient
{
    Task<DiscoveryEndpointProbeResponse> ProbeEndpointsAsync(
        DiscoveryEndpointProbeRequest request,
        CancellationToken cancellationToken = default);
}
