using ServiceLib.Discovery.Protocol;

namespace ServiceLib.Discovery.Services;

public interface IDiscoveryDnsDiagnosticClient
{
    Task<DiscoveryDnsRepairInspection> InspectDnsRepairAsync(
        DiscoveryDeepDnsRequest request,
        CancellationToken cancellationToken = default);
}
