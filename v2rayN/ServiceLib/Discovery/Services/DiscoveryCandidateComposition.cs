using ServiceLib.Discovery.Models;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Canonical composition for endpoint candidate discovery without optional provider/ASN catalog sources.
/// Pool and history state only nominate physical endpoints; Discovery always re-probes them with the
/// profile's current logical identity before Reviver sees them.
/// </summary>
public static class DiscoveryCandidateComposition
{
    public static DiscoveryCandidateProvider CreateDefault(
        IDiscoveryEndpointProbeClient engine,
        IEndpointHistoryStore? historyStore = null,
        IEndpointPoolStore? poolStore = null)
    {
        ArgumentNullException.ThrowIfNull(engine);

        historyStore ??= new SqliteEndpointHistoryStore();
        poolStore ??= new SqliteEndpointPoolStore();

        IDiscoveryCandidateSource[] sources =
        [
            new EndpointPoolCandidateSource(poolStore),
            new DnsResolutionCandidateSource(),
            new EndpointHistoryCandidateSource(historyStore),
        ];

        return new DiscoveryCandidateProvider(engine, sources, historyStore);
    }
}
