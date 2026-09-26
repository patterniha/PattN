using ServiceLib.Discovery.Models;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Canonical composition for endpoint candidate discovery. Pool and history state only nominate physical
/// endpoints; Discovery always re-probes them with the profile's current logical identity before Reviver sees them.
/// </summary>
public static class DiscoveryCandidateComposition
{
    public static DiscoveryCandidateProvider CreateWithRegisteredProviderCatalogs(
        IDiscoveryEndpointProbeClient engine,
        IEndpointHistoryStore? historyStore = null,
        IEndpointPoolStore? poolStore = null,
        IProviderAsnCatalogRegistryStore? registryStore = null)
    {
        registryStore ??= new SqliteProviderAsnCatalogRegistryStore();
        var registry = new ProviderAsnCatalogRegistryService(registryStore);
        return CreateDefault(
            engine,
            historyStore,
            poolStore,
            new RegistryProviderAsnEndpointCatalog(registry));
    }

    public static DiscoveryCandidateProvider CreateDefault(
        IDiscoveryEndpointProbeClient engine,
        IEndpointHistoryStore? historyStore = null,
        IEndpointPoolStore? poolStore = null,
        IProviderAsnEndpointCatalog? providerCatalog = null)
    {
        ArgumentNullException.ThrowIfNull(engine);

        historyStore ??= new SqliteEndpointHistoryStore();
        poolStore ??= new SqliteEndpointPoolStore();

        var sources = new List<IDiscoveryCandidateSource>
        {
            new EndpointPoolCandidateSource(poolStore),
        };
        if (providerCatalog is not null)
        {
            var audit = providerCatalog is JsonProviderAsnEndpointCatalog jsonCatalog
                ? jsonCatalog.Audit()
                : null;
            sources.Add(new ProviderAsnCandidateSource(providerCatalog, audit: audit));
        }
        sources.Add(new DnsResolutionCandidateSource());
        sources.Add(new EndpointHistoryCandidateSource(historyStore));

        return new DiscoveryCandidateProvider(engine, sources, historyStore);
    }
}
