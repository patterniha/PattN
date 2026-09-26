using ServiceLib.Discovery.Services;
using ServiceLib.Reviver.Normalization;
using ServiceLib.Reviver.Services;

namespace ServiceLib.Reviver.Strategies;

/// <summary>
/// Canonical composition for PattN's built-in Reviver strategies. Ordering is not the final execution order:
/// ReviverService still sorts by failure-specific priority, confidence, and strategy ID.
/// </summary>
public static class ReviverStrategyCatalog
{
    public static IReadOnlyList<IRepairLifecycleObserver> CreateDefaultObservers(
        IDnsRepairHistoryStore? dnsHistory)
        => dnsHistory is null ? [] : [new DnsRepairHistoryObserver(dnsHistory)];

    public static IReadOnlyList<IRepairStrategy> CreateDefault(
        IDiscoveryCandidateProvider discoveryCandidates,
        IDnsRepairEvidenceProvider dnsRepairEvidence,
        ProfileCoreCompatibility? compatibility = null)
    {
        ArgumentNullException.ThrowIfNull(discoveryCandidates);
        ArgumentNullException.ThrowIfNull(dnsRepairEvidence);

        compatibility ??= new ProfileCoreCompatibility();
        return
        [
            new DnsAddressFamilyStrategy(dnsRepairEvidence, compatibility),
            new EndpointReplacementStrategy(discoveryCandidates),
            new CoreFallbackStrategy(compatibility),
        ];
    }
}
