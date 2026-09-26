using ServiceLib.Discovery.Protocol;
using ServiceLib.Discovery.Services;
using ServiceLib.Reviver.Models;

namespace ServiceLib.Reviver.Services;

/// <summary>
/// Projects Discovery's composite DNS repair diagnostic into Reviver evidence. Discovery owns DNS observation
/// and catalog semantics; Reviver owns whether those observations justify a bounded profile mutation.
/// </summary>
public sealed class DiscoveryDnsRepairEvidenceProvider(IDiscoveryDnsDiagnosticClient discovery) : IDnsRepairEvidenceProvider
{
    public async Task<DnsRepairObservation> InspectAsync(
        string host,
        CancellationToken cancellationToken = default)
    {
        host = host.Trim().TrimEnd('.');
        if (host.IsNullOrEmpty())
        {
            throw new ArgumentException("DNS repair host is required.", nameof(host));
        }

        var inspection = await discovery.InspectDnsRepairAsync(
            new DiscoveryDeepDnsRequest { Domain = host },
            cancellationToken);

        var recommendations = inspection.ResolverRecommendations
            .OrderByDescending(x => x.ReferenceEligible)
            .ThenBy(x => x.Policy, StringComparer.Ordinal)
            .ThenBy(x => x.Id, StringComparer.Ordinal)
            .Select(x => new DnsResolverRecommendation
            {
                CatalogId = x.Id,
                Provider = x.Provider,
                Name = x.Name,
                IPv4 = x.IPv4,
                IPv6 = x.IPv6,
                DotServerName = x.DotServerName,
                DotPort = x.DotPort,
                DohUrl = x.DohUrl,
                Policy = x.Policy,
                ReferenceEligible = x.ReferenceEligible,
            })
            .ToArray();

        return new DnsRepairObservation
        {
            Host = inspection.Domain.NullIfEmpty() ?? host,
            IPv4 = MapFamily(inspection.IPv4),
            IPv6 = MapFamily(inspection.IPv6),
            ResolverCatalogVersion = inspection.ResolverCatalogVersion,
            ResolverRecommendations = recommendations,
        };
    }

    private static DnsFamilyObservation MapFamily(DiscoveryDnsRepairFamilyResult family)
        => new()
        {
            Family = family.Family,
            Addresses = family.Trace.FinalAnswers
                .Where(x => x.Type == family.QueryType && !x.Address.IsNullOrEmpty())
                .Select(x => x.Address)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.Ordinal)
                .ToArray(),
            TraceComplete = family.Trace.Complete,
            DnssecAuthenticated = family.DnssecAuthenticated,
            DnssecStatus = family.DnssecStatus,
            Error = family.Error.NullIfEmpty() ?? family.Trace.Error,
        };
}
