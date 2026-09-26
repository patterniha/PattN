using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;
using ServiceLib.Reviver.Models;
using ServiceLib.Reviver.Normalization;

namespace ServiceLib.Reviver.Strategies;

/// <summary>
/// Replaces only the physical dial endpoint. Logical protocol identity (SNI, Host, path, credentials,
/// Reality fields, ALPN, fingerprint, and protocol/transport extras) remains untouched.
/// </summary>
public sealed class EndpointReplacementStrategy(IDiscoveryCandidateProvider discovery) : IRepairStrategy
{
    public string Id => "endpoint-replacement";
    public ERepairConfidence Confidence => ERepairConfidence.EvidenceBacked;

    public int PriorityFor(ERepairFailureClass failureClass) => failureClass switch
    {
        ERepairFailureClass.DnsResolutionFailure => 0,
        ERepairFailureClass.NoUsableAddressFamily => 1,
        ERepairFailureClass.NetworkUnreachable => 2,
        ERepairFailureClass.ConnectionRefused => 3,
        ERepairFailureClass.ConnectionTimeout => 4,
        ERepairFailureClass.IntermittentFailure => 10,
        ERepairFailureClass.PerformanceDegraded => 20,
        _ => 1000,
    };

    public bool CanApply(ProfileItem profile, ERepairFailureClass failureClass)
        => !profile.IsComplex()
           && profile.ConfigType != EConfigType.Outbound
           && PriorityFor(failureClass) < 1000;

    public async IAsyncEnumerable<RepairCandidate> GenerateAsync(
        RepairSession session,
        ERepairFailureClass failureClass,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var baseline = session.Original.CreateWorkingCopy();
        if (!CanApply(baseline, failureClass))
        {
            yield break;
        }

        var logicalHost = ProfileIdentityResolver.ResolveServerName(baseline);
        var httpHost = ProfileIdentityResolver.ResolveHttpHost(baseline);

        var request = new DiscoveryCandidateRequest
        {
            OriginalAddress = baseline.Address,
            OriginalPort = baseline.Port,
            LogicalHost = logicalHost,
            HttpHost = httpHost,
            Network = baseline.Network,
            StreamSecurity = baseline.StreamSecurity,
        };

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var baselineAddress = NormalizeEndpointAddress(baseline.Address);
        await foreach (var endpoint in discovery.GetCandidatesAsync(request, cancellationToken).WithCancellation(cancellationToken))
        {
            var address = NormalizeEndpointAddress(endpoint.Address);
            if (address.IsNullOrEmpty() || address.Equals(baselineAddress, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            // Endpoint replacement is intentionally address-only in the first reviver stage. An alternate
            // remote port is a separate mutation and requires stronger evidence that the service listens there.
            if (!seen.Add(address))
            {
                continue;
            }

            var candidate = session.Original.CreateWorkingCopy();
            candidate.Address = address;
            if (!ProfileMutationGuard.ChangesOnly(baseline, candidate, nameof(ProfileItem.Address)))
            {
                throw new InvalidOperationException("Endpoint replacement modified fields outside the physical address.");
            }

            var evidenceData = new Dictionary<string, string>();
            if (endpoint.LatencyMs is not null)
            {
                evidenceData["latencyMs"] = endpoint.LatencyMs.Value.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture);
            }
            if (endpoint.Reliability is not null)
            {
                evidenceData["reliability"] = endpoint.Reliability.Value.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture);
            }
            if (!endpoint.Provider.IsNullOrEmpty())
            {
                evidenceData["provider"] = endpoint.Provider;
            }
            if (!endpoint.Asn.IsNullOrEmpty())
            {
                evidenceData["asn"] = endpoint.Asn;
            }
            if (!endpoint.Pop.IsNullOrEmpty())
            {
                evidenceData["pop"] = endpoint.Pop;
            }

            foreach (var key in new[]
                     {
                         "pinned",
                         "historical",
                         "sources",
                         "probeQualified",
                         "historySamples",
                         "historyQualified",
                         "historyFailureStreak",
                         "historyReliability",
                         "historyLastObservedAt",
                     })
            {
                if (endpoint.Metadata.TryGetValue(key, out var value) && !value.IsNullOrEmpty())
                {
                    evidenceData[key] = value;
                }
            }

            yield return new RepairCandidate
            {
                SessionId = session.Id,
                Profile = candidate,
                FailureClassAddressed = failureClass,
                Mutations =
                [
                    new RepairMutation
                    {
                        Kind = ERepairMutationKind.ReplaceEndpoint,
                        Field = nameof(ProfileItem.Address),
                        From = baseline.Address,
                        To = address,
                        Reason = "Discovery observed an alternate physical endpoint; logical profile identity is preserved.",
                        Confidence = ERepairConfidence.EvidenceBacked,
                    }
                ],
                Evidence =
                [
                    new RepairEvidence
                    {
                        Kind = "discovery.endpoint",
                        Summary = $"Discovery candidate {address}:{baseline.Port}",
                        Source = endpoint.Source,
                        ObservedAt = endpoint.ObservedAt,
                        Data = evidenceData,
                    }
                ],
            };
        }
    }

    private static string NormalizeEndpointAddress(string value)
        => DiscoveryEndpointAddress.NormalizeIfLiteral(value);
}
