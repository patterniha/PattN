using ServiceLib.Reviver.Models;
using ServiceLib.Reviver.Normalization;
using ServiceLib.Reviver.Services;

namespace ServiceLib.Reviver.Strategies;

/// <summary>
/// Repairs local endpoint-name resolution by constraining Xray's per-profile targetStrategy from authoritative
/// A/AAAA evidence. It never changes logical TLS/HTTP identity and never edits global DNS configuration.
/// </summary>
public sealed class DnsAddressFamilyStrategy(
    IDnsRepairEvidenceProvider evidenceProvider,
    ProfileCoreCompatibility compatibility,
    IDnsRepairHistoryStore? historyStore = null) : IRepairStrategy
{
    public string Id => "dns-address-family";
    public ERepairConfidence Confidence => ERepairConfidence.EvidenceBacked;

    public int PriorityFor(ERepairFailureClass failureClass) => failureClass switch
    {
        ERepairFailureClass.DnsResolutionFailure => 0,
        ERepairFailureClass.NoUsableAddressFamily => 0,
        _ => 1000,
    };

    public bool CanApply(ProfileItem profile, ERepairFailureClass failureClass)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var host = profile.Address.Trim().Trim('[', ']');
        return PriorityFor(failureClass) < 1000
               && !profile.IsComplex()
               && profile.ConfigType != EConfigType.Outbound
               && !host.IsNullOrEmpty()
               && !IPAddress.TryParse(host, out _)
               && compatibility.Supports(profile, ECoreType.Xray);
    }

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

        var host = baseline.Address.Trim().Trim('[', ']').TrimEnd('.');
        DnsRepairObservation? observation = null;
        try
        {
            observation = await evidenceProvider.InspectAsync(host, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            // DNS repair is opportunistic. Other Reviver strategies must still be able to run when
            // Discovery diagnostics are unavailable or incomplete.
        }
        if (observation is null)
        {
            yield break;
        }

        DnsRepairHistorySummary? history = null;
        if (historyStore is not null)
        {
            try
            {
                await historyStore.RecordObservationAsync(baseline.IndexId, session.Id, observation, cancellationToken);
                history = await historyStore.SummarizeAsync(host, cancellationToken: cancellationToken);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                // History is advisory. Persistence failures must not block a current repair attempt.
            }
        }

        var strategies = BuildStrategies(observation, failureClass, history);
        if (strategies.Count == 0)
        {
            yield break;
        }

        foreach (var targetStrategy in strategies)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var candidate = session.Original.CreateWorkingCopy();
            var mutations = new List<RepairMutation>();
            var currentCore = candidate.CoreType ?? ECoreType.Xray;
            if (currentCore == ECoreType.Xray
                && string.Equals(
                    baseline.GetTargetStrategy() ?? Global.AsIs,
                    targetStrategy,
                    StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            if (currentCore != ECoreType.Xray)
            {
                candidate.CoreType = ECoreType.Xray;
                mutations.Add(new RepairMutation
                {
                    Kind = ERepairMutationKind.ChangeCore,
                    Field = nameof(ProfileItem.CoreType),
                    From = currentCore.ToString(),
                    To = ECoreType.Xray.ToString(),
                    Reason = "Per-profile targetStrategy is emitted by PattN's Xray outbound generator.",
                    Confidence = ERepairConfidence.LowRisk,
                });
            }

            var previousStrategy = candidate.GetTargetStrategy() ?? Global.AsIs;
            candidate.TargetStrategy = targetStrategy;
            mutations.Add(new RepairMutation
            {
                Kind = ERepairMutationKind.PreferAddressFamily,
                Field = nameof(ProfileItem.TargetStrategy),
                From = previousStrategy,
                To = targetStrategy,
                Reason = BuildMutationReason(observation, targetStrategy),
                Confidence = ERepairConfidence.EvidenceBacked,
            });

            var allowed = currentCore == ECoreType.Xray
                ? new[] { nameof(ProfileItem.TargetStrategy) }
                : new[] { nameof(ProfileItem.CoreType), nameof(ProfileItem.TargetStrategy) };
            if (!ProfileMutationGuard.ChangesOnly(baseline, candidate, allowed))
            {
                throw new InvalidOperationException("DNS address-family repair modified fields outside CoreType/TargetStrategy.");
            }

            yield return new RepairCandidate
            {
                SessionId = session.Id,
                Profile = candidate,
                FailureClassAddressed = failureClass,
                Mutations = mutations,
                Evidence = BuildEvidence(observation, history),
            };
        }
    }

    public static IReadOnlyList<string> BuildStrategies(
        DnsRepairObservation observation,
        ERepairFailureClass failureClass,
        DnsRepairHistorySummary? history = null)
    {
        var values = new List<string>(4);
        switch (observation.HasIPv4, observation.HasIPv6)
        {
            case (true, false):
                values.Add("UseIPv4");
                if (failureClass == ERepairFailureClass.NoUsableAddressFamily)
                {
                    values.Add("ForceIPv4");
                }
                break;

            case (false, true):
                values.Add("UseIPv6");
                if (failureClass == ERepairFailureClass.NoUsableAddressFamily)
                {
                    values.Add("ForceIPv6");
                }
                break;

            case (true, true):
                var historicalPreference = history?.PreferredFamily();
                if (historicalPreference == "ipv6")
                {
                    values.Add("UseIPv6v4");
                    values.Add("UseIPv4v6");
                }
                else if (historicalPreference == "ipv4")
                {
                    values.Add("UseIPv4v6");
                    values.Add("UseIPv6v4");
                }
                else if (observation.IPv6.DnssecAuthenticated && !observation.IPv4.DnssecAuthenticated)
                {
                    values.Add("UseIPv6v4");
                    values.Add("UseIPv4v6");
                }
                else
                {
                    values.Add("UseIPv4v6");
                    values.Add("UseIPv6v4");
                }

                if (failureClass == ERepairFailureClass.NoUsableAddressFamily)
                {
                    values.Add("UseIPv4");
                    values.Add("UseIPv6");
                }
                break;
        }

        return values
            .Where(Global.TargetStrategies.Contains)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static IReadOnlyList<RepairEvidence> BuildEvidence(
        DnsRepairObservation observation,
        DnsRepairHistorySummary? history)
    {
        var familyData = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["host"] = observation.Host,
            ["ipv4Count"] = observation.IPv4.Addresses.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["ipv6Count"] = observation.IPv6.Addresses.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["ipv4DnssecAuthenticated"] = observation.IPv4.DnssecAuthenticated ? "true" : "false",
            ["ipv6DnssecAuthenticated"] = observation.IPv6.DnssecAuthenticated ? "true" : "false",
            ["ipv4DnssecStatus"] = observation.IPv4.DnssecStatus,
            ["ipv6DnssecStatus"] = observation.IPv6.DnssecStatus,
        };
        if (observation.IPv4.Addresses.Count > 0)
        {
            familyData["ipv4"] = string.Join(",", observation.IPv4.Addresses);
        }
        if (observation.IPv6.Addresses.Count > 0)
        {
            familyData["ipv6"] = string.Join(",", observation.IPv6.Addresses);
        }

        var evidence = new List<RepairEvidence>
        {
            new()
            {
                Kind = "discovery.dns.address-family",
                Summary = $"Authoritative DNS evidence for {observation.Host}: IPv4={observation.HasIPv4}, IPv6={observation.HasIPv6}.",
                Source = "pattn-discovery",
                ObservedAt = observation.ObservedAt,
                Data = familyData,
            }
        };

        if (history is { TotalSamples: > 0 })
        {
            var preferred = history.PreferredFamily() ?? string.Empty;
            evidence.Add(new RepairEvidence
            {
                Kind = "discovery.dns.history",
                Summary = $"Recent validated DNS repair history for {observation.Host}: IPv4={history.IPv4.PassRate:0.##}, IPv6={history.IPv6.PassRate:0.##}.",
                Source = "pattn.reviver-history",
                ObservedAt = observation.ObservedAt,
                Data = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["ipv4Samples"] = history.IPv4.Samples.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    ["ipv4PassRate"] = history.IPv4.PassRate.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture),
                    ["ipv6Samples"] = history.IPv6.Samples.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    ["ipv6PassRate"] = history.IPv6.PassRate.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture),
                    ["preferredFamily"] = preferred,
                },
            });
        }

        if (observation.ResolverRecommendations.Count > 0)
        {
            var references = observation.ResolverRecommendations.Where(x => x.ReferenceEligible).ToArray();
            evidence.Add(new RepairEvidence
            {
                Kind = "discovery.dns.resolver-recommendations",
                Summary = $"{references.Length} neutral encrypted resolver reference(s) are available; global DNS remains unchanged.",
                Source = "pattn-discovery.resolver-catalog",
                ObservedAt = observation.ObservedAt,
                Data = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["catalogVersion"] = observation.ResolverCatalogVersion,
                    ["referenceEligible"] = string.Join(",", references.Select(x => x.CatalogId)),
                    ["allCatalogEntries"] = string.Join(",", observation.ResolverRecommendations.Select(x => x.CatalogId)),
                    ["doh"] = string.Join(",", references.Select(x => x.DohUrl).Where(x => !x.IsNullOrEmpty())),
                    ["dot"] = string.Join(",", references.Select(x => x.DotServerName).Where(x => !x.IsNullOrEmpty())),
                },
            });
        }

        return evidence;
    }

    private static string BuildMutationReason(DnsRepairObservation observation, string strategy)
        => $"{strategy} is bounded by observed A/AAAA availability for {observation.Host}; logical profile identity remains unchanged.";
}
