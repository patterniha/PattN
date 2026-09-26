using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Protocol;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Composes endpoint sources, deduplicates their physical addresses, and opportunistically enriches them with
/// pattn-discovery's pinned Host/SNI probe. Probe failure never deletes a source candidate: Reviver's real-core
/// validation remains authoritative for whether a profile is actually repaired.
/// </summary>
public sealed class DiscoveryCandidateProvider(
    IDiscoveryEndpointProbeClient engine,
    IEnumerable<IDiscoveryCandidateSource> sources,
    IEndpointHistoryStore? historyStore = null) : IDiscoveryCandidateProvider
{
    private readonly IDiscoveryCandidateSource[] _sources = sources.ToArray();

    public async IAsyncEnumerable<DiscoveryEndpointCandidate> GetCandidatesAsync(
        DiscoveryCandidateRequest request,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.MaxCandidates <= 0)
        {
            yield break;
        }

        var sourceCandidates = new Dictionary<string, DiscoveryEndpointCandidate>(StringComparer.OrdinalIgnoreCase);
        var perSourceBudget = Math.Max(4, request.MaxCandidates * 2);
        foreach (var source in _sources)
        {
            var acceptedFromSource = 0;
            await foreach (var candidate in source.GetCandidatesAsync(request, cancellationToken).WithCancellation(cancellationToken))
            {
                if (!DiscoveryEndpointAddress.TryNormalizeLiteral(candidate.Address, out var address))
                {
                    continue;
                }

                var normalized = candidate with { Address = address };
                if (sourceCandidates.TryGetValue(address, out var existing))
                {
                    sourceCandidates[address] = MergeCandidates(existing, normalized);
                }
                else
                {
                    sourceCandidates[address] = normalized;
                }

                acceptedFromSource++;
                if (acceptedFromSource >= perSourceBudget)
                {
                    break;
                }
            }
        }

        if (sourceCandidates.Count == 0)
        {
            yield break;
        }

        var preProbeBudget = Math.Max(request.MaxCandidates, request.MaxCandidates * 8);
        var candidates = sourceCandidates.Values
            .OrderByDescending(IsPinned)
            .ThenByDescending(x => x.Reliability ?? -1d)
            .ThenByDescending(x => x.ObservedAt)
            .ThenBy(x => x.LatencyMs ?? double.MaxValue)
            .Take(preProbeBudget)
            .ToArray();
        var enriched = await TryEnrichAsync(candidates, request, cancellationToken);
        foreach (var candidate in enriched
                     .OrderByDescending(IsProbeQualified)
                     .ThenByDescending(IsPinned)
                     .ThenByDescending(x => x.Reliability ?? -1)
                     .ThenBy(x => x.LatencyMs ?? double.MaxValue)
                     .Take(request.MaxCandidates))
        {
            yield return candidate;
        }
    }

    private async Task<IReadOnlyList<DiscoveryEndpointCandidate>> TryEnrichAsync(
        IReadOnlyList<DiscoveryEndpointCandidate> candidates,
        DiscoveryCandidateRequest request,
        CancellationToken cancellationToken)
    {
        if (request.LogicalHost.IsNullOrEmpty() || request.OriginalPort is < 1 or > 65535)
        {
            return candidates;
        }

        // Reality authenticates a different handshake than ordinary Web-PKI HTTPS. A generic
        // pinned HTTP request cannot qualify a Reality endpoint and would create misleading
        // ranking/history evidence. Leave those candidates to the real-core validator.
        if (IsReality(request.StreamSecurity))
        {
            return candidates;
        }

        var httpHost = request.HttpHost.NullIfEmpty() ?? request.LogicalHost;
        try
        {
            var response = await engine.ProbeEndpointsAsync(new DiscoveryEndpointProbeRequest
            {
                Addresses = candidates.Select(x => x.Address).ToArray(),
                Port = request.OriginalPort,
                ServerName = request.LogicalHost,
                HttpHost = httpHost,
                Scheme = IsTlsLike(request.StreamSecurity) ? "https" : "http",
                Attempts = 3,
                MinSuccesses = 2,
                // The helper dials the candidate IP while TLS verifies against the preserved logical
                // ServerName. Reaching an IP directly is not a reason to disable certificate validation.
                InsecureSkipVerify = false,
            }, cancellationToken);

            var observations = response.Results.ToDictionary(x => NormalizeAddress(x.Address), StringComparer.OrdinalIgnoreCase);
            var enriched = candidates.Select(candidate =>
            {
                var key = NormalizeAddress(candidate.Address);
                if (!observations.TryGetValue(key, out var observation))
                {
                    return candidate;
                }
                var metadata = new Dictionary<string, string>(candidate.Metadata)
                {
                    ["probeQualified"] = observation.Qualified ? "true" : "false",
                    ["probeAttempts"] = observation.Attempts.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    ["probeSuccesses"] = observation.Successes.ToString(System.Globalization.CultureInfo.InvariantCulture),
                };
                if (observation.StatusCode > 0)
                {
                    metadata["httpStatus"] = observation.StatusCode.ToString(System.Globalization.CultureInfo.InvariantCulture);
                }
                if (!observation.Edge.Evidence.IsNullOrEmpty())
                {
                    metadata["edgeEvidence"] = observation.Edge.Evidence;
                }

                return candidate with
                {
                    Provider = observation.Edge.Provider.NullIfEmpty() ?? candidate.Provider,
                    Pop = observation.Edge.Pop.NullIfEmpty() ?? candidate.Pop,
                    LatencyMs = observation.MedianLatencyMs > 0 ? observation.MedianLatencyMs : candidate.LatencyMs,
                    Reliability = observation.Attempts > 0 ? observation.Reliability : candidate.Reliability,
                    LossRate = observation.Attempts > 0 ? 1d - observation.Reliability : candidate.LossRate,
                    Metadata = metadata,
                    ObservedAt = DateTimeOffset.UtcNow,
                };
            }).ToArray();

            if (historyStore is not null)
            {
                foreach (var candidate in candidates)
                {
                    var key = NormalizeAddress(candidate.Address);
                    if (!observations.TryGetValue(key, out var observation))
                    {
                        continue;
                    }

                    try
                    {
                        await historyStore.RecordProbeAsync(request, candidate, observation, cancellationToken);
                    }
                    catch (OperationCanceledException)
                    {
                        throw;
                    }
                    catch (Exception ex)
                    {
                        Logging.SaveLog("endpoint history record", ex);
                    }
                }
            }

            return enriched;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            Logging.SaveLog("pattn-discovery candidate enrichment", ex);
            return candidates;
        }
    }

    private static DiscoveryEndpointCandidate MergeCandidates(
        DiscoveryEndpointCandidate existing,
        DiscoveryEndpointCandidate incoming)
    {
        // Preserve one coherent observation. Combining max reliability from one source with
        // min latency and newest timestamp from another fabricates evidence that nobody
        // actually observed and can distort the pre-probe budget.
        var primary = PreferAsPrimary(existing, incoming) ? existing : incoming;
        var secondary = ReferenceEquals(primary, existing) ? incoming : existing;

        var metadata = new Dictionary<string, string>(primary.Metadata, StringComparer.Ordinal);
        foreach (var pair in secondary.Metadata)
        {
            metadata.TryAdd(pair.Key, pair.Value);
        }

        var sources = new[] { existing.Source, incoming.Source }
            .Where(x => !x.IsNullOrEmpty())
            .SelectMany(x => x!.Split(
                '+',
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (sources.Length > 0)
        {
            metadata["sources"] = string.Join(",", sources);
        }
        if (IsPinned(existing) || IsPinned(incoming))
        {
            metadata["pinned"] = "true";
        }

        return primary with
        {
            Source = sources.Length == 0 ? primary.Source : string.Join("+", sources),
            Provider = primary.Provider.NullIfEmpty() ?? secondary.Provider,
            Asn = primary.Asn.NullIfEmpty() ?? secondary.Asn,
            Pop = primary.Pop.NullIfEmpty() ?? secondary.Pop,
            Metadata = metadata,
        };
    }

    private static bool PreferAsPrimary(
        DiscoveryEndpointCandidate left,
        DiscoveryEndpointCandidate right)
    {
        var leftPinned = IsPinned(left);
        var rightPinned = IsPinned(right);
        if (leftPinned != rightPinned)
        {
            return leftPinned;
        }

        var leftReliability = ComparableReliability(left.Reliability);
        var rightReliability = ComparableReliability(right.Reliability);
        if (leftReliability != rightReliability)
        {
            return leftReliability > rightReliability;
        }

        if (left.ObservedAt != right.ObservedAt)
        {
            return left.ObservedAt > right.ObservedAt;
        }

        var leftLatency = ComparableLatency(left.LatencyMs);
        var rightLatency = ComparableLatency(right.LatencyMs);
        if (leftLatency != rightLatency)
        {
            return leftLatency < rightLatency;
        }

        return true;
    }

    private static double ComparableReliability(double? value)
        => value is not null
           && double.IsFinite(value.Value)
           && value.Value is >= 0d and <= 1d
            ? value.Value
            : -1d;

    private static double ComparableLatency(double? value)
        => value is not null
           && double.IsFinite(value.Value)
           && value.Value >= 0d
            ? value.Value
            : double.MaxValue;

    private static bool IsPinned(DiscoveryEndpointCandidate candidate)
        => candidate.Metadata.TryGetValue("pinned", out var value)
           && bool.TryParse(value, out var pinned)
           && pinned;

    private static bool IsProbeQualified(DiscoveryEndpointCandidate candidate)
        => candidate.Metadata.TryGetValue("probeQualified", out var value)
           && bool.TryParse(value, out var qualified)
           && qualified;

    private static bool IsTlsLike(string? streamSecurity)
        => streamSecurity is not null
           && streamSecurity.Equals("tls", StringComparison.OrdinalIgnoreCase);

    private static bool IsReality(string? streamSecurity)
        => streamSecurity is not null
           && streamSecurity.Equals(Global.StreamSecurityReality, StringComparison.OrdinalIgnoreCase);

    private static string NormalizeAddress(string value)
        => DiscoveryEndpointAddress.NormalizeIfLiteral(value);
}
