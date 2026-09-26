using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Protocol;
using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

public sealed class SqliteEndpointHistoryStore : IEndpointHistoryStore
{
    public async Task RecordProbeAsync(
        DiscoveryCandidateRequest request,
        DiscoveryEndpointCandidate sourceCandidate,
        DiscoveryEndpointProbeResult observation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(sourceCandidate);
        ArgumentNullException.ThrowIfNull(observation);
        cancellationToken.ThrowIfCancellationRequested();

        var logicalHost = NormalizeHost(request.LogicalHost);
        var httpHost = NormalizeHost(string.IsNullOrWhiteSpace(request.HttpHost) ? request.LogicalHost : request.HttpHost);
        var address = NormalizeAddress(observation.Address);
        if (logicalHost.IsNullOrEmpty()
            || address.IsNullOrEmpty()
            || request.OriginalPort is < 1 or > 65535
            || !DiscoveryEndpointAddress.TryNormalizeLiteral(address, out address))
        {
            return;
        }

        await SQLiteHelper.Instance.InsertAsync(new EndpointObservationHistoryItem
        {
            Id = Utils.GetGuid(false),
            LogicalHost = logicalHost,
            HttpHost = httpHost,
            Port = request.OriginalPort,
            Network = NormalizeToken(request.Network),
            StreamSecurity = NormalizeToken(request.StreamSecurity),
            Address = address,
            Source = sourceCandidate.Source ?? string.Empty,
            Provider = observation.Edge.Provider.NullIfEmpty() ?? sourceCandidate.Provider ?? string.Empty,
            Asn = sourceCandidate.Asn ?? string.Empty,
            Pop = observation.Edge.Pop.NullIfEmpty() ?? sourceCandidate.Pop ?? string.Empty,
            Attempts = observation.Attempts,
            Successes = observation.Successes,
            ConsecutiveSuccesses = observation.ConsecutiveSuccesses,
            Qualified = observation.Qualified,
            Reliability = Math.Clamp(observation.Reliability, 0d, 1d),
            MedianLatencyMs = observation.MedianLatencyMs > 0 ? observation.MedianLatencyMs : null,
            ErrorsJson = JsonUtils.Serialize(observation.Errors, false),
            ObservedAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        });
    }

    public async Task<IReadOnlyList<DiscoveryEndpointCandidate>> GetHistoricallyGoodAsync(
        DiscoveryCandidateRequest request,
        EndpointHistoryPolicy? policy = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        policy ??= new EndpointHistoryPolicy();
        ValidatePolicy(policy);

        var logicalHost = NormalizeHost(request.LogicalHost);
        var httpHost = NormalizeHost(string.IsNullOrWhiteSpace(request.HttpHost) ? request.LogicalHost : request.HttpHost);
        if (logicalHost.IsNullOrEmpty()
            || request.OriginalPort is < 1 or > 65535)
        {
            return [];
        }

        var network = NormalizeToken(request.Network);
        var security = NormalizeToken(request.StreamSecurity);
        var now = DateTimeOffset.UtcNow;
        var cutoff = now.Subtract(policy.HistoryWindow).ToUnixTimeMilliseconds();

        // HttpHost is part of the endpoint identity. Rows from the pre-HttpHost
        // schema remain empty and are deliberately ignored because their original
        // fronting identity cannot be reconstructed safely.
        var rows = await SQLiteHelper.Instance.TableAsync<EndpointObservationHistoryItem>()
            .Where(x => x.LogicalHost == logicalHost
                        && x.HttpHost == httpHost
                        && x.Port == request.OriginalPort
                        && x.Network == network
                        && x.StreamSecurity == security
                        && x.ObservedAtUnixMs >= cutoff)
            .ToListAsync();

        return rows
            .GroupBy(x => NormalizeAddress(x.Address), StringComparer.OrdinalIgnoreCase)
            .Select(group => Summarize(group.ToArray(), now, policy))
            .Where(x => x.IsHistoricallyGood(policy))
            .OrderBy(x => x.RecentFailureStreak)
            .ThenByDescending(x => x.DecayedReliability)
            .ThenBy(x => x.DecayedLatencyMs ?? double.MaxValue)
            .ThenByDescending(x => x.LastObservedAt)
            .Take(Math.Min(request.MaxCandidates, policy.MaximumCandidates))
            .Select(summary => new DiscoveryEndpointCandidate
            {
                Address = summary.Address,
                Port = request.OriginalPort,
                Source = "history.endpoint",
                Provider = summary.Provider.NullIfEmpty(),
                Asn = summary.Asn.NullIfEmpty(),
                Pop = summary.Pop.NullIfEmpty(),
                Reliability = summary.DecayedReliability,
                LossRate = 1d - summary.DecayedReliability,
                LatencyMs = summary.DecayedLatencyMs,
                ObservedAt = summary.LastObservedAt,
                Metadata = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["historical"] = "true",
                    ["historySamples"] = summary.Samples.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    ["historyQualified"] = summary.QualifiedObservations.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    ["historyFailureStreak"] = summary.RecentFailureStreak.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    ["historyReliability"] = summary.DecayedReliability.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture),
                    ["historyLastObservedAt"] = summary.LastObservedAt.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
                },
            })
            .ToArray();
    }

    public async Task PruneAsync(TimeSpan maxAge, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (maxAge <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(maxAge));
        }

        var cutoff = DateTimeOffset.UtcNow.Subtract(maxAge).ToUnixTimeMilliseconds();
        cancellationToken.ThrowIfCancellationRequested();
        await SQLiteHelper.Instance.ExecuteAsync(
            $"DELETE FROM {nameof(EndpointObservationHistoryItem)} WHERE {nameof(EndpointObservationHistoryItem.ObservedAtUnixMs)} < ?",
            cutoff);
    }

    public static EndpointHistorySummary Summarize(
        IReadOnlyList<EndpointObservationHistoryItem> observations,
        DateTimeOffset now,
        EndpointHistoryPolicy? policy = null)
    {
        ArgumentNullException.ThrowIfNull(observations);
        policy ??= new EndpointHistoryPolicy();
        ValidatePolicy(policy);
        if (observations.Count == 0)
        {
            throw new ArgumentException("At least one endpoint observation is required.", nameof(observations));
        }

        var ordered = observations
            .OrderByDescending(x => x.ObservedAtUnixMs)
            .ToArray();

        double weightedReliability = 0d;
        double reliabilityWeight = 0d;
        double weightedLatency = 0d;
        double latencyWeight = 0d;

        foreach (var row in ordered)
        {
            var observed = DateTimeOffset.FromUnixTimeMilliseconds(row.ObservedAtUnixMs);
            var ageSeconds = Math.Max(0d, (now - observed).TotalSeconds);
            var weight = Math.Exp(-Math.Log(2d) * ageSeconds / policy.HalfLife.TotalSeconds);
            var sampleReliability = row.Qualified
                ? Math.Clamp(row.Reliability, 0d, 1d)
                : Math.Clamp(row.Reliability, 0d, 1d) * 0.25d;

            weightedReliability += sampleReliability * weight;
            reliabilityWeight += weight;
            if (row.Qualified && row.MedianLatencyMs is > 0)
            {
                weightedLatency += row.MedianLatencyMs.Value * weight;
                latencyWeight += weight;
            }
        }

        var failureStreak = 0;
        foreach (var row in ordered)
        {
            if (row.Qualified)
            {
                break;
            }
            failureStreak++;
        }

        return new EndpointHistorySummary
        {
            Address = NormalizeAddress(ordered[0].Address),
            Samples = ordered.Length,
            QualifiedObservations = ordered.Count(x => x.Qualified),
            RecentFailureStreak = failureStreak,
            DecayedReliability = reliabilityWeight <= 0d
                ? 0d
                : Math.Clamp(weightedReliability / reliabilityWeight, 0d, 1d),
            DecayedLatencyMs = latencyWeight <= 0d ? null : weightedLatency / latencyWeight,
            LastObservedAt = DateTimeOffset.FromUnixTimeMilliseconds(ordered[0].ObservedAtUnixMs),
            Provider = ordered.Select(x => x.Provider).FirstOrDefault(x => !x.IsNullOrEmpty()) ?? string.Empty,
            Asn = ordered.Select(x => x.Asn).FirstOrDefault(x => !x.IsNullOrEmpty()) ?? string.Empty,
            Pop = ordered.Select(x => x.Pop).FirstOrDefault(x => !x.IsNullOrEmpty()) ?? string.Empty,
        };
    }

    private static void ValidatePolicy(EndpointHistoryPolicy policy)
    {
        if (policy.HistoryWindow <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(policy.HistoryWindow));
        }
        if (policy.HalfLife <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(policy.HalfLife));
        }
        if (policy.MinimumQualifiedObservations < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(policy.MinimumQualifiedObservations));
        }
        if (policy.MaximumRecentFailureStreak < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(policy.MaximumRecentFailureStreak));
        }
        if (policy.MinimumDecayedReliability is < 0d or > 1d)
        {
            throw new ArgumentOutOfRangeException(nameof(policy.MinimumDecayedReliability));
        }
        if (policy.MaximumCandidates < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(policy.MaximumCandidates));
        }
    }

    private static string NormalizeHost(string? value)
        => (value ?? string.Empty).Trim().Trim('[', ']').TrimEnd('.').ToLowerInvariant();

    private static string NormalizeAddress(string? value)
        => DiscoveryEndpointAddress.NormalizeIfLiteral(value);

    private static string NormalizeToken(string? value)
        => (value ?? string.Empty).Trim().ToLowerInvariant();
}
