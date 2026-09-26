using ServiceLib.Models.Entities;
using ServiceLib.Reviver.Models;

namespace ServiceLib.Reviver.Services;

public sealed class SqliteDnsRepairHistoryStore : IDnsRepairHistoryStore
{
    public async Task RecordObservationAsync(
        string profileId,
        string sessionId,
        DnsRepairObservation observation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(observation);
        cancellationToken.ThrowIfCancellationRequested();

        var item = new DnsRepairHistoryItem
        {
            Id = Utils.GetGuid(false),
            Host = NormalizeHost(observation.Host),
            ProfileId = profileId ?? string.Empty,
            SessionId = sessionId ?? string.Empty,
            EventKind = "observation",
            CatalogVersion = observation.ResolverCatalogVersion,
            ObservedAtUnixMs = observation.ObservedAt.ToUnixTimeMilliseconds(),
            EvidenceJson = JsonUtils.Serialize(observation, false),
        };
        await SQLiteHelper.Instance.InsertAsync(item);
    }

    public async Task RecordCandidateAsync(
        RepairCandidate candidate,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        cancellationToken.ThrowIfCancellationRequested();

        var mutation = candidate.Mutations.LastOrDefault(x => x.Kind == ERepairMutationKind.PreferAddressFamily);
        if (mutation?.To.IsNullOrEmpty() != false)
        {
            return;
        }

        var family = FamilyFromStrategy(mutation.To!);
        if (family is null)
        {
            return;
        }

        var validation = candidate.Validation;
        var item = new DnsRepairHistoryItem
        {
            Id = Utils.GetGuid(false),
            Host = NormalizeHost(candidate.Profile.Address),
            ProfileId = candidate.Profile.IndexId ?? string.Empty,
            SessionId = candidate.SessionId,
            CandidateId = candidate.Id,
            EventKind = "candidate-validation",
            TargetStrategy = mutation.To!,
            FamilyPreference = family,
            CandidateState = candidate.State.ToString(),
            CatalogVersion = candidate.Evidence
                .LastOrDefault(x => x.Kind == "discovery.dns.resolver-recommendations")?
                .Data.GetValueOrDefault("catalogVersion") ?? string.Empty,
            Attempts = validation?.Attempts ?? 0,
            Successes = validation?.Successes ?? 0,
            ConsecutiveSuccesses = validation?.ConsecutiveSuccesses ?? 0,
            LossRate = validation?.LossRate,
            MedianLatencyMs = validation?.MedianLatencyMs,
            RuntimeQuorumMet = candidate.State == ERepairCandidateState.RuntimeValidated,
            ObservedAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            EvidenceJson = JsonUtils.Serialize(candidate.Evidence, false),
        };
        await SQLiteHelper.Instance.InsertAsync(item);
    }

    public async Task<DnsRepairHistorySummary> SummarizeAsync(
        string host,
        TimeSpan? maxAge = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        host = NormalizeHost(host);
        var window = maxAge ?? TimeSpan.FromDays(30);
        var cutoff = DateTimeOffset.UtcNow.Subtract(window).ToUnixTimeMilliseconds();

        var records = await SQLiteHelper.Instance.TableAsync<DnsRepairHistoryItem>()
            .Where(x => x.Host == host && x.EventKind == "candidate-validation" && x.ObservedAtUnixMs >= cutoff)
            .ToListAsync();

        return new DnsRepairHistorySummary
        {
            Host = host,
            IPv4 = SummarizeFamily(records, "ipv4"),
            IPv6 = SummarizeFamily(records, "ipv6"),
        };
    }

    public async Task PruneAsync(TimeSpan maxAge, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (maxAge <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(maxAge));
        }

        var cutoff = DateTimeOffset.UtcNow.Subtract(maxAge).ToUnixTimeMilliseconds();
        var stale = await SQLiteHelper.Instance.TableAsync<DnsRepairHistoryItem>()
            .Where(x => x.ObservedAtUnixMs < cutoff)
            .ToListAsync();
        foreach (var item in stale)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await SQLiteHelper.Instance.DeleteAsync(item);
        }
    }

    private static DnsRepairFamilyHistory SummarizeFamily(
        IReadOnlyList<DnsRepairHistoryItem> records,
        string family)
    {
        var values = records.Where(x => x.FamilyPreference == family).ToArray();
        var latencies = values
            .Where(x => x.RuntimeQuorumMet && x.MedianLatencyMs is >= 0)
            .Select(x => x.MedianLatencyMs!.Value)
            .OrderBy(x => x)
            .ToArray();

        return new DnsRepairFamilyHistory
        {
            Family = family,
            Samples = values.Length,
            RuntimeQuorumPasses = values.Count(x => x.RuntimeQuorumMet),
            MedianLatencyMs = Median(latencies),
        };
    }

    private static double? Median(double[] values)
    {
        if (values.Length == 0)
        {
            return null;
        }
        var middle = values.Length / 2;
        return values.Length % 2 == 1
            ? values[middle]
            : (values[middle - 1] + values[middle]) / 2d;
    }

    private static string NormalizeHost(string value)
        => (value ?? string.Empty).Trim().Trim('[', ']').TrimEnd('.').ToLowerInvariant();

    private static string? FamilyFromStrategy(string value)
        => value switch
        {
            "UseIPv4" or "ForceIPv4" => "ipv4",
            "UseIPv6" or "ForceIPv6" => "ipv6",
            "UseIPv4v6" or "ForceIPv4v6" => "ipv4-first",
            "UseIPv6v4" or "ForceIPv6v4" => "ipv6-first",
            _ => null,
        };
}
