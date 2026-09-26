using ServiceLib.Models.Entities;
using ServiceLib.Reviver.Models;

namespace ServiceLib.Reviver.Services;

public sealed class RepairPromotionHistoryQueryService
{
    private const int MaximumScanItems = 5000;

    public async Task<RepairPromotionHistorySummary> QueryAsync(
        RepairPromotionHistoryQuery? query = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        query ??= new RepairPromotionHistoryQuery();
        Validate(query);

        var cutoff = DateTimeOffset.UtcNow.Subtract(query.MaxAge).ToUnixTimeMilliseconds();
        var rows = await SQLiteHelper.Instance.TableAsync<RepairPromotionHistoryItem>()
            .Where(x => x.ObservedAtUnixMs >= cutoff)
            .OrderByDescending(x => x.ObservedAtUnixMs)
            .Take(MaximumScanItems)
            .ToListAsync();

        var filtered = rows
            .Where(x => Match(query, x))
            .Take(query.MaxItems)
            .ToArray();

        return Summarize(filtered);
    }

    public static RepairPromotionHistorySummary Summarize(
        IReadOnlyList<RepairPromotionHistoryItem> rows)
    {
        ArgumentNullException.ThrowIfNull(rows);

        var entries = rows
            .OrderByDescending(x => x.ObservedAtUnixMs)
            .Select(Project)
            .ToArray();

        return new RepairPromotionHistorySummary
        {
            TotalEvents = entries.Length,
            Promotions = entries.Count(x => x.EventKind == "promoted"),
            Rollbacks = entries.Count(x => x.EventKind == "rolled-back"),
            Improved = entries.Count(x => x.OutcomeVerdict == "improved"),
            Stable = entries.Count(x => x.OutcomeVerdict == "stable"),
            Regressed = entries.Count(x => x.OutcomeVerdict == "regressed"),
            Unknown = entries.Count(x => x.OutcomeVerdict is "" or "unknown"),
            LatestEventAt = entries.Length == 0 ? null : entries[0].ObservedAt,
            Entries = entries,
        };
    }

    private static RepairPromotionHistoryEntry Project(RepairPromotionHistoryItem row)
        => new()
        {
            Id = row.Id,
            EventKind = row.EventKind,
            SessionId = row.SessionId,
            CandidateId = row.CandidateId,
            OriginalProfileId = row.OriginalProfileId,
            PromotedProfileId = row.PromotedProfileId,
            PreviousDefaultProfileId = row.PreviousDefaultProfileId,
            BecameDefault = row.BecameDefault,
            Score = row.Score,
            OutcomeVerdict = (row.OutcomeVerdict.NullIfEmpty() ?? "unknown").Trim().ToLowerInvariant(),
            Mutations = DeserializeOrDefault<List<RepairMutation>>(row.MutationsJson, nameof(row.MutationsJson)) ?? [],
            BaselineValidation = DeserializeOrDefault<RepairValidationEvidence>(row.BaselineValidationJson, nameof(row.BaselineValidationJson)),
            CandidateValidation = DeserializeOrDefault<RepairValidationEvidence>(row.CandidateValidationJson, nameof(row.CandidateValidationJson)),
            OutcomeComparison = DeserializeOrDefault<RepairOutcomeComparison>(row.OutcomeComparisonJson, nameof(row.OutcomeComparisonJson)),
            ObservedAt = DateTimeOffset.FromUnixTimeMilliseconds(row.ObservedAtUnixMs),
        };

    private static T? DeserializeOrDefault<T>(string json, string fieldName)
    {
        if (json.IsNullOrEmpty())
        {
            return default;
        }
        try
        {
            return JsonUtils.DeserializeStrict<T>(json);
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException)
        {
            throw new InvalidOperationException(
                $"Stored repair promotion history field '{fieldName}' contains invalid JSON.",
                ex);
        }
    }

    private static bool Match(
        RepairPromotionHistoryQuery query,
        RepairPromotionHistoryItem row)
    {
        if (!query.EventKind.IsNullOrEmpty()
            && !string.Equals(row.EventKind, query.EventKind, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        if (!query.SessionId.IsNullOrEmpty()
            && !string.Equals(row.SessionId, query.SessionId, StringComparison.Ordinal))
        {
            return false;
        }
        if (!query.CandidateId.IsNullOrEmpty()
            && !string.Equals(row.CandidateId, query.CandidateId, StringComparison.Ordinal))
        {
            return false;
        }
        if (!query.ProfileId.IsNullOrEmpty()
            && !string.Equals(row.OriginalProfileId, query.ProfileId, StringComparison.Ordinal)
            && !string.Equals(row.PromotedProfileId, query.ProfileId, StringComparison.Ordinal))
        {
            return false;
        }
        return true;
    }

    private static void Validate(RepairPromotionHistoryQuery query)
    {
        if (query.MaxAge <= TimeSpan.Zero || query.MaxAge > TimeSpan.FromDays(3650))
        {
            throw new ArgumentOutOfRangeException(nameof(query.MaxAge), "Promotion history age must be greater than zero and at most 10 years.");
        }
        if (query.MaxItems is < 1 or > 1000)
        {
            throw new ArgumentOutOfRangeException(nameof(query.MaxItems), "Promotion history item limit must be between 1 and 1000.");
        }
        if (!query.EventKind.IsNullOrEmpty()
            && !string.Equals(query.EventKind, "promoted", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(query.EventKind, "rolled-back", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Promotion history event kind must be 'promoted' or 'rolled-back'.", nameof(query.EventKind));
        }
    }
}
