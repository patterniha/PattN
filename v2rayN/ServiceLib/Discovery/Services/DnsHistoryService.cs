using ServiceLib.Discovery.Models;
using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

public sealed class DnsHistoryService
{
    public async Task<DnsHistorySnapshot> LoadAsync(
        TimeSpan? window = null,
        int maxPointsPerResolver = 12,
        int maxEvents = 30,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (maxPointsPerResolver is < 2 or > 200)
        {
            throw new ArgumentOutOfRangeException(nameof(maxPointsPerResolver));
        }
        if (maxEvents is < 1 or > 500)
        {
            throw new ArgumentOutOfRangeException(nameof(maxEvents));
        }

        var age = window ?? TimeSpan.FromDays(90);
        if (age <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(window));
        }
        var cutoff = DateTimeOffset.UtcNow.Subtract(age).ToUnixTimeMilliseconds();

        var telemetry = await SQLiteHelper.Instance.TableAsync<DnsResolverTelemetryItem>()
            .Where(x => x.ObservedAtUnixMs >= cutoff)
            .ToListAsync();
        var dnsSettings = await SQLiteHelper.Instance.TableAsync<DnsSettingsRepairHistoryItem>()
            .Where(x => x.ObservedAtUnixMs >= cutoff)
            .ToListAsync();
        var promotions = await SQLiteHelper.Instance.TableAsync<RepairPromotionHistoryItem>()
            .Where(x => x.ObservedAtUnixMs >= cutoff)
            .ToListAsync();

        var trends = telemetry
            .GroupBy(x => x.ResolverCatalogId, StringComparer.Ordinal)
            .Select(group =>
            {
                var ordered = group
                    .OrderByDescending(x => x.ObservedAtUnixMs)
                    .Take(maxPointsPerResolver)
                    .ToArray();
                return new DnsResolverTrend
                {
                    CatalogId = group.Key,
                    Name = ordered.FirstOrDefault()?.Name ?? group.Key,
                    Provider = ordered.FirstOrDefault()?.Provider ?? string.Empty,
                    Points = ordered.Select(ToPoint).ToArray(),
                    Direction = TrendDirection(ordered),
                };
            })
            .OrderBy(x => x.Name, StringComparer.Ordinal)
            .ToArray();

        var events = dnsSettings
            .Select(ToDnsSettingsEvent)
            .Concat(promotions.Select(ToPromotionEvent))
            .OrderByDescending(x => x.ObservedAt)
            .Take(maxEvents)
            .ToArray();

        var newest = events.Select(x => (DateTimeOffset?)x.ObservedAt)
            .Concat(telemetry.Select(x => (DateTimeOffset?)DateTimeOffset.FromUnixTimeMilliseconds(x.ObservedAtUnixMs)))
            .Where(x => x is not null)
            .OrderByDescending(x => x)
            .FirstOrDefault();

        return new DnsHistorySnapshot
        {
            ResolverTrends = trends,
            Events = events,
            NewestAt = newest,
        };
    }

    public static string TrendDirection(IReadOnlyList<DnsResolverTelemetryItem> newestFirst)
    {
        if (newestFirst.Count < 4)
        {
            return "insufficient";
        }

        var count = Math.Min(newestFirst.Count, 10);
        var recentCount = count / 2;
        var recent = newestFirst.Take(recentCount).Average(x => Math.Clamp(x.HealthScore, 0d, 1d));
        var older = newestFirst.Skip(recentCount).Take(count - recentCount).Average(x => Math.Clamp(x.HealthScore, 0d, 1d));
        var delta = recent - older;

        return delta switch
        {
            >= 0.08d => "improving",
            <= -0.08d => "declining",
            _ => "stable",
        };
    }

    private static DnsResolverTrendPoint ToPoint(DnsResolverTelemetryItem item)
        => new()
        {
            ObservedAt = DateTimeOffset.FromUnixTimeMilliseconds(item.ObservedAtUnixMs),
            HealthClass = item.HealthClass,
            Quality = item.Quality,
            HealthScore = Math.Clamp(item.HealthScore, 0d, 1d),
            Reliability = Math.Clamp(item.ReliabilityFloor, 0d, 1d),
            MedianLatencyMs = item.MedianLatencyMs,
            QuorumTransportCount = item.QuorumTransportCount,
            InterceptionSuspected = item.InterceptionSuspected,
            Error = item.Error,
        };

    private static DnsHistoryEvent ToDnsSettingsEvent(DnsSettingsRepairHistoryItem item)
    {
        var action = item.EventKind == "rolled-back" ? "DNS rollback" : "DNS apply";
        return new DnsHistoryEvent
        {
            ObservedAt = DateTimeOffset.FromUnixTimeMilliseconds(item.ObservedAtUnixMs),
            Kind = $"dns-settings.{item.EventKind}",
            Summary = $"{action}: {item.ResolverCatalogId} · catalog {item.CatalogVersion}",
        };
    }

    private static DnsHistoryEvent ToPromotionEvent(RepairPromotionHistoryItem item)
    {
        var action = item.EventKind == "rolled-back" ? "Reviver rollback" : "Reviver promotion";
        var verdict = item.OutcomeVerdict.IsNullOrEmpty() ? string.Empty : $" · outcome {item.OutcomeVerdict}";
        return new DnsHistoryEvent
        {
            ObservedAt = DateTimeOffset.FromUnixTimeMilliseconds(item.ObservedAtUnixMs),
            Kind = $"reviver.{item.EventKind}",
            Summary = $"{action}: {item.OriginalProfileId} -> {item.PromotedProfileId}{verdict}",
        };
    }
}
