using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Protocol;
using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

public sealed class DnsHealthDashboardService
{
    private readonly Func<IDnsResolverTelemetryProbe> _probeFactory;
    private readonly TimeSpan _historyWindow;
    private readonly TimeSpan _halfLife;
    private readonly int _catalogMaxAgeDays;

    public DnsHealthDashboardService(
        Func<IDnsResolverTelemetryProbe>? probeFactory = null,
        TimeSpan? historyWindow = null,
        TimeSpan? halfLife = null,
        int catalogMaxAgeDays = 120)
    {
        _probeFactory = probeFactory ?? (() => new DiscoveryResolverTelemetryProbe());
        _historyWindow = historyWindow ?? TimeSpan.FromDays(90);
        _halfLife = halfLife ?? TimeSpan.FromDays(14);
        _catalogMaxAgeDays = Math.Clamp(catalogMaxAgeDays, 1, 3650);
    }

    public async Task<DnsHealthDashboardSnapshot> RefreshAsync(
        string probeDomain = "example.com",
        CancellationToken cancellationToken = default)
    {
        probeDomain = probeDomain.Trim().TrimEnd('.');
        if (probeDomain.IsNullOrEmpty())
        {
            throw new ArgumentException("Resolver telemetry probe domain is required.", nameof(probeDomain));
        }

        DiscoveryResolverCatalog? catalog = null;
        DiscoveryResolverCatalogAudit? audit = null;
        DateTimeOffset? auditObservedAt = null;
        var refreshErrors = new List<string>();

        try
        {
            await using var probe = _probeFactory();
            catalog = await probe.GetCatalogAsync(cancellationToken);
            try
            {
                audit = await probe.AuditCatalogAsync(_catalogMaxAgeDays, cancellationToken);
                auditObservedAt = DateTimeOffset.UtcNow;
                await PersistAuditAsync(catalog.Version, audit, auditObservedAt.Value, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                refreshErrors.Add($"catalog audit: {ex.Message}");
            }

            foreach (var resolver in catalog.Resolvers)
            {
                cancellationToken.ThrowIfCancellationRequested();
                await RefreshResolverAsync(probe, catalog.Version, resolver, probeDomain, refreshErrors, cancellationToken);
            }

        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            refreshErrors.Add(ex.Message);
        }

        var cached = await LoadCachedAsync(cancellationToken);
        var options = catalog is null
            ? Array.Empty<DnsResolverOption>()
            : catalog.Resolvers
                .Select(identity => ToOption(identity, cached.Resolvers.FirstOrDefault(x => x.CatalogId == identity.Id)))
                .OrderByDescending(x => x.ReferenceEligible)
                .ThenBy(x => x.IsSafeToApply ? 0 : 1)
                .ThenBy(x => x.Name, StringComparer.Ordinal)
                .ToArray();

        return cached with
        {
            DiscoveryAvailable = catalog is not null,
            CatalogVersion = catalog?.Version.NullIfEmpty() ?? cached.CatalogVersion,
            CatalogAuditKnown = audit is not null,
            CatalogValid = audit?.Valid ?? cached.CatalogValid,
            CatalogStaleCount = audit?.StaleCount ?? cached.CatalogStaleCount,
            CatalogMaxAgeDays = audit?.MaxAgeDays ?? cached.CatalogMaxAgeDays,
            CatalogAuditedAt = auditObservedAt ?? cached.CatalogAuditedAt,
            ResolverOptions = options,
            Error = string.Join("; ", refreshErrors.Where(x => !x.IsNullOrEmpty()).Distinct(StringComparer.Ordinal)),
        };
    }

    public async Task<DnsHealthDashboardSnapshot> LoadCachedAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var cutoff = DateTimeOffset.UtcNow.Subtract(_historyWindow).ToUnixTimeMilliseconds();
        var records = await SQLiteHelper.Instance.TableAsync<DnsResolverTelemetryItem>()
            .Where(x => x.ObservedAtUnixMs >= cutoff)
            .ToListAsync();

        var cachedAudit = await SQLiteHelper.Instance.TableAsync<DnsResolverCatalogAuditItem>()
            .Where(x => x.Id == "builtin")
            .FirstOrDefaultAsync();

        var rows = records
            .GroupBy(x => x.ResolverCatalogId, StringComparer.Ordinal)
            .Select(group => ToRow(group.OrderByDescending(x => x.ObservedAtUnixMs).First()))
            .OrderByDescending(x => x.ReferenceEligible)
            .ThenBy(x => HealthOrder(x.HealthClass))
            .ThenBy(x => x.Name, StringComparer.Ordinal)
            .ToArray();

        var newest = records.Count == 0
            ? (DateTimeOffset?)null
            : DateTimeOffset.FromUnixTimeMilliseconds(records.Max(x => x.ObservedAtUnixMs));
        var latestVersion = records
            .OrderByDescending(x => x.ObservedAtUnixMs)
            .Select(x => x.CatalogVersion)
            .FirstOrDefault(x => !x.IsNullOrEmpty()) ?? string.Empty;

        return new DnsHealthDashboardSnapshot
        {
            DiscoveryAvailable = false,
            CatalogVersion = cachedAudit?.CatalogVersion.NullIfEmpty() ?? latestVersion,
            CatalogAuditKnown = cachedAudit is not null,
            CatalogValid = cachedAudit?.Valid ?? false,
            CatalogStaleCount = cachedAudit?.StaleCount ?? 0,
            CatalogMaxAgeDays = cachedAudit?.MaxAgeDays ?? _catalogMaxAgeDays,
            CatalogAuditedAt = cachedAudit is null ? null : DateTimeOffset.FromUnixTimeMilliseconds(cachedAudit.AuditedAtUnixMs),
            Resolvers = rows,
            RefreshedAt = newest,
        };
    }

    public async Task PruneAsync(
        TimeSpan? maxAge = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var age = maxAge ?? _historyWindow;
        if (age <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(maxAge));
        }
        var cutoff = DateTimeOffset.UtcNow.Subtract(age).ToUnixTimeMilliseconds();
        var stale = await SQLiteHelper.Instance.TableAsync<DnsResolverTelemetryItem>()
            .Where(x => x.ObservedAtUnixMs < cutoff)
            .ToListAsync();
        foreach (var item in stale)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await SQLiteHelper.Instance.DeleteAsync(item);
        }
    }

    private static async Task PersistAuditAsync(
        string catalogVersion,
        DiscoveryResolverCatalogAudit audit,
        DateTimeOffset observedAt,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await SQLiteHelper.Instance.ReplaceAsync(new DnsResolverCatalogAuditItem
        {
            Id = "builtin",
            CatalogVersion = catalogVersion.NullIfEmpty() ?? audit.Version,
            Valid = audit.Valid,
            MaxAgeDays = audit.MaxAgeDays,
            StaleCount = audit.StaleCount,
            AuditedAtUnixMs = observedAt.ToUnixTimeMilliseconds(),
            EntriesJson = JsonUtils.Serialize(audit.Entries, false),
            Error = audit.Error,
        });
    }

    private async Task RefreshResolverAsync(
        IDnsResolverTelemetryProbe probe,
        string catalogVersion,
        DiscoveryResolverCatalogIdentity resolver,
        string probeDomain,
        List<string> refreshErrors,
        CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var previous = await LatestForAsync(resolver.Id, cancellationToken);

        var item = new DnsResolverTelemetryItem
        {
            Id = Utils.GetGuid(false),
            ResolverCatalogId = resolver.Id,
            CatalogVersion = catalogVersion,
            Provider = resolver.Provider,
            Name = resolver.Name,
            Policy = resolver.Policy,
            ReferenceEligible = resolver.ReferenceEligible,
            ObservedAtUnixMs = now.ToUnixTimeMilliseconds(),
        };

        try
        {
            var profiled = await ProfileWithFamilyFallbackAsync(
                probe,
                resolver,
                probeDomain,
                cancellationToken);
            item.Address = profiled.Address;
            var result = profiled.Result;

            item.Quality = result.Quality.NullIfEmpty() ?? "unknown";
            item.Status = result.Status.NullIfEmpty() ?? "unknown";
            item.ReliabilityFloor = Clamp01(result.ReliabilityFloor);
            item.QuorumTransportCount = result.QuorumTransportCount;
            item.InterceptionSuspected = result.InterceptionSuspected;
            item.MedianLatencyMs = MedianLatency(result);
            item.ReasonCodes = string.Join(
                ",",
                result.QualityReasons.Concat(result.InterceptionReasons).Distinct(StringComparer.Ordinal));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            item.Quality = "unknown";
            item.Status = "unavailable";
            item.Error = ex.Message;
            refreshErrors.Add($"{resolver.Id}: {ex.Message}");
        }

        var historical = await HistoryForAsync(resolver.Id, cancellationToken);
        var score = ComputeDecayedHealthScore(historical.Append(item), now, _halfLife);
        item.HealthScore = score;
        item.HealthClass = ClassifyHealth(score, previous?.HealthClass, item.InterceptionSuspected, !item.Error.IsNullOrEmpty());

        await SQLiteHelper.Instance.InsertAsync(item);
    }

    private static async Task<(string Address, DiscoveryResolverProfileResult Result)> ProfileWithFamilyFallbackAsync(
        IDnsResolverTelemetryProbe probe,
        DiscoveryResolverCatalogIdentity resolver,
        string probeDomain,
        CancellationToken cancellationToken)
    {
        var addresses = new[]
        {
            resolver.IPv4.FirstOrDefault(),
            resolver.IPv6.FirstOrDefault(),
        }
        .Where(x => !x.IsNullOrEmpty())
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();

        if (addresses.Length == 0)
        {
            throw new InvalidOperationException("resolver catalog entry has no address");
        }

        DiscoveryResolverProfileResult? lastResult = null;
        string? lastResultAddress = null;
        Exception? lastError = null;

        foreach (var address in addresses)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var result = await probe.ProfileAsync(
                    new DiscoveryResolverProfileRequest
                    {
                        Address = address!,
                        Port = resolver.Port,
                        Domain = probeDomain,
                        Attempts = 3,
                        MinSuccesses = 2,
                        ServerName = resolver.DotServerName,
                        DotPort = resolver.DotPort,
                        DohUrl = resolver.DohUrl,
                        CheckUdp = true,
                        CheckTcp = true,
                        CheckEdns = true,
                        CheckTxt = true,
                        CheckDot = !resolver.DotServerName.IsNullOrEmpty(),
                        CheckDoh = !resolver.DohUrl.IsNullOrEmpty(),
                    },
                    cancellationToken);

                lastResult = result;
                lastResultAddress = address!;
                if (result.QuorumTransportCount > 0)
                {
                    return (address!, result);
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                lastError = ex;
            }
        }

        if (lastResult is not null && !lastResultAddress.IsNullOrEmpty())
        {
            return (lastResultAddress!, lastResult);
        }
        throw new InvalidOperationException(
            $"resolver profiling failed on all catalog address families: {lastError?.Message ?? "unknown error"}",
            lastError);
    }

    private async Task<DnsResolverTelemetryItem?> LatestForAsync(
        string resolverId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return await SQLiteHelper.Instance.TableAsync<DnsResolverTelemetryItem>()
            .Where(x => x.ResolverCatalogId == resolverId)
            .OrderByDescending(x => x.ObservedAtUnixMs)
            .FirstOrDefaultAsync();
    }

    private async Task<IReadOnlyList<DnsResolverTelemetryItem>> HistoryForAsync(
        string resolverId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var cutoff = DateTimeOffset.UtcNow.Subtract(_historyWindow).ToUnixTimeMilliseconds();
        return await SQLiteHelper.Instance.TableAsync<DnsResolverTelemetryItem>()
            .Where(x => x.ResolverCatalogId == resolverId && x.ObservedAtUnixMs >= cutoff)
            .ToListAsync();
    }

    public static double ComputeDecayedHealthScore(
        IEnumerable<DnsResolverTelemetryItem> records,
        DateTimeOffset now,
        TimeSpan halfLife)
    {
        if (halfLife <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(halfLife));
        }

        double weighted = 0;
        double weights = 0;
        foreach (var item in records)
        {
            var observed = DateTimeOffset.FromUnixTimeMilliseconds(item.ObservedAtUnixMs);
            var ageSeconds = Math.Max(0, (now - observed).TotalSeconds);
            var weight = Math.Exp(-Math.Log(2d) * ageSeconds / halfLife.TotalSeconds);
            var quality = QualityScore(item.Quality);
            var score = Clamp01(item.ReliabilityFloor * 0.65d + quality * 0.35d);
            if (item.InterceptionSuspected)
            {
                score = Math.Min(score, 0.12d);
            }
            if (!item.Error.IsNullOrEmpty())
            {
                score = 0d;
            }

            weighted += score * weight;
            weights += weight;
        }
        return weights <= 0 ? 0.5d : Clamp01(weighted / weights);
    }

    public static string ClassifyHealth(
        double score,
        string? previousClass,
        bool interceptionSuspected = false,
        bool unavailable = false)
    {
        if (interceptionSuspected)
        {
            return "suspicious";
        }
        if (unavailable)
        {
            return "unavailable";
        }

        score = Clamp01(score);
        return previousClass switch
        {
            "healthy" => score >= 0.62d
                ? "healthy"
                : score < 0.45d
                    ? "degraded"
                    : "watch",
            "degraded" => score >= 0.82d
                ? "healthy"
                : score <= 0.68d
                    ? "degraded"
                    : "watch",
            "watch" => score >= 0.78d
                ? "healthy"
                : score <= 0.50d
                    ? "degraded"
                    : "watch",
            "suspicious" or "unavailable" => score <= 0.52d ? "degraded" : "watch",
            _ => score >= 0.75d
                ? "healthy"
                : score <= 0.52d
                    ? "degraded"
                    : "watch",
        };
    }

    private static DnsResolverHealthRow ToRow(DnsResolverTelemetryItem item)
        => new()
        {
            CatalogId = item.ResolverCatalogId,
            Name = item.Name,
            Provider = item.Provider,
            Policy = item.Policy,
            ReferenceEligible = item.ReferenceEligible,
            Address = item.Address,
            Quality = item.Quality.NullIfEmpty() ?? "unknown",
            HealthClass = item.HealthClass.NullIfEmpty() ?? "watch",
            Reliability = Clamp01(item.ReliabilityFloor),
            QuorumTransportCount = item.QuorumTransportCount,
            HealthScore = Clamp01(item.HealthScore),
            MedianLatencyMs = item.MedianLatencyMs,
            InterceptionSuspected = item.InterceptionSuspected,
            Reasons = item.ReasonCodes
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
            Error = item.Error,
            ObservedAt = DateTimeOffset.FromUnixTimeMilliseconds(item.ObservedAtUnixMs),
        };

    private static DnsResolverOption ToOption(
        DiscoveryResolverCatalogIdentity identity,
        DnsResolverHealthRow? health)
        => new()
        {
            CatalogId = identity.Id,
            Provider = identity.Provider,
            Name = identity.Name,
            IPv4 = identity.IPv4,
            IPv6 = identity.IPv6,
            Port = identity.Port,
            DotServerName = identity.DotServerName,
            DotPort = identity.DotPort,
            DohUrl = identity.DohUrl,
            Policy = identity.Policy,
            ReferenceEligible = identity.ReferenceEligible,
            HealthClass = health?.HealthClass ?? "unavailable",
            Quality = health?.Quality ?? "unknown",
            QuorumTransportCount = health?.QuorumTransportCount ?? 0,
            InterceptionSuspected = health?.InterceptionSuspected ?? false,
        };

    private static double? MedianLatency(DiscoveryResolverProfileResult result)
    {
        var values = new[]
        {
            result.Udp?.MedianLatencyMs,
            result.Tcp?.MedianLatencyMs,
            result.Dot?.MedianLatencyMs,
            result.Doh?.MedianLatencyMs,
        }
        .Where(x => x is > 0)
        .Select(x => x!.Value)
        .OrderBy(x => x)
        .ToArray();

        if (values.Length == 0)
        {
            return null;
        }
        var middle = values.Length / 2;
        return values.Length % 2 == 1
            ? values[middle]
            : (values[middle - 1] + values[middle]) / 2d;
    }

    private static double QualityScore(string? quality)
        => quality?.Trim().ToLowerInvariant() switch
        {
            "strong" => 1d,
            "usable" => 0.82d,
            "degraded" => 0.58d,
            "unstable" => 0.30d,
            "suspicious" => 0.08d,
            "unusable" => 0d,
            _ => 0.5d,
        };

    private static int HealthOrder(string value)
        => value switch
        {
            "healthy" => 0,
            "watch" => 1,
            "degraded" => 2,
            "suspicious" => 3,
            "unavailable" => 4,
            _ => 5,
        };

    private static double Clamp01(double value) => Math.Clamp(value, 0d, 1d);
}
