using ServiceLib.Discovery.Models;
using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Explicit bounded retention for append-only lifecycle evidence. Preview freezes exact IDs; apply deletes only
/// those IDs, so records created after preview cannot be swept into the same maintenance action.
/// </summary>
public sealed class LifecycleRetentionService
{
    // Stay comfortably below SQLite's common host-parameter limit while ensuring
    // retention apply materializes at most the IDs frozen into the plan.
    private const int RetentionQueryBatchSize = 400;

    public async Task<LifecycleRetentionPlan> PreviewAsync(
        LifecycleRetentionPolicy? policy = null,
        DateTimeOffset? now = null,
        CancellationToken cancellationToken = default)
    {
        policy ??= new LifecycleRetentionPolicy();
        Validate(policy);
        cancellationToken.ThrowIfCancellationRequested();

        var createdAt = now ?? DateTimeOffset.UtcNow;
        var tables = new[]
        {
            new LifecycleRetentionTablePlan
            {
                Table = nameof(DnsRepairHistoryItem),
                CutoffUnixMs = createdAt.Subtract(policy.DnsRepairHistoryRetention).ToUnixTimeMilliseconds(),
                CandidateIds = await SelectDnsRepairIdsAsync(
                    createdAt.Subtract(policy.DnsRepairHistoryRetention).ToUnixTimeMilliseconds(),
                    policy.MaximumDeletesPerTable,
                    cancellationToken),
            },
            new LifecycleRetentionTablePlan
            {
                Table = nameof(DnsResolverTelemetryItem),
                CutoffUnixMs = createdAt.Subtract(policy.ResolverTelemetryRetention).ToUnixTimeMilliseconds(),
                CandidateIds = await SelectResolverTelemetryIdsAsync(
                    createdAt.Subtract(policy.ResolverTelemetryRetention).ToUnixTimeMilliseconds(),
                    policy.MaximumDeletesPerTable,
                    cancellationToken),
            },
            new LifecycleRetentionTablePlan
            {
                Table = nameof(RepairPromotionHistoryItem),
                CutoffUnixMs = createdAt.Subtract(policy.PromotionHistoryRetention).ToUnixTimeMilliseconds(),
                CandidateIds = await SelectPromotionHistoryIdsAsync(
                    createdAt.Subtract(policy.PromotionHistoryRetention).ToUnixTimeMilliseconds(),
                    policy.MaximumDeletesPerTable,
                    cancellationToken),
            },
            new LifecycleRetentionTablePlan
            {
                Table = nameof(EndpointObservationHistoryItem),
                CutoffUnixMs = createdAt.Subtract(policy.EndpointObservationRetention).ToUnixTimeMilliseconds(),
                CandidateIds = await SelectEndpointObservationIdsAsync(
                    createdAt.Subtract(policy.EndpointObservationRetention).ToUnixTimeMilliseconds(),
                    policy.MaximumDeletesPerTable,
                    cancellationToken),
            },
            new LifecycleRetentionTablePlan
            {
                Table = nameof(ProviderAsnCatalogRemoteApplyProvenanceItem),
                CutoffUnixMs = createdAt.Subtract(policy.RemoteCatalogProvenanceRetention).ToUnixTimeMilliseconds(),
                CandidateIds = await SelectRemoteCatalogProvenanceIdsAsync(
                    createdAt.Subtract(policy.RemoteCatalogProvenanceRetention).ToUnixTimeMilliseconds(),
                    policy.MaximumDeletesPerTable,
                    cancellationToken),
            },
            new LifecycleRetentionTablePlan
            {
                Table = nameof(ProviderAsnCatalogRemoteSourceRevisionItem),
                CutoffUnixMs = createdAt.Subtract(policy.RemoteSourceRevisionRetention).ToUnixTimeMilliseconds(),
                CandidateIds = await SelectRemoteSourceRevisionIdsAsync(
                    createdAt.Subtract(policy.RemoteSourceRevisionRetention).ToUnixTimeMilliseconds(),
                    policy.MaximumDeletesPerTable,
                    cancellationToken),
            },
        };

        return new LifecycleRetentionPlan
        {
            CreatedAt = createdAt,
            Policy = policy,
            Tables = tables,
        };
    }

    public async Task<LifecycleRetentionResult> ApplyAsync(
        LifecycleRetentionPlan plan,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plan);
        Validate(plan.Policy);
        ValidatePlan(plan);
        cancellationToken.ThrowIfCancellationRequested();

        var results = new List<LifecycleRetentionTableResult>(plan.Tables.Count);
        foreach (var table in plan.Tables)
        {
            cancellationToken.ThrowIfCancellationRequested();
            results.Add(table.Table switch
            {
                nameof(DnsRepairHistoryItem) => await DeleteDnsRepairAsync(table, cancellationToken),
                nameof(DnsResolverTelemetryItem) => await DeleteResolverTelemetryAsync(table, cancellationToken),
                nameof(RepairPromotionHistoryItem) => await DeletePromotionHistoryAsync(table, cancellationToken),
                nameof(EndpointObservationHistoryItem) => await DeleteEndpointObservationsAsync(table, cancellationToken),
                nameof(ProviderAsnCatalogRemoteApplyProvenanceItem) => await DeleteRemoteCatalogProvenanceAsync(table, cancellationToken),
                nameof(ProviderAsnCatalogRemoteSourceRevisionItem) => await DeleteRemoteSourceRevisionsAsync(table, cancellationToken),
                _ => throw new InvalidOperationException($"Unknown lifecycle retention table '{table.Table}'."),
            });
        }

        return new LifecycleRetentionResult
        {
            Planned = results.Sum(x => x.Planned),
            Deleted = results.Sum(x => x.Deleted),
            AlreadyMissing = results.Sum(x => x.AlreadyMissing),
            Tables = results,
        };
    }

    public async Task<LifecycleRetentionResult> RunAsync(
        LifecycleRetentionPolicy? policy = null,
        DateTimeOffset? now = null,
        CancellationToken cancellationToken = default)
    {
        var plan = await PreviewAsync(policy, now, cancellationToken);
        return await ApplyAsync(plan, cancellationToken);
    }

    public static IReadOnlyList<string> SelectCandidateIds<T>(
        IEnumerable<T> rows,
        long cutoffUnixMs,
        int maximum,
        Func<T, long> timestamp,
        Func<T, string> id)
    {
        ArgumentNullException.ThrowIfNull(rows);
        ArgumentNullException.ThrowIfNull(timestamp);
        ArgumentNullException.ThrowIfNull(id);
        if (maximum < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maximum));
        }

        return rows
            .Where(x => timestamp(x) < cutoffUnixMs)
            .OrderBy(timestamp)
            .ThenBy(id, StringComparer.Ordinal)
            .Select(id)
            .Where(x => !x.IsNullOrEmpty())
            .Distinct(StringComparer.Ordinal)
            .Take(maximum)
            .ToArray();
    }

    private static async Task<IReadOnlyList<string>> SelectDnsRepairIdsAsync(
        long cutoffUnixMs,
        int maximum,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var rows = await SQLiteHelper.Instance.TableAsync<DnsRepairHistoryItem>()
            .Where(x => x.ObservedAtUnixMs < cutoffUnixMs)
            .OrderBy(x => x.ObservedAtUnixMs)
            .Take(maximum)
            .ToListAsync();
        return rows.Select(x => x.Id).Where(x => !x.IsNullOrEmpty()).Distinct(StringComparer.Ordinal).ToArray();
    }

    private static async Task<IReadOnlyList<string>> SelectResolverTelemetryIdsAsync(
        long cutoffUnixMs,
        int maximum,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var rows = await SQLiteHelper.Instance.TableAsync<DnsResolverTelemetryItem>()
            .Where(x => x.ObservedAtUnixMs < cutoffUnixMs)
            .OrderBy(x => x.ObservedAtUnixMs)
            .Take(maximum)
            .ToListAsync();
        return rows.Select(x => x.Id).Where(x => !x.IsNullOrEmpty()).Distinct(StringComparer.Ordinal).ToArray();
    }

    private static async Task<IReadOnlyList<string>> SelectPromotionHistoryIdsAsync(
        long cutoffUnixMs,
        int maximum,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var rows = await SQLiteHelper.Instance.TableAsync<RepairPromotionHistoryItem>()
            .Where(x => x.ObservedAtUnixMs < cutoffUnixMs)
            .OrderBy(x => x.ObservedAtUnixMs)
            .Take(maximum)
            .ToListAsync();
        return rows.Select(x => x.Id).Where(x => !x.IsNullOrEmpty()).Distinct(StringComparer.Ordinal).ToArray();
    }

    private static async Task<IReadOnlyList<string>> SelectEndpointObservationIdsAsync(
        long cutoffUnixMs,
        int maximum,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var rows = await SQLiteHelper.Instance.TableAsync<EndpointObservationHistoryItem>()
            .Where(x => x.ObservedAtUnixMs < cutoffUnixMs)
            .OrderBy(x => x.ObservedAtUnixMs)
            .Take(maximum)
            .ToListAsync();
        return rows.Select(x => x.Id).Where(x => !x.IsNullOrEmpty()).Distinct(StringComparer.Ordinal).ToArray();
    }

    private static async Task<IReadOnlyList<string>> SelectRemoteSourceRevisionIdsAsync(
        long cutoffUnixMs,
        int maximum,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var rows = await SQLiteHelper.Instance.TableAsync<ProviderAsnCatalogRemoteSourceRevisionItem>()
            .Where(x => x.ChangedAtUnixMs < cutoffUnixMs)
            .OrderBy(x => x.ChangedAtUnixMs)
            .Take(maximum)
            .ToListAsync();
        return rows.Select(x => x.Id)
            .Where(x => !x.IsNullOrEmpty())
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    public static bool IsRemoteProvenanceRetentionEligible(
        ProviderAsnCatalogRemoteApplyProvenanceItem item,
        ProviderAsnCatalogRevisionItem? revision,
        long cutoffUnixMs)
    {
        ArgumentNullException.ThrowIfNull(item);
        return item.AppliedAtUnixMs < cutoffUnixMs
               && (revision is null || revision.RolledBackAtUnixMs is not null);
    }

    private static async Task<IReadOnlyList<string>> SelectRemoteCatalogProvenanceIdsAsync(
        long cutoffUnixMs,
        int maximum,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // Eligibility depends on both provenance age and whether its corresponding
        // catalog revision still survives. Perform that join in SQLite and apply the
        // retention budget there so preview memory/work remains bounded.
        var sql =
            $"SELECT p.* FROM {nameof(ProviderAsnCatalogRemoteApplyProvenanceItem)} p " +
            $"LEFT JOIN {nameof(ProviderAsnCatalogRevisionItem)} r ON r.Id = p.RevisionId " +
            "WHERE p.AppliedAtUnixMs < ? " +
            "AND (r.Id IS NULL OR r.RolledBackAtUnixMs IS NOT NULL) " +
            "ORDER BY p.AppliedAtUnixMs ASC, p.RevisionId ASC LIMIT ?";
        var rows = await SQLiteHelper.Instance.QueryAsync<ProviderAsnCatalogRemoteApplyProvenanceItem>(
            sql,
            cutoffUnixMs,
            maximum);

        return rows.Select(x => x.RevisionId)
            .Where(x => !x.IsNullOrEmpty())
            .Distinct(StringComparer.Ordinal)
            .Take(maximum)
            .ToArray();
    }

    private static Task<LifecycleRetentionTableResult> DeleteDnsRepairAsync(
        LifecycleRetentionTablePlan table,
        CancellationToken cancellationToken)
        => DeletePlannedRowsAsync<DnsRepairHistoryItem>(
            table,
            nameof(DnsRepairHistoryItem),
            nameof(DnsRepairHistoryItem.Id),
            nameof(DnsRepairHistoryItem.ObservedAtUnixMs),
            x => x.Id,
            cancellationToken);

    private static Task<LifecycleRetentionTableResult> DeleteResolverTelemetryAsync(
        LifecycleRetentionTablePlan table,
        CancellationToken cancellationToken)
        => DeletePlannedRowsAsync<DnsResolverTelemetryItem>(
            table,
            nameof(DnsResolverTelemetryItem),
            nameof(DnsResolverTelemetryItem.Id),
            nameof(DnsResolverTelemetryItem.ObservedAtUnixMs),
            x => x.Id,
            cancellationToken);

    private static Task<LifecycleRetentionTableResult> DeletePromotionHistoryAsync(
        LifecycleRetentionTablePlan table,
        CancellationToken cancellationToken)
        => DeletePlannedRowsAsync<RepairPromotionHistoryItem>(
            table,
            nameof(RepairPromotionHistoryItem),
            nameof(RepairPromotionHistoryItem.Id),
            nameof(RepairPromotionHistoryItem.ObservedAtUnixMs),
            x => x.Id,
            cancellationToken);

    private static Task<LifecycleRetentionTableResult> DeleteEndpointObservationsAsync(
        LifecycleRetentionTablePlan table,
        CancellationToken cancellationToken)
        => DeletePlannedRowsAsync<EndpointObservationHistoryItem>(
            table,
            nameof(EndpointObservationHistoryItem),
            nameof(EndpointObservationHistoryItem.Id),
            nameof(EndpointObservationHistoryItem.ObservedAtUnixMs),
            x => x.Id,
            cancellationToken);

    private static Task<LifecycleRetentionTableResult> DeleteRemoteSourceRevisionsAsync(
        LifecycleRetentionTablePlan table,
        CancellationToken cancellationToken)
        => DeletePlannedRowsAsync<ProviderAsnCatalogRemoteSourceRevisionItem>(
            table,
            nameof(ProviderAsnCatalogRemoteSourceRevisionItem),
            nameof(ProviderAsnCatalogRemoteSourceRevisionItem.Id),
            nameof(ProviderAsnCatalogRemoteSourceRevisionItem.ChangedAtUnixMs),
            x => x.Id,
            cancellationToken);

    private static async Task<LifecycleRetentionTableResult> DeleteRemoteCatalogProvenanceAsync(
        LifecycleRetentionTablePlan table,
        CancellationToken cancellationToken)
    {
        var planned = table.CandidateIds.ToHashSet(StringComparer.Ordinal);
        if (planned.Count == 0)
        {
            return new LifecycleRetentionTableResult { Table = table.Table };
        }

        var rows = new List<ProviderAsnCatalogRemoteApplyProvenanceItem>(planned.Count);
        foreach (var batch in table.CandidateIds.Chunk(RetentionQueryBatchSize))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var placeholders = string.Join(",", batch.Select(_ => "?"));
            var sql =
                $"SELECT p.* FROM {nameof(ProviderAsnCatalogRemoteApplyProvenanceItem)} p " +
                $"LEFT JOIN {nameof(ProviderAsnCatalogRevisionItem)} r ON r.Id = p.RevisionId " +
                $"WHERE p.RevisionId IN ({placeholders}) " +
                "AND p.AppliedAtUnixMs < ? " +
                "AND (r.Id IS NULL OR r.RolledBackAtUnixMs IS NOT NULL)";
            var args = batch.Cast<object>().Append(table.CutoffUnixMs).ToArray();
            rows.AddRange(
                await SQLiteHelper.Instance.QueryAsync<ProviderAsnCatalogRemoteApplyProvenanceItem>(
                    sql,
                    args));
        }

        // Rechecking revision eligibility at apply prevents a preview that was valid
        // when a revision was absent/retired from deleting provenance if reconciliation
        // makes that revision surviving evidence before apply.
        return await DeleteRowsAsync(table, rows, x => x.RevisionId, cancellationToken);
    }

    private static async Task<LifecycleRetentionTableResult> DeletePlannedRowsAsync<T>(
        LifecycleRetentionTablePlan table,
        string tableName,
        string idColumn,
        string timestampColumn,
        Func<T, string> id,
        CancellationToken cancellationToken)
        where T : new()
    {
        var planned = table.CandidateIds.ToHashSet(StringComparer.Ordinal);
        if (planned.Count == 0)
        {
            return new LifecycleRetentionTableResult { Table = table.Table };
        }

        var rows = new List<T>(planned.Count);
        foreach (var batch in table.CandidateIds.Chunk(RetentionQueryBatchSize))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var placeholders = string.Join(",", batch.Select(_ => "?"));
            var sql =
                $"SELECT * FROM {tableName} WHERE {idColumn} IN ({placeholders}) " +
                $"AND {timestampColumn} < ?";
            var args = batch.Cast<object>().Append(table.CutoffUnixMs).ToArray();
            rows.AddRange(await SQLiteHelper.Instance.QueryAsync<T>(sql, args));
        }

        return await DeleteRowsAsync(table, rows, id, cancellationToken);
    }

    internal static async Task<LifecycleRetentionTableResult> DeleteRowsAsync<T>(
        LifecycleRetentionTablePlan table,
        IReadOnlyList<T> rows,
        Func<T, string> id,
        CancellationToken cancellationToken,
        Func<T, CancellationToken, Task<int>>? deleteRow = null)
    {
        var planned = table.CandidateIds.ToHashSet(StringComparer.Ordinal);
        if (planned.Count == 0)
        {
            return new LifecycleRetentionTableResult { Table = table.Table };
        }

        var matches = rows
            .Where(x => planned.Contains(id(x)))
            .ToArray();

        deleteRow ??= (row, _) => SQLiteHelper.Instance.DeleteAsync(row!);

        var deleted = 0;
        foreach (var row in matches)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (await deleteRow(row, cancellationToken) > 0)
            {
                deleted++;
            }
        }

        return new LifecycleRetentionTableResult
        {
            Table = table.Table,
            Planned = planned.Count,
            Deleted = deleted,
            AlreadyMissing = planned.Count - deleted,
        };
    }

    private static void ValidatePlan(LifecycleRetentionPlan plan)
    {
        var allowed = new HashSet<string>(StringComparer.Ordinal)
        {
            nameof(DnsRepairHistoryItem),
            nameof(DnsResolverTelemetryItem),
            nameof(RepairPromotionHistoryItem),
            nameof(EndpointObservationHistoryItem),
            nameof(ProviderAsnCatalogRemoteApplyProvenanceItem),
            nameof(ProviderAsnCatalogRemoteSourceRevisionItem),
        };
        var seen = new HashSet<string>(StringComparer.Ordinal);

        if (plan.CreatedAt == default)
        {
            throw new InvalidOperationException("Lifecycle retention plan is missing its creation timestamp.");
        }

        foreach (var table in plan.Tables)
        {
            if (!allowed.Contains(table.Table))
            {
                throw new InvalidOperationException($"Unknown lifecycle retention table '{table.Table}'.");
            }
            if (!seen.Add(table.Table))
            {
                throw new InvalidOperationException($"Duplicate lifecycle retention table plan '{table.Table}'.");
            }

            var expectedCutoff = table.Table switch
            {
                nameof(DnsRepairHistoryItem) => plan.CreatedAt.Subtract(plan.Policy.DnsRepairHistoryRetention).ToUnixTimeMilliseconds(),
                nameof(DnsResolverTelemetryItem) => plan.CreatedAt.Subtract(plan.Policy.ResolverTelemetryRetention).ToUnixTimeMilliseconds(),
                nameof(RepairPromotionHistoryItem) => plan.CreatedAt.Subtract(plan.Policy.PromotionHistoryRetention).ToUnixTimeMilliseconds(),
                nameof(EndpointObservationHistoryItem) => plan.CreatedAt.Subtract(plan.Policy.EndpointObservationRetention).ToUnixTimeMilliseconds(),
                nameof(ProviderAsnCatalogRemoteApplyProvenanceItem) => plan.CreatedAt.Subtract(plan.Policy.RemoteCatalogProvenanceRetention).ToUnixTimeMilliseconds(),
                nameof(ProviderAsnCatalogRemoteSourceRevisionItem) => plan.CreatedAt.Subtract(plan.Policy.RemoteSourceRevisionRetention).ToUnixTimeMilliseconds(),
                _ => throw new InvalidOperationException($"Unknown lifecycle retention table '{table.Table}'."),
            };
            if (table.CutoffUnixMs != expectedCutoff)
            {
                throw new InvalidOperationException($"Lifecycle retention cutoff for '{table.Table}' does not match the frozen plan policy.");
            }
            if (table.CandidateIds.Count > plan.Policy.MaximumDeletesPerTable)
            {
                throw new InvalidOperationException($"Lifecycle retention table '{table.Table}' exceeds its delete budget.");
            }
            if (table.CandidateIds.Any(x => x.IsNullOrEmpty())
                || table.CandidateIds.Distinct(StringComparer.Ordinal).Count() != table.CandidateIds.Count)
            {
                throw new InvalidOperationException($"Lifecycle retention table '{table.Table}' contains invalid or duplicate IDs.");
            }
        }
    }

    private static void Validate(LifecycleRetentionPolicy policy)
    {
        var values = new[]
        {
            policy.DnsRepairHistoryRetention,
            policy.ResolverTelemetryRetention,
            policy.PromotionHistoryRetention,
            policy.EndpointObservationRetention,
            policy.RemoteCatalogProvenanceRetention,
            policy.RemoteSourceRevisionRetention,
        };
        if (values.Any(x => x <= TimeSpan.Zero || x > TimeSpan.FromDays(3650)))
        {
            throw new ArgumentOutOfRangeException(nameof(policy), "Lifecycle retention windows must be greater than zero and no more than 10 years.");
        }
        if (policy.MaximumDeletesPerTable is < 1 or > 10000)
        {
            throw new ArgumentOutOfRangeException(nameof(policy.MaximumDeletesPerTable), "Lifecycle retention delete limit must be between 1 and 10000 per table.");
        }
    }
}
