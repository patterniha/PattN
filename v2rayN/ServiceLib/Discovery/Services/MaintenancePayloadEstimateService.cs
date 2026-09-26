using ServiceLib.Discovery.Models;
using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Estimates serialized evidence payload represented by frozen maintenance plans. This is not a prediction
/// of immediate SQLite file-size reduction: SQLite may retain free pages until a later vacuum/compaction.
/// </summary>
public sealed class MaintenancePayloadEstimateService
{
    private const int EstimateQueryBatchSize = 400;

    public async Task<MaintenancePayloadEstimate> EstimateEndpointMaintenanceAsync(
        EndpointMaintenancePlan plan,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plan);
        cancellationToken.ThrowIfCancellationRequested();

        var ids = plan.PoolEntriesToRemove
            .Select(x => x.Id)
            .Where(x => !x.IsNullOrEmpty())
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (ids.Length == 0)
        {
            return new MaintenancePayloadEstimate();
        }

        var bytes = await SumRowsAsync<EndpointPoolItem>(
            ids,
            nameof(EndpointPoolItem),
            nameof(EndpointPoolItem.Id),
            cancellationToken);

        return new MaintenancePayloadEstimate
        {
            TotalBytes = bytes,
            BytesByCategory = new Dictionary<string, long>(StringComparer.Ordinal)
            {
                [nameof(EndpointPoolItem)] = bytes,
            },
        };
    }

    public async Task<MaintenancePayloadEstimate> EstimateLifecycleRetentionAsync(
        LifecycleRetentionPlan plan,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plan);
        cancellationToken.ThrowIfCancellationRequested();

        var values = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (var table in plan.Tables)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var ids = table.CandidateIds
                .Where(x => !x.IsNullOrEmpty())
                .Distinct(StringComparer.Ordinal)
                .ToArray();
            if (ids.Length == 0)
            {
                values[table.Table] = 0;
                continue;
            }

            values[table.Table] = table.Table switch
            {
                nameof(DnsRepairHistoryItem) => await SumRowsAsync<DnsRepairHistoryItem>(
                    ids,
                    nameof(DnsRepairHistoryItem),
                    nameof(DnsRepairHistoryItem.Id),
                    cancellationToken),
                nameof(DnsResolverTelemetryItem) => await SumRowsAsync<DnsResolverTelemetryItem>(
                    ids,
                    nameof(DnsResolverTelemetryItem),
                    nameof(DnsResolverTelemetryItem.Id),
                    cancellationToken),
                nameof(RepairPromotionHistoryItem) => await SumRowsAsync<RepairPromotionHistoryItem>(
                    ids,
                    nameof(RepairPromotionHistoryItem),
                    nameof(RepairPromotionHistoryItem.Id),
                    cancellationToken),
                nameof(EndpointObservationHistoryItem) => await SumRowsAsync<EndpointObservationHistoryItem>(
                    ids,
                    nameof(EndpointObservationHistoryItem),
                    nameof(EndpointObservationHistoryItem.Id),
                    cancellationToken),
                nameof(ProviderAsnCatalogRemoteApplyProvenanceItem) => await SumRowsAsync<ProviderAsnCatalogRemoteApplyProvenanceItem>(
                    ids,
                    nameof(ProviderAsnCatalogRemoteApplyProvenanceItem),
                    nameof(ProviderAsnCatalogRemoteApplyProvenanceItem.RevisionId),
                    cancellationToken),
                nameof(ProviderAsnCatalogRemoteSourceRevisionItem) => await SumRowsAsync<ProviderAsnCatalogRemoteSourceRevisionItem>(
                    ids,
                    nameof(ProviderAsnCatalogRemoteSourceRevisionItem),
                    nameof(ProviderAsnCatalogRemoteSourceRevisionItem.Id),
                    cancellationToken),
                _ => throw new InvalidOperationException($"Unknown lifecycle retention table '{table.Table}'."),
            };
        }

        return new MaintenancePayloadEstimate
        {
            TotalBytes = values.Values.Sum(),
            BytesByCategory = values,
        };
    }

    private static async Task<long> SumRowsAsync<T>(
        IReadOnlyList<string> ids,
        string tableName,
        string idColumn,
        CancellationToken cancellationToken)
        where T : new()
    {
        long total = 0;
        foreach (var batch in ids.Chunk(EstimateQueryBatchSize))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var placeholders = string.Join(",", batch.Select(_ => "?"));
            var rows = await SQLiteHelper.Instance.QueryAsync<T>(
                $"SELECT * FROM {tableName} WHERE {idColumn} IN ({placeholders})",
                batch.Cast<object>().ToArray());
            total += rows.Sum(x => SerializedBytes(x));
        }
        return total;
    }

    public static long SerializedBytes<T>(T value)
        => System.Text.Encoding.UTF8.GetByteCount(JsonUtils.Serialize(value, false));
}
