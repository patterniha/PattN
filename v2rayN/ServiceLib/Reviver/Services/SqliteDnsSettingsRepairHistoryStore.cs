using ServiceLib.Models.Entities;
using ServiceLib.Reviver.Models;

namespace ServiceLib.Reviver.Services;

public sealed class SqliteDnsSettingsRepairHistoryStore : IDnsSettingsRepairHistoryStore
{
    public Task RecordAppliedAsync(
        DnsSettingsRepairReceipt receipt,
        CancellationToken cancellationToken = default)
        => RecordAsync("applied", receipt, receipt.AppliedAt, cancellationToken);

    public Task RecordRolledBackAsync(
        DnsSettingsRepairReceipt receipt,
        CancellationToken cancellationToken = default)
        => RecordAsync("rolled-back", receipt, DateTimeOffset.UtcNow, cancellationToken);

    public async Task<DnsSettingsRepairReceipt?> GetLatestActiveAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var items = await SQLiteHelper.Instance.TableAsync<DnsSettingsRepairHistoryItem>().ToListAsync();
        var rolledBack = new HashSet<string>(StringComparer.Ordinal);

        foreach (var item in items.OrderByDescending(x => x.ObservedAtUnixMs))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (item.EventKind == "rolled-back")
            {
                rolledBack.Add(item.PlanId);
                continue;
            }
            if (item.EventKind != "applied" || rolledBack.Contains(item.PlanId) || item.ReceiptJson.IsNullOrEmpty())
            {
                continue;
            }

            var receipt = JsonUtils.Deserialize<DnsSettingsRepairReceipt>(item.ReceiptJson);
            if (receipt is not null)
            {
                return receipt;
            }
        }

        return null;
    }

    private static async Task RecordAsync(
        string eventKind,
        DnsSettingsRepairReceipt receipt,
        DateTimeOffset observedAt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        cancellationToken.ThrowIfCancellationRequested();

        await SQLiteHelper.Instance.InsertAsync(new DnsSettingsRepairHistoryItem
        {
            Id = Utils.GetGuid(false),
            EventKind = eventKind,
            PlanId = receipt.PlanId,
            ResolverCatalogId = receipt.ResolverCatalogId,
            CatalogVersion = receipt.CatalogVersion,
            ReceiptJson = JsonUtils.Serialize(receipt, false),
            ObservedAtUnixMs = observedAt.ToUnixTimeMilliseconds(),
        });
    }
}
