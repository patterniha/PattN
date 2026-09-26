using ServiceLib.Reviver.Models;

namespace ServiceLib.Reviver.Services;

public interface IRepairPromotionHistoryStore
{
    Task RecordPromotedAsync(
        RepairPromotionPlan plan,
        RepairPromotionReceipt receipt,
        CancellationToken cancellationToken = default);

    Task RecordRolledBackAsync(
        RepairPromotionReceipt receipt,
        CancellationToken cancellationToken = default);
}
