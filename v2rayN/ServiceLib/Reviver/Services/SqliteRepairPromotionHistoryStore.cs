using ServiceLib.Models.Entities;
using ServiceLib.Reviver.Models;

namespace ServiceLib.Reviver.Services;

public sealed class SqliteRepairPromotionHistoryStore : IRepairPromotionHistoryStore
{
    public async Task RecordPromotedAsync(
        RepairPromotionPlan plan,
        RepairPromotionReceipt receipt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(receipt);
        cancellationToken.ThrowIfCancellationRequested();

        await SQLiteHelper.Instance.InsertAsync(new RepairPromotionHistoryItem
        {
            Id = Utils.GetGuid(false),
            EventKind = "promoted",
            SessionId = receipt.SessionId,
            CandidateId = receipt.CandidateId,
            OriginalProfileId = receipt.OriginalProfileId,
            PromotedProfileId = receipt.PromotedProfileId,
            PreviousDefaultProfileId = receipt.PreviousDefaultProfileId ?? string.Empty,
            BecameDefault = receipt.BecameDefault,
            Score = plan.Score,
            OutcomeVerdict = plan.OutcomeComparison?.Verdict ?? "unknown",
            MutationsJson = JsonUtils.Serialize(plan.Mutations, false),
            BaselineValidationJson = JsonUtils.Serialize(plan.BaselineValidation, false),
            CandidateValidationJson = JsonUtils.Serialize(plan.Validation, false),
            OutcomeComparisonJson = JsonUtils.Serialize(plan.OutcomeComparison, false),
            ObservedAtUnixMs = receipt.PromotedAt.ToUnixTimeMilliseconds(),
        });
    }

    public async Task RecordRolledBackAsync(
        RepairPromotionReceipt receipt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        cancellationToken.ThrowIfCancellationRequested();

        await SQLiteHelper.Instance.InsertAsync(new RepairPromotionHistoryItem
        {
            Id = Utils.GetGuid(false),
            EventKind = "rolled-back",
            SessionId = receipt.SessionId,
            CandidateId = receipt.CandidateId,
            OriginalProfileId = receipt.OriginalProfileId,
            PromotedProfileId = receipt.PromotedProfileId,
            PreviousDefaultProfileId = receipt.PreviousDefaultProfileId ?? string.Empty,
            BecameDefault = receipt.BecameDefault,
            ObservedAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        });
    }
}
