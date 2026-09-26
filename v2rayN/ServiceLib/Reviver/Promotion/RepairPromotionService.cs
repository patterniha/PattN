using ServiceLib.Reviver.Models;
using ServiceLib.Reviver.Services;

namespace ServiceLib.Reviver.Promotion;

/// <summary>
/// Transactional-by-construction promotion: a validated candidate becomes a new user-owned child profile.
/// The source profile is never overwritten, which makes rollback a deletion of the child plus default restoration.
/// </summary>
public sealed class RepairPromotionService(
    IRepairPromotionHistoryStore? historyStore = null,
    Func<string, Task<ProfileItem?>>? profileLoader = null,
    Func<Config, List<ProfileItem>, Task<int>>? removeServers = null,
    Func<Config, Task<int>>? saveConfig = null)
{
    private readonly Func<string, Task<ProfileItem?>> _profileLoader =
        profileLoader ?? (id => AppManager.Instance.GetProfileItem(id));
    private readonly Func<Config, List<ProfileItem>, Task<int>> _removeServers =
        removeServers ?? ((config, profiles) => ConfigHandler.RemoveServers(config, profiles));
    private readonly Func<Config, Task<int>> _saveConfig =
        saveConfig ?? (config => ConfigHandler.SaveConfig(config));
    public RepairPromotionPlan Prepare(RepairSession session, RepairCandidate candidate)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(candidate);
        if (candidate.SessionId != session.Id)
        {
            throw new InvalidOperationException("Candidate belongs to a different repair session.");
        }
        if (candidate.State != ERepairCandidateState.RuntimeValidated || candidate.Validation is null)
        {
            throw new InvalidOperationException("Only runtime-validated repair candidates can be promoted.");
        }

        var child = JsonUtils.DeepCopy(candidate.Profile)
            ?? throw new InvalidOperationException("Could not clone the validated repair profile.");

        // The repaired child is deliberately detached from subscription ownership. A future subscription refresh
        // must not silently remove or overwrite a locally validated repair.
        child.IndexId = string.Empty;
        child.Subid = string.Empty;
        child.IsSub = false;
        child.Remarks = BuildChildRemarks(session.Original.Remarks);

        return new RepairPromotionPlan
        {
            SessionId = session.Id,
            CandidateId = candidate.Id,
            OriginalProfileId = session.Original.IndexId,
            ChildProfile = child,
            Mutations = candidate.Mutations.ToArray(),
            BaselineValidation = session.BaselineValidation,
            Validation = candidate.Validation,
            OutcomeComparison = RepairOutcomeComparer.Compare(session.BaselineValidation, candidate.Validation),
            Score = candidate.Score,
        };
    }

    public async Task<RepairPromotionReceipt> PromoteAsync(
        Config config,
        RepairPromotionPlan plan,
        bool makeDefault,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(plan);
        cancellationToken.ThrowIfCancellationRequested();

        var previousDefault = config.IndexId;
        var child = plan.ChildProfile;
        if (child.IndexId.IsNotEmpty())
        {
            throw new InvalidOperationException("Promotion plan was already consumed or modified: child already has an ID.");
        }

        var result = await ConfigHandler.AddServer(config, child);
        if (result != 0 || child.IndexId.IsNullOrEmpty())
        {
            throw new InvalidOperationException("PattN failed to persist the repaired child profile.");
        }

        try
        {
            if (makeDefault)
            {
                if (await ConfigHandler.SetDefaultServerIndex(config, child.IndexId) != 0)
                {
                    throw new InvalidOperationException("The repaired child was saved but could not be selected as default.");
                }
            }
        }
        catch (Exception promotionError)
        {
            // Compensating transaction: if the optional default switch fails, remove the child we just created
            // and restore the previous default. Never mask a failed compensation as an ordinary promotion failure.
            var compensationErrors = new List<Exception>();
            try
            {
                if (await _removeServers(config, [child]) != 0)
                {
                    compensationErrors.Add(new InvalidOperationException("Failed to remove the repaired child during promotion compensation."));
                }
            }
            catch (Exception ex)
            {
                compensationErrors.Add(ex);
            }

            config.IndexId = previousDefault;
            try
            {
                if (await _saveConfig(config) != 0)
                {
                    compensationErrors.Add(new InvalidOperationException("Failed to persist the previous default during promotion compensation."));
                }
            }
            catch (Exception ex)
            {
                compensationErrors.Add(ex);
            }

            if (compensationErrors.Count > 0)
            {
                throw new AggregateException(
                    "Repair promotion failed and compensating rollback was incomplete; persistent state requires reconciliation.",
                    [promotionError, .. compensationErrors]);
            }
            throw;
        }

        var receipt = new RepairPromotionReceipt
        {
            SessionId = plan.SessionId,
            CandidateId = plan.CandidateId,
            OriginalProfileId = plan.OriginalProfileId,
            PromotedProfileId = child.IndexId,
            PreviousDefaultProfileId = previousDefault,
            BecameDefault = makeDefault,
        };

        if (historyStore is not null)
        {
            try
            {
                await historyStore.RecordPromotedAsync(plan, receipt, CancellationToken.None);
            }
            catch (Exception ex)
            {
                Logging.SaveLog($"Repair promotion history write failed: {ex}");
            }
        }

        return receipt;
    }

    public async Task RollbackAsync(Config config, RepairPromotionReceipt receipt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(receipt);
        cancellationToken.ThrowIfCancellationRequested();

        var promoted = await _profileLoader(receipt.PromotedProfileId);
        var wasDefault = string.Equals(config.IndexId, receipt.PromotedProfileId, StringComparison.Ordinal);
        var previousDefault = receipt.PreviousDefaultProfileId ?? string.Empty;

        // Validate the replacement before touching durable state. A stale receipt must never make
        // the config point at a profile that no longer exists, nor may it name the child being removed.
        if (wasDefault && previousDefault.IsNotEmpty())
        {
            if (string.Equals(previousDefault, receipt.PromotedProfileId, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "Repair rollback receipt names the promoted profile as its own previous default.");
            }

            if (await _profileLoader(previousDefault) is null)
            {
                throw new InvalidOperationException(
                    "The previous default profile no longer exists; rollback was left untouched for explicit reconciliation.");
            }
        }

        // If the promoted child is currently selected, persist the replacement default before
        // deleting the child. This avoids a crash window where durable config points at a
        // profile that has already been removed.
        if (wasDefault)
        {
            var currentDefault = config.IndexId;
            config.IndexId = previousDefault;
            if (await _saveConfig(config) != 0)
            {
                config.IndexId = currentDefault;
                throw new InvalidOperationException(
                    "The previous default profile could not be persisted; the promoted repair profile was left untouched.");
            }
        }

        if (promoted is not null)
        {
            Exception? removalError = null;
            try
            {
                if (await _removeServers(config, [promoted]) != 0)
                {
                    removalError = new InvalidOperationException(
                        "Failed to remove the promoted repair profile during rollback.");
                }
            }
            catch (Exception ex)
            {
                // RemoveServers now uses a database transaction and reports transactional failures
                // by throwing. Treat that exactly like an explicit failure result so default-state
                // compensation is not skipped after the replacement default has already been saved.
                removalError = ex;
            }

            if (removalError is not null)
            {
                var compensationErrors = new List<Exception>();
                if (wasDefault)
                {
                    try
                    {
                        // A transactional/commit error can leave deletion outcome uncertain. Restore
                        // the child as default only when it still exists; never persist a dangling ID.
                        if (await _profileLoader(receipt.PromotedProfileId) is not null)
                        {
                            config.IndexId = receipt.PromotedProfileId;
                            if (await _saveConfig(config) != 0)
                            {
                                compensationErrors.Add(new InvalidOperationException(
                                    "Failed to restore the promoted profile as default after rollback deletion failed."));
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        compensationErrors.Add(ex);
                    }
                }

                if (compensationErrors.Count > 0)
                {
                    throw new AggregateException(
                        "Repair rollback could not remove the promoted profile and default-state compensation was incomplete.",
                        [removalError, .. compensationErrors]);
                }

                throw new InvalidOperationException(
                    "Failed to remove the promoted repair profile during rollback.",
                    removalError);
            }
        }

        if (historyStore is not null)
        {
            try
            {
                await historyStore.RecordRolledBackAsync(receipt, CancellationToken.None);
            }
            catch (Exception ex)
            {
                Logging.SaveLog($"Repair rollback history write failed: {ex}");
            }
        }
    }

    private static string BuildChildRemarks(string? originalRemarks)
    {
        var baseName = originalRemarks.IsNullOrEmpty() ? "Revived" : originalRemarks.Trim();
        return $"{baseName}-revived";
    }
}
