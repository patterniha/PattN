using ServiceLib.Reviver.Models;
using ServiceLib.Reviver.Services;

namespace ServiceLib.Reviver.Promotion;

/// <summary>
/// Explicit, reversible application-level DNS repair. This service is intentionally separate from profile repair:
/// preparing a plan never mutates Config, and applying a plan only changes SimpleDNSItem.RemoteDNS/BootstrapDNS.
/// </summary>
public sealed class DnsSettingsRepairService
{
    private readonly IDnsSettingsRepairHistoryStore? _historyStore;
    private readonly Func<Config, Task<int>> _saveConfig;

    public DnsSettingsRepairService(Func<Config, Task<int>>? saveConfig = null)
        : this(null, saveConfig)
    {
    }

    public DnsSettingsRepairService(
        IDnsSettingsRepairHistoryStore? historyStore,
        Func<Config, Task<int>>? saveConfig = null)
    {
        _historyStore = historyStore;
        _saveConfig = saveConfig ?? ConfigHandler.SaveConfig;
    }

    public Task<DnsSettingsRepairReceipt?> GetLatestActiveReceiptAsync(
        CancellationToken cancellationToken = default)
        => _historyStore is null
            ? Task.FromResult<DnsSettingsRepairReceipt?>(null)
            : _historyStore.GetLatestActiveAsync(cancellationToken);

    public DnsSettingsRepairPlan Prepare(
        Config config,
        DnsResolverRecommendation resolver,
        string catalogVersion)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(resolver);
        if (resolver.CatalogId.IsNullOrEmpty())
        {
            throw new ArgumentException("Resolver catalog ID is required.", nameof(resolver));
        }

        var remote = resolver.DohUrl.NullIfEmpty()
            ?? resolver.IPv4.FirstOrDefault()
            ?? resolver.IPv6.FirstOrDefault();
        var bootstrap = resolver.IPv4.FirstOrDefault()
            ?? resolver.IPv6.FirstOrDefault();

        if (remote.IsNullOrEmpty())
        {
            throw new InvalidOperationException("Resolver recommendation has no usable DoH or IP endpoint.");
        }

        var before = Clone(config.SimpleDNSItem ?? new SimpleDNSItem());
        var after = Clone(before);
        var changes = new List<string>();

        if (!string.Equals(after.RemoteDNS, remote, StringComparison.Ordinal))
        {
            after.RemoteDNS = remote;
            changes.Add(nameof(SimpleDNSItem.RemoteDNS));
        }
        if (!bootstrap.IsNullOrEmpty()
            && !string.Equals(after.BootstrapDNS, bootstrap, StringComparison.Ordinal))
        {
            after.BootstrapDNS = bootstrap;
            changes.Add(nameof(SimpleDNSItem.BootstrapDNS));
        }

        if (changes.Count == 0)
        {
            throw new InvalidOperationException("The selected resolver is already represented by the current SimpleDNS settings.");
        }

        return new DnsSettingsRepairPlan
        {
            ResolverCatalogId = resolver.CatalogId,
            ResolverName = resolver.Name,
            ResolverPolicy = resolver.Policy,
            ResolverReferenceEligible = resolver.ReferenceEligible,
            CatalogVersion = catalogVersion ?? string.Empty,
            Before = before,
            After = after,
            BeforeFingerprint = Fingerprint(before),
            AfterFingerprint = Fingerprint(after),
            Changes = changes,
        };
    }

    public async Task<DnsSettingsRepairReceipt> ApplyAsync(
        Config config,
        DnsSettingsRepairPlan plan,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(plan);
        cancellationToken.ThrowIfCancellationRequested();

        var current = Clone(config.SimpleDNSItem ?? new SimpleDNSItem());
        if (!string.Equals(Fingerprint(current), plan.BeforeFingerprint, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("DNS settings changed after this repair plan was prepared; create a fresh plan.");
        }

        config.SimpleDNSItem = Clone(plan.After);
        Exception? persistenceError = null;
        try
        {
            if (await _saveConfig(config) != 0)
            {
                persistenceError = new InvalidOperationException("DNS settings persistence returned a failure result.");
            }
        }
        catch (Exception ex)
        {
            persistenceError = ex;
        }

        if (persistenceError is not null)
        {
            config.SimpleDNSItem = current;
            Exception? compensationError = null;
            try
            {
                if (await _saveConfig(config) != 0)
                {
                    compensationError = new InvalidOperationException(
                        "Compensating DNS settings persistence returned a failure result.");
                }
            }
            catch (Exception ex)
            {
                compensationError = ex;
            }

            if (compensationError is not null)
            {
                throw new InvalidOperationException(
                    "Failed to persist DNS settings, and compensating persistence of the previous settings also failed. " +
                    "The in-memory configuration was restored, but durable state is uncertain.",
                    new AggregateException(persistenceError, compensationError));
            }

            throw new InvalidOperationException(
                "Failed to persist DNS settings; the previous settings were restored and persisted.",
                persistenceError);
        }

        var receipt = new DnsSettingsRepairReceipt
        {
            PlanId = plan.Id,
            ResolverCatalogId = plan.ResolverCatalogId,
            CatalogVersion = plan.CatalogVersion,
            Before = Clone(plan.Before),
            Applied = Clone(plan.After),
            AppliedFingerprint = plan.AfterFingerprint,
        };

        if (_historyStore is not null)
        {
            try
            {
                await _historyStore.RecordAppliedAsync(receipt, CancellationToken.None);
            }
            catch (Exception historyError)
            {
                config.SimpleDNSItem = current;
                var compensationError = await TryPersistAsync(
                    config,
                    "Compensating DNS settings persistence after history failure returned a failure result.");

                Exception? historyNeutralizationError = null;
                if (compensationError is null)
                {
                    try
                    {
                        // Record a rollback marker even when the applied-history write threw before its
                        // commit point. If it actually committed before throwing, this newer marker
                        // neutralizes the orphaned active receipt; if it did not, the marker is harmless.
                        await _historyStore.RecordRolledBackAsync(receipt, CancellationToken.None);
                    }
                    catch (Exception ex)
                    {
                        historyNeutralizationError = ex;
                    }
                }

                if (compensationError is not null || historyNeutralizationError is not null)
                {
                    var errors = new List<Exception> { historyError };
                    if (compensationError is not null)
                    {
                        errors.Add(compensationError);
                    }
                    if (historyNeutralizationError is not null)
                    {
                        errors.Add(historyNeutralizationError);
                    }

                    throw new InvalidOperationException(
                        "DNS repair settings/history could not be committed atomically. The in-memory settings were restored, but durable config or repair-history state is uncertain.",
                        new AggregateException(errors));
                }

                throw new InvalidOperationException(
                    "Failed to record DNS repair history; the previous settings were restored and persisted, and the repair history was neutralized.",
                    historyError);
            }
        }

        return receipt;
    }

    public async Task RollbackAsync(
        Config config,
        DnsSettingsRepairReceipt receipt,
        bool force = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(receipt);
        cancellationToken.ThrowIfCancellationRequested();

        var current = Clone(config.SimpleDNSItem ?? new SimpleDNSItem());
        if (!force
            && !string.Equals(Fingerprint(current), receipt.AppliedFingerprint, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("DNS settings changed after the repair was applied; rollback would overwrite newer changes.");
        }

        config.SimpleDNSItem = Clone(receipt.Before);
        Exception? rollbackPersistenceError = null;
        try
        {
            if (await _saveConfig(config) != 0)
            {
                rollbackPersistenceError = new InvalidOperationException("DNS rollback persistence returned a failure result.");
            }
        }
        catch (Exception ex)
        {
            rollbackPersistenceError = ex;
        }

        if (rollbackPersistenceError is not null)
        {
            config.SimpleDNSItem = current;
            Exception? compensationError = null;
            try
            {
                if (await _saveConfig(config) != 0)
                {
                    compensationError = new InvalidOperationException(
                        "Compensating pre-rollback DNS persistence returned a failure result.");
                }
            }
            catch (Exception ex)
            {
                compensationError = ex;
            }

            if (compensationError is not null)
            {
                throw new InvalidOperationException(
                    "Failed to persist DNS rollback, and compensating persistence of the pre-rollback settings also failed. " +
                    "The in-memory configuration was restored, but durable state is uncertain.",
                    new AggregateException(rollbackPersistenceError, compensationError));
            }

            throw new InvalidOperationException(
                "Failed to persist DNS rollback; the pre-rollback settings were restored and persisted.",
                rollbackPersistenceError);
        }

        if (_historyStore is not null)
        {
            try
            {
                await _historyStore.RecordRolledBackAsync(receipt, CancellationToken.None);
            }
            catch (Exception historyError)
            {
                config.SimpleDNSItem = current;
                var compensationError = await TryPersistAsync(
                    config,
                    "Compensating pre-rollback DNS persistence after history failure returned a failure result.");

                Exception? historyReactivationError = null;
                if (compensationError is null)
                {
                    try
                    {
                        // If the rollback-history insert committed before throwing, append a newer
                        // applied marker so restart-time recovery still sees the restored applied state.
                        // If it did not commit, this is simply an idempotent re-assertion.
                        await _historyStore.RecordAppliedAsync(
                            receipt with { AppliedAt = DateTimeOffset.UtcNow },
                            CancellationToken.None);
                    }
                    catch (Exception ex)
                    {
                        historyReactivationError = ex;
                    }
                }

                if (compensationError is not null || historyReactivationError is not null)
                {
                    var errors = new List<Exception> { historyError };
                    if (compensationError is not null)
                    {
                        errors.Add(compensationError);
                    }
                    if (historyReactivationError is not null)
                    {
                        errors.Add(historyReactivationError);
                    }

                    throw new InvalidOperationException(
                        "DNS rollback settings/history could not be committed atomically. The in-memory applied settings were restored, but durable config or repair-history state is uncertain.",
                        new AggregateException(errors));
                }

                throw new InvalidOperationException(
                    "Failed to record DNS rollback history; the applied settings were restored and persisted, and the active repair history was reinstated.",
                    historyError);
            }
        }
    }

    private async Task<Exception?> TryPersistAsync(Config config, string failureMessage)
    {
        try
        {
            return await _saveConfig(config) == 0
                ? null
                : new InvalidOperationException(failureMessage);
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    private static SimpleDNSItem Clone(SimpleDNSItem source)
        => JsonUtils.DeepCopy(source)
            ?? throw new InvalidOperationException("Could not clone SimpleDNS settings.");

    private static string Fingerprint(SimpleDNSItem source)
        => JsonUtils.Serialize(source, false);
}
