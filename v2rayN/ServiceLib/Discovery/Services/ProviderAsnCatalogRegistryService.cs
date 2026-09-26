using ServiceLib.Discovery.Models;
using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Explicit registry/lifecycle orchestration for user-configurable provider/ASN catalog files.
/// Registry state never bypasses ProviderAsnCatalogUpdateService: file mutation remains stale-checked,
/// atomic, verified, compensating, and rollback-protected.
/// </summary>
public sealed class ProviderAsnCatalogRegistryService(
    IProviderAsnCatalogRegistryStore store,
    ProviderAsnCatalogUpdateService? updates = null)
{
    private readonly ProviderAsnCatalogUpdateService _updates = updates ?? new();

    public async Task<ProviderAsnCatalogRegistryView> RegisterAsync(
        string filePath,
        ProviderAsnCatalogRegistrationOptions? options = null,
        DateTimeOffset? now = null,
        CancellationToken cancellationToken = default)
    {
        options ??= new ProviderAsnCatalogRegistrationOptions();
        ValidateAuditPolicy(options.AuditPolicy);
        cancellationToken.ThrowIfCancellationRequested();

        var path = NormalizePath(filePath);
        var existing = await store.FindByPathAsync(path, cancellationToken);
        if (existing is null)
        {
            var all = await store.ListAsync(
                new ProviderAsnCatalogRegistryQuery
                {
                    IncludeDisabled = true,
                    IncludeUnregistered = true,
                    MaxItems = 1000,
                },
                cancellationToken);
            existing = all.FirstOrDefault(x => PathEquals(x.FilePath, path));
        }

        // Recovery must precede the authoritative file read. A process may have
        // died after replacing the catalog but before committing registry state.
        // Reading first would cache transient bytes and then continue with stale
        // content after recovery restored the prior file.
        if (existing is not null)
        {
            existing = await ProviderAsnCatalogApplyRecovery.RecoverWithLeaseAsync(
                existing,
                store,
                _updates,
                cancellationToken);
        }

        var catalog = await JsonProviderAsnEndpointCatalog.LoadAsync(path, cancellationToken);
        var observedAt = now ?? DateTimeOffset.UtcNow;
        var audit = catalog.Audit(observedAt, options.AuditPolicy);
        EnsureRegistrationAudit(audit, options.RequireFreshMetadata);

        if (existing is not null
            && !string.Equals(existing.CatalogId, catalog.Document.Id.Trim(), StringComparison.Ordinal))
        {
            if (existing.UnregisteredAtUnixMs is null)
            {
                throw new InvalidOperationException(
                    $"Registered catalog path already belongs to catalog ID '{existing.CatalogId}'. Unregister/re-register is required for an identity change.");
            }

            var preservedRevision = (await store.ListRevisionsAsync(
                new ProviderAsnCatalogRevisionQuery
                {
                    RegistryId = existing.Id,
                    IncludeRolledBack = true,
                    MaxItems = 1,
                },
                cancellationToken)).FirstOrDefault();
            if (preservedRevision is not null)
            {
                throw new InvalidOperationException(
                    "This retired catalog still has preserved rollback history. Explicitly discard its revision history before re-registering the same path with a different catalog ID.");
            }

            existing.ActiveRevisionId = string.Empty;
        }

        if (options.Enabled)
        {
            await EnsureNoEnabledCatalogIdCollisionAsync(
                catalog.Document.Id,
                existing?.Id,
                cancellationToken);
        }

        var item = existing ?? new ProviderAsnCatalogRegistryItem
        {
            Id = Utils.GetGuid(false),
            RegisteredAtUnixMs = observedAt.ToUnixTimeMilliseconds(),
        };

        item.FilePath = path;
        var requestedDisplayName = options.DisplayName?.Trim() ?? string.Empty;
        item.DisplayName = !requestedDisplayName.IsNullOrEmpty()
            ? requestedDisplayName
            : !item.DisplayName.IsNullOrEmpty()
                ? item.DisplayName
                : catalog.Document.Id.Trim();

        var wasRetired = item.UnregisteredAtUnixMs is not null;
        var reconcilesDifferentBytes = wasRetired
                                       && !item.Sha256.IsNullOrEmpty()
                                       && !string.Equals(item.Sha256, catalog.Sha256, StringComparison.Ordinal);
        if (reconcilesDifferentBytes)
        {
            // Preserved revisions remain historical evidence, but none describe the newly reconciled file state.
            item.ActiveRevisionId = string.Empty;
        }

        item.Enabled = options.Enabled;
        item.UnregisteredAtUnixMs = null;
        ApplyCatalogMetadata(item, catalog, audit, observedAt);
        await store.UpsertAsync(item, cancellationToken);
        return Project(item);
    }

    public async Task<IReadOnlyList<ProviderAsnCatalogRegistryView>> ListAsync(
        ProviderAsnCatalogRegistryQuery? query = null,
        CancellationToken cancellationToken = default)
    {
        var rows = await store.ListAsync(query, cancellationToken);
        var recovered = new List<ProviderAsnCatalogRegistryView>(rows.Count);
        foreach (var row in rows)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var current = await ProviderAsnCatalogApplyRecovery.RecoverWithLeaseAsync(
                row,
                store,
                _updates,
                cancellationToken);
            recovered.Add(Project(current));
        }
        return recovered;
    }

    public async Task<ProviderAsnCatalogRegistryView> GetAsync(
        string id,
        CancellationToken cancellationToken = default)
    {
        var item = await RequireRegistryAsync(id, cancellationToken);
        item = await ProviderAsnCatalogApplyRecovery.RecoverWithLeaseAsync(
            item,
            store,
            _updates,
            cancellationToken);
        return Project(item);
    }

    public async Task<ProviderAsnCatalogRegistryView> RefreshAsync(
        string id,
        ProviderAsnCatalogAuditPolicy? auditPolicy = null,
        DateTimeOffset? now = null,
        CancellationToken cancellationToken = default)
    {
        auditPolicy ??= new ProviderAsnCatalogAuditPolicy();
        ValidateAuditPolicy(auditPolicy);
        var item = await RequireRegisteredRegistryAsync(id, cancellationToken);
        var catalog = await JsonProviderAsnEndpointCatalog.LoadAsync(item.FilePath, cancellationToken);
        if (!string.Equals(catalog.Document.Id.Trim(), item.CatalogId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Registered catalog ID '{item.CatalogId}' no longer matches file catalog ID '{catalog.Document.Id}'.");
        }

        var observedAt = now ?? DateTimeOffset.UtcNow;
        var audit = catalog.Audit(observedAt, auditPolicy);
        if (!audit.Valid)
        {
            throw new InvalidOperationException(
                $"Provider/ASN catalog metadata audit failed: {string.Join(",", audit.Errors)}");
        }

        ApplyCatalogMetadata(item, catalog, audit, observedAt);
        await store.UpsertAsync(item, cancellationToken);
        return Project(item);
    }

    public async Task<ProviderAsnCatalogRegistryView> SetEnabledAsync(
        string id,
        bool enabled,
        CancellationToken cancellationToken = default)
    {
        var item = await RequireRegisteredRegistryAsync(id, cancellationToken);
        if (enabled && !item.Enabled)
        {
            await EnsureNoEnabledCatalogIdCollisionAsync(item.CatalogId, item.Id, cancellationToken);

            var catalog = await JsonProviderAsnEndpointCatalog.LoadAsync(item.FilePath, cancellationToken);
            if (!string.Equals(catalog.Document.Id.Trim(), item.CatalogId, StringComparison.Ordinal)
                || !string.Equals(catalog.Sha256, item.Sha256, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "Provider/ASN catalog changed on disk while disabled; refresh or re-register it before enabling.");
            }
        }

        item.Enabled = enabled;
        item.UpdatedAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        await store.UpsertAsync(item, cancellationToken);
        return Project(item);
    }

    public async Task<ProviderAsnCatalogRegistryView> RenameAsync(
        string id,
        string? displayName,
        CancellationToken cancellationToken = default)
    {
        var item = await RequireRegisteredRegistryAsync(id, cancellationToken);
        item.DisplayName = displayName?.Trim().NullIfEmpty() ?? item.CatalogId;
        item.UpdatedAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        await store.UpsertAsync(item, cancellationToken);
        return Project(item);
    }

    public async Task<ProviderAsnCatalogUnregisterReceipt> UnregisterAsync(
        string id,
        ProviderAsnCatalogUnregisterOptions? options = null,
        DateTimeOffset? now = null,
        CancellationToken cancellationToken = default)
    {
        options ??= new ProviderAsnCatalogUnregisterOptions();
        var item = await RequireRegisteredRegistryAsync(id, cancellationToken);
        var retiredAt = now ?? DateTimeOffset.UtcNow;
        var retired = Clone(item);

        retired.Enabled = false;
        retired.UnregisteredAtUnixMs = retiredAt.ToUnixTimeMilliseconds();
        retired.UpdatedAtUnixMs = retiredAt.ToUnixTimeMilliseconds();
        if (options.DiscardRevisionHistory)
        {
            retired.ActiveRevisionId = string.Empty;
        }

        var revisionCount = await store.RetireAsync(
            retired,
            options.DiscardRevisionHistory,
            cancellationToken);

        return new ProviderAsnCatalogUnregisterReceipt
        {
            RegistryId = retired.Id,
            FilePath = retired.FilePath,
            CatalogId = retired.CatalogId,
            UnregisteredAt = retiredAt,
            RevisionHistoryDiscarded = options.DiscardRevisionHistory,
            RevisionCount = revisionCount,
        };
    }

    public async Task<ProviderAsnCatalogUnregisterReceipt> DiscardRetiredRevisionHistoryAsync(
        string id,
        DateTimeOffset? now = null,
        CancellationToken cancellationToken = default)
    {
        var item = await RequireRegistryAsync(id, cancellationToken);
        if (item.UnregisteredAtUnixMs is null)
        {
            throw new InvalidOperationException(
                "Revision history can be discarded through this operation only after the catalog has been unregistered.");
        }

        var updatedAt = now ?? DateTimeOffset.UtcNow;
        var retired = Clone(item);
        retired.ActiveRevisionId = string.Empty;
        retired.UpdatedAtUnixMs = updatedAt.ToUnixTimeMilliseconds();

        var revisionCount = await store.RetireAsync(
            retired,
            discardRevisionHistory: true,
            cancellationToken);

        return new ProviderAsnCatalogUnregisterReceipt
        {
            RegistryId = retired.Id,
            FilePath = retired.FilePath,
            CatalogId = retired.CatalogId,
            UnregisteredAt = DateTimeOffset.FromUnixTimeMilliseconds(retired.UnregisteredAtUnixMs.Value),
            RevisionHistoryDiscarded = true,
            RevisionCount = revisionCount,
        };
    }

    public async Task<ProviderAsnCatalogUpdatePlan> PrepareUpdateAsync(
        string registryId,
        ReadOnlyMemory<byte> newBytes,
        ProviderAsnCatalogUpdateOptions? options = null,
        DateTimeOffset? now = null,
        CancellationToken cancellationToken = default)
    {
        var item = await RequireRegisteredRegistryAsync(registryId, cancellationToken);
        var plan = await _updates.PrepareAsync(
            item.FilePath,
            newBytes,
            options,
            now,
            cancellationToken);

        if (!string.Equals(plan.AfterCatalogId, item.CatalogId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Replacement catalog ID '{plan.AfterCatalogId}' does not match registry catalog ID '{item.CatalogId}'.");
        }
        return plan;
    }

    public async Task<ProviderAsnCatalogRevisionView> ApplyUpdateAsync(
        string registryId,
        ProviderAsnCatalogUpdatePlan plan,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var item = await RequireRegisteredRegistryAsync(registryId, cancellationToken);

        await using var operationLease = await ProviderAsnCatalogApplyRecovery.AcquireOperationLeaseAsync(
            item.FilePath,
            cancellationToken);
        item = await ProviderAsnCatalogApplyRecovery.RecoverIfNeededAsync(
            item,
            store,
            _updates,
            cancellationToken);
        ValidatePlanOwnership(item, plan);

        var revisionId = Utils.GetGuid(false);
        var journal = ProviderAsnCatalogApplyRecovery.Create(item, plan, revisionId);
        await ProviderAsnCatalogApplyRecovery.WriteAsync(journal, cancellationToken);

        ProviderAsnCatalogUpdateReceipt? receipt = null;
        ProviderAsnCatalogRevisionItem? revision = null;
        var compensationSucceeded = false;

        try
        {
            receipt = await _updates.ApplyAsync(plan, cancellationToken);
            ProviderAsnCatalogFaultInjection.Hit("after-file-apply");

            revision = CreateRevision(item.Id, plan, receipt, revisionId);
            var catalog = JsonProviderAsnEndpointCatalog.FromBytes(plan.AfterBytes);
            var updatedRegistry = Clone(item);
            ApplyCatalogMetadata(updatedRegistry, catalog, plan.AfterAudit, receipt.AppliedAt);
            updatedRegistry.ActiveRevisionId = revision.Id;

            // The file update is already committed. Complete persistence without allowing caller cancellation
            // to strand a successfully-applied file in an unknown registry state.
            await store.InsertRevisionAsync(revision, CancellationToken.None);
            ProviderAsnCatalogFaultInjection.Hit("after-revision-insert");

            await store.UpsertAsync(updatedRegistry, CancellationToken.None);
            ProviderAsnCatalogFaultInjection.Hit("after-registry-upsert");

            ProviderAsnCatalogApplyRecovery.Complete(plan.DestinationPath);
            return Project(revision, updatedRegistry.ActiveRevisionId);
        }
        catch (Exception persistenceError)
        {
            try
            {
                // Recovery uses the durable pre-update journal and handles all crash-like partial states,
                // including a file replacement with no revision row and a revision row without registry commit.
                _ = await ProviderAsnCatalogApplyRecovery.RecoverIfNeededAsync(
                    item,
                    store,
                    _updates,
                    CancellationToken.None);
                compensationSucceeded = true;
            }
            catch (Exception rollbackError)
            {
                Logging.SaveLog($"Provider catalog registry compensation failed: {rollbackError}");
            }

            if (compensationSucceeded)
            {
                throw new InvalidOperationException(
                    "Provider/ASN catalog update did not commit; the durable recovery journal restored the prior file/registry state.",
                    persistenceError);
            }

            throw new InvalidOperationException(
                "Provider/ASN catalog update failed and automatic crash-recovery could not reconcile the file/registry state; the recovery journal was retained.",
                persistenceError);
        }
    }

    public async Task<ProviderAsnCatalogRevisionView> RollbackRevisionAsync(
        string revisionId,
        bool force = false,
        CancellationToken cancellationToken = default)
    {
        var revision = await RequireRevisionAsync(revisionId, cancellationToken);
        if (revision.RolledBackAtUnixMs is not null)
        {
            throw new InvalidOperationException("Provider/ASN catalog revision has already been rolled back.");
        }

        var registry = await RequireRegisteredRegistryAsync(revision.RegistryId, cancellationToken);
        await using var operationLease = await ProviderAsnCatalogApplyRecovery.AcquireOperationLeaseAsync(
            registry.FilePath,
            cancellationToken);
        registry = await RequireRegistryAsync(revision.RegistryId, cancellationToken);
        registry = await ProviderAsnCatalogApplyRecovery.RecoverIfNeededAsync(
            registry,
            store,
            _updates,
            cancellationToken);
        revision = await RequireRevisionAsync(revisionId, cancellationToken);
        if (revision.RolledBackAtUnixMs is not null)
        {
            throw new InvalidOperationException("Provider/ASN catalog revision has already been rolled back.");
        }
        if (!force
            && !string.Equals(registry.ActiveRevisionId, revision.Id, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Provider/ASN catalog revision is not the active registry revision; rollback would cross a newer update.");
        }

        var receipt = ToReceipt(revision);
        var rollbackAt = DateTimeOffset.UtcNow;
        var beforeRevision = JsonUtils.DeepCopy(revision)
            ?? throw new InvalidOperationException("Could not snapshot provider catalog revision before rollback.");
        var refreshed = Clone(registry);
        var rolledBackRevision = JsonUtils.DeepCopy(revision)
            ?? throw new InvalidOperationException("Could not snapshot provider catalog revision after rollback.");

        if (revision.DestinationExisted)
        {
            var catalog = JsonProviderAsnEndpointCatalog.FromBytes(revision.BeforeBytes);
            var audit = catalog.Audit(rollbackAt);
            if (!audit.Valid)
            {
                throw new InvalidOperationException(
                    $"Rollback target provider catalog failed metadata audit: {string.Join(",", audit.Errors)}");
            }

            var revisions = await store.ListRevisionsAsync(
                new ProviderAsnCatalogRevisionQuery
                {
                    RegistryId = registry.Id,
                    IncludeRolledBack = false,
                    MaxItems = 1000,
                },
                cancellationToken);
            var priorActiveRevisionId = revisions
                .Where(x => x.Id != revision.Id
                            && x.RolledBackAtUnixMs is null
                            && string.Equals(x.AfterSha256, revision.BeforeSha256, StringComparison.Ordinal))
                .OrderByDescending(x => x.AppliedAtUnixMs)
                .Select(x => x.Id)
                .FirstOrDefault() ?? string.Empty;

            ApplyCatalogMetadata(refreshed, catalog, audit, rollbackAt);
            refreshed.ActiveRevisionId = priorActiveRevisionId;
        }
        else
        {
            // The update created a new destination; rollback removes it and
            // leaves the registry disabled until an explicit re-registration.
            refreshed.Enabled = false;
            refreshed.CatalogVersion = string.Empty;
            refreshed.CatalogSource = string.Empty;
            refreshed.Sha256 = string.Empty;
            refreshed.CatalogUpdatedAtUnixMs = null;
            refreshed.LastAuditJson = string.Empty;
            refreshed.LastAuditedAtUnixMs = 0;
            refreshed.ActiveRevisionId = string.Empty;
            refreshed.UpdatedAtUnixMs = rollbackAt.ToUnixTimeMilliseconds();
        }

        rolledBackRevision.RolledBackAtUnixMs = rollbackAt.ToUnixTimeMilliseconds();
        rolledBackRevision.RollbackForced = force;

        var rollbackJournal = await ProviderAsnCatalogApplyRecovery.CreateRollbackAsync(
            registry,
            beforeRevision,
            refreshed,
            rolledBackRevision,
            cancellationToken);
        await ProviderAsnCatalogApplyRecovery.WriteRollbackAsync(
            rollbackJournal,
            cancellationToken);

        var fileRollbackCompleted = false;
        try
        {
            await _updates.RollbackAsync(receipt, force, cancellationToken);
            fileRollbackCompleted = true;
            ProviderAsnCatalogFaultInjection.Hit("after-rollback-file");

            // The file rollback is now durable. Finish the SQLite side without
            // allowing caller cancellation to strand the cross-store operation.
            await store.UpsertAsync(refreshed, CancellationToken.None);
            ProviderAsnCatalogFaultInjection.Hit("after-rollback-registry");

            await store.UpdateRevisionAsync(rolledBackRevision, CancellationToken.None);
            ProviderAsnCatalogFaultInjection.Hit("after-rollback-revision");

            ProviderAsnCatalogApplyRecovery.CompleteRollback(registry.FilePath);
            return Project(rolledBackRevision, refreshed.ActiveRevisionId);
        }
        catch (Exception rollbackError)
        {
            try
            {
                _ = await ProviderAsnCatalogApplyRecovery.RecoverIfNeededAsync(
                    registry,
                    store,
                    _updates,
                    CancellationToken.None);
            }
            catch (Exception recoveryError)
            {
                Logging.SaveLog($"Provider catalog rollback crash recovery failed: {recoveryError}");
                var message = fileRollbackCompleted
                    ? "Provider/ASN catalog rollback persistence failed after the catalog file was restored, and automatic reconciliation could not complete; the rollback journal was retained."
                    : "Provider/ASN catalog rollback failed before the catalog file was durably restored, and automatic reconciliation could not complete; the rollback journal was retained.";
                throw new InvalidOperationException(message, rollbackError);
            }

            var reconciledMessage = fileRollbackCompleted
                ? "Provider/ASN catalog rollback persistence failed after the catalog file was restored; the durable recovery journal completed reconciliation. Reload registry state before continuing."
                : "Provider/ASN catalog rollback did not complete normally; the durable recovery journal completed reconciliation. Reload registry state before continuing.";
            throw new InvalidOperationException(reconciledMessage, rollbackError);
        }
    }

    public async Task<IReadOnlyList<ProviderAsnCatalogRevisionView>> ListRevisionsAsync(
        ProviderAsnCatalogRevisionQuery? query = null,
        CancellationToken cancellationToken = default)
    {
        var rows = await store.ListRevisionsAsync(query, cancellationToken);
        var activeByRegistry = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var registryId in rows.Select(x => x.RegistryId).Distinct(StringComparer.Ordinal))
        {
            var registry = await store.GetAsync(registryId, cancellationToken);
            activeByRegistry[registryId] = registry?.UnregisteredAtUnixMs is null
                ? registry?.ActiveRevisionId ?? string.Empty
                : string.Empty;
        }

        return rows
            .Select(x => Project(
                x,
                activeByRegistry.TryGetValue(x.RegistryId, out var active) ? active : string.Empty))
            .ToArray();
    }

    public async Task<IReadOnlyList<JsonProviderAsnEndpointCatalog>> LoadEnabledCatalogsAsync(
        CancellationToken cancellationToken = default)
    {
        var rows = await store.ListAsync(
            new ProviderAsnCatalogRegistryQuery
            {
                IncludeDisabled = false,
                MaxItems = 1000,
            },
            cancellationToken);

        var catalogs = new List<JsonProviderAsnEndpointCatalog>(rows.Count);
        var seenCatalogIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var storedRow in rows)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var row = await ProviderAsnCatalogApplyRecovery.RecoverWithLeaseAsync(
                storedRow,
                store,
                _updates,
                cancellationToken);
            if (!seenCatalogIds.Add(row.CatalogId))
            {
                throw new InvalidOperationException(
                    $"Multiple enabled provider/ASN catalog resources share catalog ID '{row.CatalogId}'.");
            }

            var catalog = await JsonProviderAsnEndpointCatalog.LoadAsync(row.FilePath, cancellationToken);
            if (!string.Equals(catalog.Document.Id.Trim(), row.CatalogId, StringComparison.Ordinal)
                || !string.Equals(catalog.Sha256, row.Sha256, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Registered provider/ASN catalog '{row.Id}' changed on disk; refresh the registry before use.");
            }
            catalogs.Add(catalog);
        }
        return catalogs;
    }

    private async Task EnsureNoEnabledCatalogIdCollisionAsync(
        string catalogId,
        string? exceptRegistryId,
        CancellationToken cancellationToken)
    {
        var rows = await store.ListAsync(
            new ProviderAsnCatalogRegistryQuery
            {
                IncludeDisabled = false,
                MaxItems = 1000,
            },
            cancellationToken);

        if (rows.Any(x => x.Id != exceptRegistryId
                          && string.Equals(x.CatalogId, catalogId, StringComparison.Ordinal)))
        {
            throw new InvalidOperationException(
                $"An enabled provider/ASN catalog with ID '{catalogId}' is already registered.");
        }
    }

    private async Task<ProviderAsnCatalogRegistryItem> RequireRegistryAsync(
        string id,
        CancellationToken cancellationToken)
        => await store.GetAsync(id, cancellationToken)
           ?? throw new InvalidOperationException($"Provider/ASN catalog registry item '{id}' was not found.");

    private async Task<ProviderAsnCatalogRegistryItem> RequireRegisteredRegistryAsync(
        string id,
        CancellationToken cancellationToken)
    {
        var item = await RequireRegistryAsync(id, cancellationToken);
        item = await ProviderAsnCatalogApplyRecovery.RecoverWithLeaseAsync(
            item,
            store,
            _updates,
            cancellationToken);
        if (item.UnregisteredAtUnixMs is not null)
        {
            throw new InvalidOperationException(
                $"Provider/ASN catalog registry item '{id}' is retired. Re-register its file before modifying or rolling it back.");
        }
        return item;
    }

    private async Task<ProviderAsnCatalogRevisionItem> RequireRevisionAsync(
        string id,
        CancellationToken cancellationToken)
        => await store.GetRevisionAsync(id, cancellationToken)
           ?? throw new InvalidOperationException($"Provider/ASN catalog revision '{id}' was not found.");

    private static void ValidatePlanOwnership(
        ProviderAsnCatalogRegistryItem item,
        ProviderAsnCatalogUpdatePlan plan)
    {
        if (!string.Equals(
                NormalizePath(plan.DestinationPath),
                NormalizePath(item.FilePath),
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Provider catalog update plan belongs to a different registry path.");
        }
        if (!string.Equals(plan.AfterCatalogId, item.CatalogId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Provider catalog update plan belongs to a different catalog ID.");
        }
    }

    private static ProviderAsnCatalogRevisionItem CreateRevision(
        string registryId,
        ProviderAsnCatalogUpdatePlan plan,
        ProviderAsnCatalogUpdateReceipt receipt,
        string? revisionId = null)
        => new()
        {
            Id = revisionId.NullIfEmpty() ?? Utils.GetGuid(false),
            RegistryId = registryId,
            PlanId = receipt.PlanId,
            DestinationPath = receipt.DestinationPath,
            DestinationExisted = receipt.DestinationExisted,
            BeforeSha256 = receipt.BeforeSha256,
            AfterSha256 = receipt.AfterSha256,
            BeforeCatalogId = plan.BeforeCatalogId,
            BeforeCatalogVersion = plan.BeforeCatalogVersion,
            AfterCatalogId = plan.AfterCatalogId,
            AfterCatalogVersion = plan.AfterCatalogVersion,
            BeforeBytes = receipt.BeforeBytes.ToArray(),
            AppliedAtUnixMs = receipt.AppliedAt.ToUnixTimeMilliseconds(),
            AuditJson = JsonUtils.Serialize(plan.AfterAudit, false),
            DiffJson = JsonUtils.Serialize(plan.Diff, false),
        };

    private static ProviderAsnCatalogUpdateReceipt ToReceipt(
        ProviderAsnCatalogRevisionItem revision)
        => new()
        {
            PlanId = revision.PlanId,
            DestinationPath = revision.DestinationPath,
            DestinationExisted = revision.DestinationExisted,
            BeforeSha256 = revision.BeforeSha256,
            AfterSha256 = revision.AfterSha256,
            BeforeBytes = revision.BeforeBytes.ToArray(),
            AppliedAt = DateTimeOffset.FromUnixTimeMilliseconds(revision.AppliedAtUnixMs),
        };

    private static void ApplyCatalogMetadata(
        ProviderAsnCatalogRegistryItem item,
        JsonProviderAsnEndpointCatalog catalog,
        ProviderAsnCatalogAudit audit,
        DateTimeOffset observedAt)
    {
        item.CatalogId = catalog.Document.Id.Trim();
        item.CatalogVersion = catalog.Document.Version.Trim();
        item.CatalogSource = catalog.Document.Source.Trim();
        item.Sha256 = catalog.Sha256;
        item.CatalogUpdatedAtUnixMs = catalog.Document.UpdatedAt?.ToUnixTimeMilliseconds();
        item.LastAuditedAtUnixMs = audit.AuditedAt.ToUnixTimeMilliseconds();
        item.LastAuditJson = JsonUtils.Serialize(audit, false);
        item.UpdatedAtUnixMs = observedAt.ToUnixTimeMilliseconds();
    }

    private static ProviderAsnCatalogRegistryItem Clone(ProviderAsnCatalogRegistryItem item)
        => JsonUtils.DeepCopy(item)
           ?? throw new InvalidOperationException("Could not clone provider/ASN catalog registry state.");

    private static ProviderAsnCatalogRegistryView Project(ProviderAsnCatalogRegistryItem item)
        => new()
        {
            Id = item.Id,
            FilePath = item.FilePath,
            DisplayName = item.DisplayName,
            Enabled = item.Enabled,
            CatalogId = item.CatalogId,
            CatalogVersion = item.CatalogVersion,
            CatalogSource = item.CatalogSource,
            Sha256 = item.Sha256,
            CatalogUpdatedAt = item.CatalogUpdatedAtUnixMs is null
                ? null
                : DateTimeOffset.FromUnixTimeMilliseconds(item.CatalogUpdatedAtUnixMs.Value),
            RegisteredAt = DateTimeOffset.FromUnixTimeMilliseconds(item.RegisteredAtUnixMs),
            UpdatedAt = DateTimeOffset.FromUnixTimeMilliseconds(item.UpdatedAtUnixMs),
            UnregisteredAt = item.UnregisteredAtUnixMs is null
                ? null
                : DateTimeOffset.FromUnixTimeMilliseconds(item.UnregisteredAtUnixMs.Value),
            LastAuditedAt = item.LastAuditedAtUnixMs <= 0
                ? null
                : DateTimeOffset.FromUnixTimeMilliseconds(item.LastAuditedAtUnixMs),
            LastAudit = DeserializeOrDefault<ProviderAsnCatalogAudit>(item.LastAuditJson, nameof(item.LastAuditJson)),
            ActiveRevisionId = item.ActiveRevisionId,
        };

    private static ProviderAsnCatalogRevisionView Project(
        ProviderAsnCatalogRevisionItem item,
        string activeRevisionId)
        => new()
        {
            Id = item.Id,
            RegistryId = item.RegistryId,
            PlanId = item.PlanId,
            DestinationPath = item.DestinationPath,
            BeforeSha256 = item.BeforeSha256,
            AfterSha256 = item.AfterSha256,
            BeforeCatalogVersion = item.BeforeCatalogVersion,
            AfterCatalogVersion = item.AfterCatalogVersion,
            AppliedAt = DateTimeOffset.FromUnixTimeMilliseconds(item.AppliedAtUnixMs),
            RolledBackAt = item.RolledBackAtUnixMs is null
                ? null
                : DateTimeOffset.FromUnixTimeMilliseconds(item.RolledBackAtUnixMs.Value),
            RollbackForced = item.RollbackForced,
            Active = item.RolledBackAtUnixMs is null
                     && string.Equals(item.Id, activeRevisionId, StringComparison.Ordinal),
            AppliedAudit = DeserializeOrDefault<ProviderAsnCatalogAudit>(item.AuditJson, nameof(item.AuditJson)),
            Diff = DeserializeOrDefault<ProviderAsnCatalogDiff>(item.DiffJson, nameof(item.DiffJson)),
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
                $"Stored provider catalog registry field '{fieldName}' contains invalid JSON.",
                ex);
        }
    }

    private static void EnsureRegistrationAudit(
        ProviderAsnCatalogAudit audit,
        bool requireFresh)
    {
        if (!audit.Valid)
        {
            throw new InvalidOperationException(
                $"Provider/ASN catalog metadata audit failed: {string.Join(",", audit.Errors)}");
        }
        if (requireFresh && (!audit.FreshnessKnown || audit.Stale))
        {
            throw new InvalidOperationException(
                "Provider/ASN catalog registration requires fresh updatedAt metadata.");
        }
    }

    private static void ValidateAuditPolicy(ProviderAsnCatalogAuditPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (policy.MaximumAge <= TimeSpan.Zero
            || policy.MaximumAge > TimeSpan.FromDays(3650))
        {
            throw new ArgumentOutOfRangeException(nameof(policy.MaximumAge));
        }
        if (policy.MaximumFutureClockSkew < TimeSpan.Zero
            || policy.MaximumFutureClockSkew > TimeSpan.FromDays(1))
        {
            throw new ArgumentOutOfRangeException(nameof(policy.MaximumFutureClockSkew));
        }
        if (policy.MaximumDuplicateDetails is < 0 or > 10000)
        {
            throw new ArgumentOutOfRangeException(nameof(policy.MaximumDuplicateDetails));
        }
    }

    private static string NormalizePath(string path)
    {
        if (path.IsNullOrEmpty())
        {
            throw new ArgumentException("Provider/ASN catalog file path is required.", nameof(path));
        }
        return Path.GetFullPath(path);
    }

    private static bool PathEquals(string left, string right)
        => string.Equals(
            Path.GetFullPath(left),
            Path.GetFullPath(right),
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
}
