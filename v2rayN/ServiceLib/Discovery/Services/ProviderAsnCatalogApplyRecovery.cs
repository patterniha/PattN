using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ServiceLib.Discovery.Models;
using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

internal sealed record ProviderAsnCatalogPendingApplyJournal
{
    public int Version { get; init; } = 1;
    public required string RegistryId { get; init; }
    public required string RevisionId { get; init; }
    public required string PlanId { get; init; }
    public required string DestinationPath { get; init; }
    public bool DestinationExisted { get; init; }
    public required string BeforeSha256 { get; init; }
    public required string AfterSha256 { get; init; }
    public byte[] BeforeBytes { get; init; } = [];
    public required ProviderAsnCatalogRegistryItem BeforeRegistry { get; init; }
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
}

internal sealed record ProviderAsnCatalogPendingRollbackJournal
{
    public int Version { get; init; } = 1;
    public required string RegistryId { get; init; }
    public required string RevisionId { get; init; }
    public required string DestinationPath { get; init; }
    public required string BeforeFileSha256 { get; init; }
    public required string AfterFileSha256 { get; init; }
    public required ProviderAsnCatalogRegistryItem BeforeRegistry { get; init; }
    public required ProviderAsnCatalogRegistryItem AfterRegistry { get; init; }
    public required ProviderAsnCatalogRevisionItem BeforeRevision { get; init; }
    public required ProviderAsnCatalogRevisionItem AfterRevision { get; init; }
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
}

internal static class ProviderAsnCatalogApplyRecovery
{
    private const string MissingFingerprint = "<missing>";

    public static ProviderAsnCatalogPendingApplyJournal Create(
        ProviderAsnCatalogRegistryItem beforeRegistry,
        ProviderAsnCatalogUpdatePlan plan,
        string revisionId)
    {
        ArgumentNullException.ThrowIfNull(beforeRegistry);
        ArgumentNullException.ThrowIfNull(plan);
        if (revisionId.IsNullOrEmpty())
        {
            throw new ArgumentException("Pending catalog apply requires a revision ID.", nameof(revisionId));
        }

        return new ProviderAsnCatalogPendingApplyJournal
        {
            RegistryId = beforeRegistry.Id,
            RevisionId = revisionId,
            PlanId = plan.Id,
            DestinationPath = Path.GetFullPath(plan.DestinationPath),
            DestinationExisted = plan.DestinationExisted,
            BeforeSha256 = plan.BeforeSha256,
            AfterSha256 = plan.AfterSha256,
            BeforeBytes = plan.BeforeBytes.ToArray(),
            BeforeRegistry = JsonUtils.DeepCopy(beforeRegistry)
                ?? throw new InvalidOperationException("Could not snapshot provider catalog registry state for crash recovery."),
        };
    }

    public static async Task WriteAsync(
        ProviderAsnCatalogPendingApplyJournal journal,
        CancellationToken cancellationToken)
    {
        Validate(journal);
        var raw = JsonSerializer.SerializeToUtf8Bytes(
            journal,
            new JsonSerializerOptions { WriteIndented = true });
        await DurableAtomicFile.WriteAsync(JournalPath(journal.DestinationPath), raw, cancellationToken: cancellationToken);
    }

    public static async Task<ProviderAsnCatalogPendingRollbackJournal> CreateRollbackAsync(
        ProviderAsnCatalogRegistryItem beforeRegistry,
        ProviderAsnCatalogRevisionItem beforeRevision,
        ProviderAsnCatalogRegistryItem afterRegistry,
        ProviderAsnCatalogRevisionItem afterRevision,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(beforeRegistry);
        ArgumentNullException.ThrowIfNull(beforeRevision);
        ArgumentNullException.ThrowIfNull(afterRegistry);
        ArgumentNullException.ThrowIfNull(afterRevision);

        var destinationPath = Path.GetFullPath(beforeRevision.DestinationPath);
        var journal = new ProviderAsnCatalogPendingRollbackJournal
        {
            RegistryId = beforeRegistry.Id,
            RevisionId = beforeRevision.Id,
            DestinationPath = destinationPath,
            BeforeFileSha256 = await CurrentFingerprintAsync(destinationPath, cancellationToken),
            AfterFileSha256 = beforeRevision.DestinationExisted
                ? beforeRevision.BeforeSha256
                : MissingFingerprint,
            BeforeRegistry = JsonUtils.DeepCopy(beforeRegistry)
                ?? throw new InvalidOperationException("Could not snapshot provider catalog registry state before rollback."),
            AfterRegistry = JsonUtils.DeepCopy(afterRegistry)
                ?? throw new InvalidOperationException("Could not snapshot provider catalog registry state after rollback."),
            BeforeRevision = JsonUtils.DeepCopy(beforeRevision)
                ?? throw new InvalidOperationException("Could not snapshot provider catalog revision before rollback."),
            AfterRevision = JsonUtils.DeepCopy(afterRevision)
                ?? throw new InvalidOperationException("Could not snapshot provider catalog revision after rollback."),
        };
        ValidateRollback(journal);
        return journal;
    }

    public static async Task WriteRollbackAsync(
        ProviderAsnCatalogPendingRollbackJournal journal,
        CancellationToken cancellationToken)
    {
        ValidateRollback(journal);
        var raw = JsonSerializer.SerializeToUtf8Bytes(
            journal,
            new JsonSerializerOptions { WriteIndented = true });
        await DurableAtomicFile.WriteAsync(
            RollbackJournalPath(journal.DestinationPath),
            raw,
            cancellationToken: cancellationToken);
    }

    public static async Task<FileStream> AcquireOperationLeaseAsync(
        string destinationPath,
        CancellationToken cancellationToken)
    {
        var path = OperationLeasePath(destinationPath);
        var deadline = DateTime.UtcNow.AddSeconds(10);
        IOException? lastError = null;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return new FileStream(
                    path,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    1,
                    FileOptions.Asynchronous | FileOptions.WriteThrough);
            }
            catch (DirectoryNotFoundException)
            {
                // A missing parent is a permanent path/configuration error, not lease contention.
                // Retrying it for the full lease timeout only hides the real failure.
                throw;
            }
            catch (PathTooLongException)
            {
                throw;
            }
            catch (IOException ex) when (DateTime.UtcNow < deadline)
            {
                lastError = ex;
                await Task.Delay(50, cancellationToken);
            }
            catch (IOException)
            {
                throw;
            }

            if (DateTime.UtcNow >= deadline)
            {
                throw new IOException(
                    $"Timed out waiting for provider catalog registry-operation lease: {path}",
                    lastError);
            }
        }
    }

    public static async Task<ProviderAsnCatalogRegistryItem> RecoverWithLeaseAsync(
        ProviderAsnCatalogRegistryItem item,
        IProviderAsnCatalogRegistryStore store,
        ProviderAsnCatalogUpdateService updates,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(item);

        // A normal registry read must remain read-only. The operation lease is an adjacent
        // filesystem artifact, so acquiring it unconditionally turns Get/List into writes and
        // fails for valid logical/test paths whose parent directory does not exist locally.
        //
        // Writers create the lease before any recovery journal. Once a catalog has ever been
        // mutated, the durable lease file remains present and readers continue to serialize with
        // later mutations. A fresh path with neither a lease nor a journal can be returned
        // immediately; a concurrent writer that acquires just after this check linearizes after
        // this read.
        var leasePath = OperationLeasePath(item.FilePath);
        var journalPath = JournalPath(item.FilePath);
        var rollbackJournalPath = RollbackJournalPath(item.FilePath);
        if (!File.Exists(leasePath)
            && !File.Exists(journalPath)
            && !File.Exists(rollbackJournalPath))
        {
            return item;
        }

        await using var lease = await AcquireOperationLeaseAsync(item.FilePath, cancellationToken);
        return await RecoverIfNeededAsync(item, store, updates, cancellationToken);
    }

    public static async Task<ProviderAsnCatalogRegistryItem> RecoverIfNeededAsync(
        ProviderAsnCatalogRegistryItem item,
        IProviderAsnCatalogRegistryStore store,
        ProviderAsnCatalogUpdateService updates,
        CancellationToken cancellationToken)
    {
        var journalPath = JournalPath(item.FilePath);
        var rollbackJournalPath = RollbackJournalPath(item.FilePath);
        if (File.Exists(journalPath) && File.Exists(rollbackJournalPath))
        {
            throw new InvalidOperationException(
                "Provider catalog has both apply and rollback recovery journals; manual reconciliation is required.");
        }
        if (File.Exists(rollbackJournalPath))
        {
            return await RecoverRollbackIfNeededAsync(
                item,
                store,
                rollbackJournalPath,
                cancellationToken);
        }
        if (!File.Exists(journalPath))
        {
            return item;
        }

        ProviderAsnCatalogPendingApplyJournal journal;
        try
        {
            var raw = await File.ReadAllBytesAsync(journalPath, cancellationToken);
            journal = JsonSerializer.Deserialize<ProviderAsnCatalogPendingApplyJournal>(raw)
                ?? throw new InvalidOperationException("Pending provider catalog apply journal decoded to null.");
            Validate(journal);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException)
        {
            throw new InvalidOperationException(
                $"Pending provider catalog apply journal is invalid and requires manual reconciliation: {journalPath}",
                ex);
        }

        if (!string.Equals(journal.RegistryId, item.Id, StringComparison.Ordinal)
            || !PathEquals(journal.DestinationPath, item.FilePath))
        {
            throw new InvalidOperationException(
                "Pending provider catalog apply journal belongs to a different registry/path; refusing recovery.");
        }

        var currentRegistry = await store.GetAsync(journal.RegistryId, cancellationToken)
            ?? throw new InvalidOperationException(
                "Pending provider catalog apply journal references a missing registry item.");
        var currentSha = await CurrentFingerprintAsync(journal.DestinationPath, cancellationToken);
        var revision = await store.GetRevisionAsync(journal.RevisionId, cancellationToken);

        if (string.Equals(currentSha, journal.AfterSha256, StringComparison.Ordinal)
            && string.Equals(currentRegistry.Sha256, journal.AfterSha256, StringComparison.Ordinal)
            && string.Equals(currentRegistry.ActiveRevisionId, journal.RevisionId, StringComparison.Ordinal)
            && revision is not null
            && revision.RolledBackAtUnixMs is null
            && RevisionMatchesJournal(revision, journal))
        {
            DurableAtomicFile.Delete(journalPath);
            return currentRegistry;
        }

        if (!string.Equals(currentSha, journal.BeforeSha256, StringComparison.Ordinal)
            && !string.Equals(currentSha, journal.AfterSha256, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Provider catalog changed to an unknown state while a crash-recovery journal is pending; refusing to overwrite it.");
        }

        if (string.Equals(currentSha, journal.AfterSha256, StringComparison.Ordinal))
        {
            await updates.RollbackAsync(
                new ProviderAsnCatalogUpdateReceipt
                {
                    PlanId = journal.PlanId,
                    DestinationPath = journal.DestinationPath,
                    DestinationExisted = journal.DestinationExisted,
                    BeforeSha256 = journal.BeforeSha256,
                    AfterSha256 = journal.AfterSha256,
                    BeforeBytes = journal.BeforeBytes.ToArray(),
                    AppliedAt = journal.CreatedAt,
                },
                force: false,
                CancellationToken.None);
        }

        if (revision is not null && revision.RolledBackAtUnixMs is null)
        {
            revision.RolledBackAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            await store.UpdateRevisionAsync(revision, CancellationToken.None);
        }

        var restored = JsonUtils.DeepCopy(journal.BeforeRegistry)
            ?? throw new InvalidOperationException("Could not restore provider catalog registry crash-recovery snapshot.");
        await store.UpsertAsync(restored, CancellationToken.None);
        DurableAtomicFile.Delete(journalPath);
        return restored;
    }

    private static async Task<ProviderAsnCatalogRegistryItem> RecoverRollbackIfNeededAsync(
        ProviderAsnCatalogRegistryItem item,
        IProviderAsnCatalogRegistryStore store,
        string journalPath,
        CancellationToken cancellationToken)
    {
        ProviderAsnCatalogPendingRollbackJournal journal;
        try
        {
            var raw = await File.ReadAllBytesAsync(journalPath, cancellationToken);
            journal = JsonSerializer.Deserialize<ProviderAsnCatalogPendingRollbackJournal>(raw)
                ?? throw new InvalidOperationException("Pending provider catalog rollback journal decoded to null.");
            ValidateRollback(journal);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException)
        {
            throw new InvalidOperationException(
                $"Pending provider catalog rollback journal is invalid and requires manual reconciliation: {journalPath}",
                ex);
        }

        if (!string.Equals(journal.RegistryId, item.Id, StringComparison.Ordinal)
            || !PathEquals(journal.DestinationPath, item.FilePath))
        {
            throw new InvalidOperationException(
                "Pending provider catalog rollback journal belongs to a different registry/path; refusing recovery.");
        }

        var currentRegistry = await store.GetAsync(journal.RegistryId, cancellationToken)
            ?? throw new InvalidOperationException(
                "Pending provider catalog rollback journal references a missing registry item.");
        var currentRevision = await store.GetRevisionAsync(journal.RevisionId, cancellationToken)
            ?? throw new InvalidOperationException(
                "Pending provider catalog rollback journal references a missing revision.");
        var currentSha = await CurrentFingerprintAsync(journal.DestinationPath, cancellationToken);

        if (string.Equals(currentSha, journal.BeforeFileSha256, StringComparison.Ordinal))
        {
            if (!RegistryMatchesSnapshot(currentRegistry, journal.BeforeRegistry)
                || !RevisionMatchesSnapshot(currentRevision, journal.BeforeRevision))
            {
                throw new InvalidOperationException(
                    "Rollback journal is pending but the file remained at the pre-rollback state while registry/revision state drifted.");
            }

            DurableAtomicFile.Delete(journalPath);
            return currentRegistry;
        }

        if (!string.Equals(currentSha, journal.AfterFileSha256, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Provider catalog changed to an unknown state while a rollback recovery journal is pending; refusing reconciliation.");
        }

        await store.UpsertAsync(
            JsonUtils.DeepCopy(journal.AfterRegistry)
                ?? throw new InvalidOperationException("Could not restore post-rollback registry snapshot."),
            CancellationToken.None);
        await store.UpdateRevisionAsync(
            JsonUtils.DeepCopy(journal.AfterRevision)
                ?? throw new InvalidOperationException("Could not restore post-rollback revision snapshot."),
            CancellationToken.None);

        DurableAtomicFile.Delete(journalPath);
        return JsonUtils.DeepCopy(journal.AfterRegistry)
            ?? throw new InvalidOperationException("Could not project recovered post-rollback registry snapshot.");
    }

    public static void CompleteRollback(string destinationPath)
    {
        var path = RollbackJournalPath(destinationPath);
        if (File.Exists(path))
        {
            DurableAtomicFile.Delete(path);
        }
    }

    public static void Complete(string destinationPath)
    {
        var path = JournalPath(destinationPath);
        if (File.Exists(path))
        {
            DurableAtomicFile.Delete(path);
        }
    }

    public static string OperationLeasePath(string destinationPath)
    {
        destinationPath = Path.GetFullPath(destinationPath);
        var directory = Path.GetDirectoryName(destinationPath)
            ?? throw new InvalidOperationException("Provider catalog destination has no parent directory.");
        return Path.Combine(
            directory,
            "." + Path.GetFileName(destinationPath) + ".pattn-registry-operation.lock");
    }

    public static string JournalPath(string destinationPath)
    {
        destinationPath = Path.GetFullPath(destinationPath);
        var directory = Path.GetDirectoryName(destinationPath)
            ?? throw new InvalidOperationException("Provider catalog destination has no parent directory.");
        return Path.Combine(
            directory,
            "." + Path.GetFileName(destinationPath) + ".pattn-registry-apply.json");
    }

    public static string RollbackJournalPath(string destinationPath)
    {
        destinationPath = Path.GetFullPath(destinationPath);
        var directory = Path.GetDirectoryName(destinationPath)
            ?? throw new InvalidOperationException("Provider catalog destination has no parent directory.");
        return Path.Combine(
            directory,
            "." + Path.GetFileName(destinationPath) + ".pattn-registry-rollback.json");
    }

    private static void Validate(ProviderAsnCatalogPendingApplyJournal journal)
    {
        if (journal.Version != 1
            || journal.RegistryId.IsNullOrEmpty()
            || journal.RevisionId.IsNullOrEmpty()
            || journal.PlanId.IsNullOrEmpty()
            || journal.DestinationPath.IsNullOrEmpty()
            || journal.AfterSha256.IsNullOrEmpty())
        {
            throw new InvalidOperationException("Pending provider catalog apply journal is incomplete.");
        }

        if (journal.BeforeRegistry is null
            || !string.Equals(journal.BeforeRegistry.Id, journal.RegistryId, StringComparison.Ordinal)
            || journal.BeforeRegistry.FilePath.IsNullOrEmpty()
            || !PathEquals(journal.BeforeRegistry.FilePath, journal.DestinationPath))
        {
            throw new InvalidOperationException(
                "Pending provider catalog apply journal contains a registry snapshot for a different ID/path.");
        }

        if (!IsSha256(journal.AfterSha256))
        {
            throw new InvalidOperationException("Pending provider catalog apply journal has an invalid replacement SHA-256.");
        }

        if (journal.DestinationExisted)
        {
            var before = Convert.ToHexString(SHA256.HashData(journal.BeforeBytes)).ToLowerInvariant();
            if (!IsSha256(journal.BeforeSha256)
                || !string.Equals(before, journal.BeforeSha256, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Pending provider catalog apply journal has invalid previous-file evidence.");
            }
            if (!journal.BeforeRegistry.Sha256.IsNullOrEmpty()
                && !string.Equals(journal.BeforeRegistry.Sha256, journal.BeforeSha256, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "Pending provider catalog apply journal registry snapshot does not match the previous-file SHA-256.");
            }
        }
        else if (!string.Equals(journal.BeforeSha256, MissingFingerprint, StringComparison.Ordinal)
                 || journal.BeforeBytes.Length != 0)
        {
            throw new InvalidOperationException("Pending provider catalog apply journal has inconsistent missing-file evidence.");
        }
    }

    private static void ValidateRollback(ProviderAsnCatalogPendingRollbackJournal journal)
    {
        if (journal.Version != 1
            || journal.RegistryId.IsNullOrEmpty()
            || journal.RevisionId.IsNullOrEmpty()
            || journal.DestinationPath.IsNullOrEmpty()
            || journal.BeforeRegistry is null
            || journal.AfterRegistry is null
            || journal.BeforeRevision is null
            || journal.AfterRevision is null)
        {
            throw new InvalidOperationException("Pending provider catalog rollback journal is incomplete.");
        }

        if (!string.Equals(journal.BeforeRegistry.Id, journal.RegistryId, StringComparison.Ordinal)
            || !string.Equals(journal.AfterRegistry.Id, journal.RegistryId, StringComparison.Ordinal)
            || journal.BeforeRegistry.FilePath.IsNullOrEmpty()
            || journal.AfterRegistry.FilePath.IsNullOrEmpty()
            || !PathEquals(journal.BeforeRegistry.FilePath, journal.DestinationPath)
            || !PathEquals(journal.AfterRegistry.FilePath, journal.DestinationPath))
        {
            throw new InvalidOperationException(
                "Pending provider catalog rollback journal contains registry snapshots for a different ID/path.");
        }

        if (!string.Equals(journal.BeforeRevision.Id, journal.RevisionId, StringComparison.Ordinal)
            || !string.Equals(journal.AfterRevision.Id, journal.RevisionId, StringComparison.Ordinal)
            || !string.Equals(journal.BeforeRevision.RegistryId, journal.RegistryId, StringComparison.Ordinal)
            || !string.Equals(journal.AfterRevision.RegistryId, journal.RegistryId, StringComparison.Ordinal)
            || !PathEquals(journal.BeforeRevision.DestinationPath, journal.DestinationPath)
            || !PathEquals(journal.AfterRevision.DestinationPath, journal.DestinationPath)
            || journal.BeforeRevision.RolledBackAtUnixMs is not null
            || journal.AfterRevision.RolledBackAtUnixMs is null)
        {
            throw new InvalidOperationException(
                "Pending provider catalog rollback journal contains inconsistent revision snapshots.");
        }

        if (!(IsSha256(journal.BeforeFileSha256)
              || string.Equals(journal.BeforeFileSha256, MissingFingerprint, StringComparison.Ordinal))
            || !(IsSha256(journal.AfterFileSha256)
                 || string.Equals(journal.AfterFileSha256, MissingFingerprint, StringComparison.Ordinal)))
        {
            throw new InvalidOperationException(
                "Pending provider catalog rollback journal contains invalid file fingerprints.");
        }

        var expectedTarget = journal.BeforeRevision.DestinationExisted
            ? journal.BeforeRevision.BeforeSha256
            : MissingFingerprint;
        if (!string.Equals(journal.AfterFileSha256, expectedTarget, StringComparison.Ordinal)
            || !string.Equals(journal.BeforeRevision.BeforeSha256, journal.AfterRevision.BeforeSha256, StringComparison.Ordinal)
            || !string.Equals(journal.BeforeRevision.AfterSha256, journal.AfterRevision.AfterSha256, StringComparison.Ordinal)
            || string.Equals(journal.AfterRegistry.ActiveRevisionId, journal.RevisionId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Pending provider catalog rollback journal target state is inconsistent.");
        }

        if (journal.BeforeRevision.DestinationExisted
            && !string.Equals(journal.AfterRegistry.Sha256, journal.AfterFileSha256, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Pending provider catalog rollback journal target registry SHA does not match the restored file.");
        }
        if (!journal.BeforeRevision.DestinationExisted
            && !journal.AfterRegistry.Sha256.IsNullOrEmpty())
        {
            throw new InvalidOperationException(
                "Pending provider catalog rollback journal target registry unexpectedly retains a file SHA.");
        }
    }

    private static bool RegistryMatchesSnapshot(
        ProviderAsnCatalogRegistryItem current,
        ProviderAsnCatalogRegistryItem expected)
        => string.Equals(current.Id, expected.Id, StringComparison.Ordinal)
           && PathEquals(current.FilePath, expected.FilePath)
           && string.Equals(current.CatalogId, expected.CatalogId, StringComparison.Ordinal)
           && string.Equals(current.CatalogVersion, expected.CatalogVersion, StringComparison.Ordinal)
           && string.Equals(current.Sha256, expected.Sha256, StringComparison.Ordinal)
           && string.Equals(current.ActiveRevisionId, expected.ActiveRevisionId, StringComparison.Ordinal)
           && current.UnregisteredAtUnixMs == expected.UnregisteredAtUnixMs;

    private static bool RevisionMatchesSnapshot(
        ProviderAsnCatalogRevisionItem current,
        ProviderAsnCatalogRevisionItem expected)
        => string.Equals(current.Id, expected.Id, StringComparison.Ordinal)
           && string.Equals(current.RegistryId, expected.RegistryId, StringComparison.Ordinal)
           && string.Equals(current.PlanId, expected.PlanId, StringComparison.Ordinal)
           && PathEquals(current.DestinationPath, expected.DestinationPath)
           && string.Equals(current.BeforeSha256, expected.BeforeSha256, StringComparison.Ordinal)
           && string.Equals(current.AfterSha256, expected.AfterSha256, StringComparison.Ordinal)
           && current.RolledBackAtUnixMs == expected.RolledBackAtUnixMs
           && current.RollbackForced == expected.RollbackForced;

    private static bool RevisionMatchesJournal(
        ProviderAsnCatalogRevisionItem revision,
        ProviderAsnCatalogPendingApplyJournal journal)
        => string.Equals(revision.Id, journal.RevisionId, StringComparison.Ordinal)
           && string.Equals(revision.RegistryId, journal.RegistryId, StringComparison.Ordinal)
           && string.Equals(revision.PlanId, journal.PlanId, StringComparison.Ordinal)
           && PathEquals(revision.DestinationPath, journal.DestinationPath)
           && string.Equals(revision.BeforeSha256, journal.BeforeSha256, StringComparison.Ordinal)
           && string.Equals(revision.AfterSha256, journal.AfterSha256, StringComparison.Ordinal);

    private static bool IsSha256(string value)
        => value.Length == 64 && value.All(Uri.IsHexDigit);

    private static async Task<string> CurrentFingerprintAsync(string path, CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
        {
            return MissingFingerprint;
        }

        var raw = await File.ReadAllBytesAsync(path, cancellationToken);
        return Convert.ToHexString(SHA256.HashData(raw)).ToLowerInvariant();
    }

    private static bool PathEquals(string left, string right)
        => string.Equals(
            Path.GetFullPath(left),
            Path.GetFullPath(right),
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
}

internal static class ProviderAsnCatalogFaultInjection
{
    private static Action<string>? _handler;

    public static Action<string>? Handler
    {
        get => Volatile.Read(ref _handler);
        set => Volatile.Write(ref _handler, value);
    }

    public static void Hit(string checkpoint)
        => Volatile.Read(ref _handler)?.Invoke(checkpoint);
}
