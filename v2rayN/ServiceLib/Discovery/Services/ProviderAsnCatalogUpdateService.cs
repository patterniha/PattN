using ServiceLib.Discovery.Models;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Explicit transactional provider-catalog file update. Preparation validates/audits/diffs without touching disk.
/// Apply performs stale-state detection and same-directory atomic replacement. Rollback protects newer edits.
/// </summary>
public sealed class ProviderAsnCatalogUpdateService
{
    private const string MissingFingerprint = "<missing>";

    public async Task<ProviderAsnCatalogUpdatePlan> PrepareAsync(
        string destinationPath,
        ReadOnlyMemory<byte> newBytes,
        ProviderAsnCatalogUpdateOptions? options = null,
        DateTimeOffset? now = null,
        CancellationToken cancellationToken = default)
    {
        options ??= new ProviderAsnCatalogUpdateOptions();
        ValidateOptions(options);
        cancellationToken.ThrowIfCancellationRequested();

        var path = NormalizePath(destinationPath);
        if (newBytes.IsEmpty)
        {
            throw new ArgumentException("Provider/ASN catalog update payload is empty.", nameof(newBytes));
        }

        var preparedAt = now ?? DateTimeOffset.UtcNow;
        var afterBytes = newBytes.ToArray();
        var after = JsonProviderAsnEndpointCatalog.FromBytes(afterBytes);
        var afterAudit = after.Audit(preparedAt, options.AuditPolicy);
        if (!afterAudit.Valid)
        {
            throw new InvalidOperationException(
                $"Provider/ASN catalog update failed metadata audit: {string.Join(",", afterAudit.Errors)}");
        }
        if (options.RequireFreshNewCatalog
            && (!afterAudit.FreshnessKnown || afterAudit.Stale))
        {
            throw new InvalidOperationException("Provider/ASN catalog update requires a fresh catalog timestamp.");
        }

        var existed = File.Exists(path);
        var beforeBytes = existed
            ? await File.ReadAllBytesAsync(path, cancellationToken)
            : [];
        var beforeSha = existed ? Fingerprint(beforeBytes) : MissingFingerprint;

        JsonProviderAsnEndpointCatalog? before = null;
        ProviderAsnCatalogAudit? beforeAudit = null;
        ProviderAsnCatalogDiff? diff = null;
        var beforeError = string.Empty;

        if (existed)
        {
            try
            {
                before = JsonProviderAsnEndpointCatalog.FromBytes(beforeBytes);
                beforeAudit = before.Audit(preparedAt, options.AuditPolicy);
            }
            catch (InvalidOperationException ex)
            {
                beforeError = ex.Message;
            }

            if (before is not null)
            {
                if (options.RequireSameCatalogId
                    && !string.Equals(
                        before.Document.Id.Trim(),
                        after.Document.Id.Trim(),
                        StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        $"Catalog ID change from '{before.Document.Id}' to '{after.Document.Id}' is not allowed by this update plan.");
                }
                try
                {
                    diff = ProviderAsnCatalogDiffService.Compare(before, after);
                }
                catch (InvalidOperationException ex)
                {
                    beforeError = beforeError.IsNullOrEmpty()
                        ? $"Catalog diff unavailable: {ex.Message}"
                        : beforeError + "; Catalog diff unavailable: " + ex.Message;
                }
            }
        }

        return new ProviderAsnCatalogUpdatePlan
        {
            DestinationPath = path,
            PreparedAt = preparedAt,
            DestinationExisted = existed,
            BeforeSha256 = beforeSha,
            AfterSha256 = after.Sha256,
            BeforeCatalogId = before?.Document.Id ?? string.Empty,
            BeforeCatalogVersion = before?.Document.Version ?? string.Empty,
            AfterCatalogId = after.Document.Id,
            AfterCatalogVersion = after.Document.Version,
            BeforeCatalogError = beforeError,
            BeforeAudit = beforeAudit,
            AfterAudit = afterAudit,
            Diff = diff,
            BeforeBytes = beforeBytes,
            AfterBytes = afterBytes,
        };
    }

    public async Task<ProviderAsnCatalogUpdateReceipt> ApplyAsync(
        ProviderAsnCatalogUpdatePlan plan,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plan);
        cancellationToken.ThrowIfCancellationRequested();
        ValidatePlan(plan);

        await using var lease = await AcquireUpdateLeaseAsync(plan.DestinationPath, cancellationToken);
        var current = await CurrentFingerprintAsync(plan.DestinationPath, cancellationToken);
        if (!string.Equals(current, plan.BeforeSha256, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Provider/ASN catalog changed after update preparation; prepare a fresh update plan.");
        }

        var replaced = false;
        try
        {
            await WriteAtomicallyAsync(
                plan.DestinationPath,
                plan.AfterBytes,
                plan.BeforeSha256,
                cancellationToken);
            replaced = true;

            var written = await CurrentFingerprintAsync(plan.DestinationPath, cancellationToken);
            if (!string.Equals(written, plan.AfterSha256, StringComparison.Ordinal))
            {
                throw new IOException("Provider/ASN catalog SHA-256 verification failed after atomic replacement.");
            }
        }
        catch
        {
            if (replaced)
            {
                await RestoreBeforeBestEffortAsync(plan, CancellationToken.None);
            }
            throw;
        }

        return new ProviderAsnCatalogUpdateReceipt
        {
            PlanId = plan.Id,
            DestinationPath = plan.DestinationPath,
            DestinationExisted = plan.DestinationExisted,
            BeforeSha256 = plan.BeforeSha256,
            AfterSha256 = plan.AfterSha256,
            BeforeBytes = plan.BeforeBytes.ToArray(),
        };
    }

    public async Task RollbackAsync(
        ProviderAsnCatalogUpdateReceipt receipt,
        bool force = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        cancellationToken.ThrowIfCancellationRequested();
        ValidateReceipt(receipt);

        await using var lease = await AcquireUpdateLeaseAsync(receipt.DestinationPath, cancellationToken);
        var current = await CurrentFingerprintAsync(receipt.DestinationPath, cancellationToken);
        if (!force && !string.Equals(current, receipt.AfterSha256, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Provider/ASN catalog changed after this update; rollback would overwrite newer edits.");
        }

        if (receipt.DestinationExisted)
        {
            await WriteAtomicallyAsync(
                receipt.DestinationPath,
                receipt.BeforeBytes,
                force ? null : receipt.AfterSha256,
                cancellationToken);
            var restored = await CurrentFingerprintAsync(receipt.DestinationPath, cancellationToken);
            if (!string.Equals(restored, receipt.BeforeSha256, StringComparison.Ordinal))
            {
                throw new IOException("Provider/ASN catalog rollback SHA-256 verification failed.");
            }
        }
        else if (File.Exists(receipt.DestinationPath))
        {
            if (!force)
            {
                var beforeDelete = await CurrentFingerprintAsync(receipt.DestinationPath, cancellationToken);
                if (!string.Equals(beforeDelete, receipt.AfterSha256, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException("Provider/ASN catalog changed during rollback; refusing to delete newer content.");
                }
            }
            DurableAtomicFile.Delete(receipt.DestinationPath);
        }
    }

    private static void ValidatePlan(ProviderAsnCatalogUpdatePlan plan)
    {
        if (plan.PreparedAt == default)
        {
            throw new InvalidOperationException("Provider/ASN catalog update plan is missing its preparation timestamp.");
        }
        if (plan.AfterBytes.Length == 0)
        {
            throw new InvalidOperationException("Provider/ASN catalog update plan contains no replacement bytes.");
        }
        if (plan.DestinationPath.IsNullOrEmpty())
        {
            throw new InvalidOperationException("Provider/ASN catalog update plan is missing its destination path.");
        }

        var fingerprint = Fingerprint(plan.AfterBytes);
        if (!string.Equals(fingerprint, plan.AfterSha256, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Provider/ASN catalog update payload no longer matches its prepared SHA-256.");
        }

        var parsedAfter = JsonProviderAsnEndpointCatalog.FromBytes(plan.AfterBytes);
        if (!string.Equals(parsedAfter.Document.Id, plan.AfterCatalogId, StringComparison.Ordinal)
            || !string.Equals(parsedAfter.Document.Version, plan.AfterCatalogVersion, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Provider/ASN catalog update payload no longer matches its prepared catalog identity.");
        }
        if (plan.DestinationExisted)
        {
            if (!string.Equals(Fingerprint(plan.BeforeBytes), plan.BeforeSha256, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Provider/ASN catalog update plan contains invalid previous-file evidence.");
            }
        }
        else if (!string.Equals(plan.BeforeSha256, MissingFingerprint, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Provider/ASN catalog update plan has inconsistent missing-file evidence.");
        }
    }

    private static void ValidateReceipt(ProviderAsnCatalogUpdateReceipt receipt)
    {
        if (receipt.PlanId.IsNullOrEmpty() || receipt.DestinationPath.IsNullOrEmpty())
        {
            throw new InvalidOperationException("Provider/ASN catalog rollback receipt is incomplete.");
        }
        if (receipt.DestinationExisted)
        {
            if (!string.Equals(Fingerprint(receipt.BeforeBytes), receipt.BeforeSha256, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Provider/ASN catalog rollback receipt contains invalid previous-file evidence.");
            }
        }
        else if (!string.Equals(receipt.BeforeSha256, MissingFingerprint, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Provider/ASN catalog rollback receipt has inconsistent missing-file evidence.");
        }
        if (receipt.AfterSha256.IsNullOrEmpty())
        {
            throw new InvalidOperationException("Provider/ASN catalog rollback receipt is missing its applied SHA-256.");
        }
    }

    private static void ValidateOptions(ProviderAsnCatalogUpdateOptions options)
    {
        ArgumentNullException.ThrowIfNull(options.AuditPolicy);
        if (options.AuditPolicy.MaximumAge <= TimeSpan.Zero
            || options.AuditPolicy.MaximumAge > TimeSpan.FromDays(3650))
        {
            throw new ArgumentOutOfRangeException(nameof(options.AuditPolicy.MaximumAge));
        }
    }

    private static async Task<FileStream> AcquireUpdateLeaseAsync(
        string path,
        CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(path);
        if (directory.IsNullOrEmpty() || !Directory.Exists(directory))
        {
            throw new DirectoryNotFoundException($"Provider/ASN catalog directory does not exist: {directory}");
        }

        var lockPath = Path.Combine(
            directory,
            "." + Path.GetFileName(path) + ".pattn-update.lock");
        var deadline = DateTime.UtcNow.AddSeconds(10);
        IOException? lastError = null;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                // Keep the sidecar instead of deleting it after release. Unlinking a
                // lock file can split Unix writers across different inodes while one
                // process still holds the old file. FileShare.None gives cooperating
                // PattN processes one stable lease per destination catalog.
                return new FileStream(
                    lockPath,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    1,
                    FileOptions.Asynchronous | FileOptions.WriteThrough);
            }
            catch (IOException ex) when (DateTime.UtcNow < deadline)
            {
                lastError = ex;
                await Task.Delay(50, cancellationToken);
                continue;
            }

            throw new IOException(
                $"Timed out waiting for the provider/ASN catalog update lease: {lockPath}",
                lastError);
        }
    }

    private static string NormalizePath(string value)
    {
        if (value.IsNullOrEmpty())
        {
            throw new ArgumentException("Provider/ASN catalog destination path is required.", nameof(value));
        }
        return Path.GetFullPath(value);
    }

    private static async Task<string> CurrentFingerprintAsync(
        string path,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
        {
            return MissingFingerprint;
        }
        var bytes = await File.ReadAllBytesAsync(path, cancellationToken);
        return Fingerprint(bytes);
    }

    private static string Fingerprint(ReadOnlySpan<byte> bytes)
        => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static Task WriteAtomicallyAsync(
        string path,
        ReadOnlyMemory<byte> bytes,
        string? expectedCurrentFingerprint,
        CancellationToken cancellationToken)
        => DurableAtomicFile.WriteAsync(
            path,
            bytes,
            async token =>
            {
                if (expectedCurrentFingerprint.IsNullOrEmpty())
                {
                    return;
                }

                var current = await CurrentFingerprintAsync(path, token);
                if (!string.Equals(current, expectedCurrentFingerprint, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        "Provider/ASN catalog changed while the replacement file was being prepared; refusing atomic replace.");
                }
            },
            cancellationToken);

    private static async Task RestoreBeforeBestEffortAsync(
        ProviderAsnCatalogUpdatePlan plan,
        CancellationToken cancellationToken)
    {
        try
        {
            var current = await CurrentFingerprintAsync(plan.DestinationPath, cancellationToken);
            if (!string.Equals(current, plan.AfterSha256, StringComparison.Ordinal))
            {
                Logging.SaveLog(
                    "Provider catalog compensation skipped because destination no longer matches the applied catalog.");
                return;
            }

            if (plan.DestinationExisted)
            {
                await WriteAtomicallyAsync(
                    plan.DestinationPath,
                    plan.BeforeBytes,
                    plan.AfterSha256,
                    cancellationToken);
            }
            else if (File.Exists(plan.DestinationPath))
            {
                DurableAtomicFile.Delete(plan.DestinationPath);
            }
        }
        catch (Exception ex)
        {
            Logging.SaveLog($"Provider catalog compensation failed: {ex}");
        }
    }
}
