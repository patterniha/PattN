using ServiceLib.Discovery.Models;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Explicit SQLite VACUUM workflow. Preview is read-only. Apply rejects stale plans, checkpoints WAL, then VACUUMs.
/// Nothing in application startup or ordinary maintenance calls this service automatically.
/// </summary>
public sealed class SQLiteCompactionService
{
    public async Task<SQLiteCompactionPlan> PreviewAsync(
        DateTimeOffset? now = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var path = SQLiteHelper.Instance.DatabasePath;
        var info = new FileInfo(path);
        if (!info.Exists)
        {
            throw new FileNotFoundException("SQLite database file does not exist.", path);
        }

        var pageSize = await ReadPragmaAsync<PageSizeRow>("PRAGMA page_size;", x => x.Value);
        var pageCount = await ReadPragmaAsync<PageCountRow>("PRAGMA page_count;", x => x.Value);
        var freePages = await ReadPragmaAsync<FreeListRow>("PRAGMA freelist_count;", x => x.Value);

        return new SQLiteCompactionPlan
        {
            CreatedAt = now ?? DateTimeOffset.UtcNow,
            DatabasePath = path,
            DatabaseLengthBytes = info.Length,
            LastWriteUtcTicks = info.LastWriteTimeUtc.Ticks,
            PageSizeBytes = pageSize,
            PageCount = pageCount,
            FreePageCount = freePages,
            EstimatedReclaimBytes = ComputeEstimatedReclaim(pageSize, freePages),
        };
    }

    public async Task<SQLiteCompactionResult> ApplyAsync(
        SQLiteCompactionPlan plan,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (plan.CreatedAt == default || plan.DatabasePath.IsNullOrEmpty())
        {
            throw new InvalidOperationException("SQLite compaction plan is incomplete.");
        }

        var current = await PreviewAsync(cancellationToken: cancellationToken);
        if (!IsSameDatabaseState(plan, current))
        {
            throw new InvalidOperationException(
                "SQLite database changed after the compaction preview. Prepare a new preview before applying.");
        }

        await ExecuteCompactionCommandsAsync(
            () => CheckpointWalAsync(cancellationToken),
            sql => SQLiteHelper.Instance.ExecuteAsync(sql),
            cancellationToken);

        var after = await PreviewAsync(cancellationToken: CancellationToken.None);
        return new SQLiteCompactionResult
        {
            Before = plan,
            After = after,
            FileBytesReclaimed = Math.Max(0, plan.DatabaseLengthBytes - after.DatabaseLengthBytes),
        };
    }

    internal static async Task ExecuteCompactionCommandsAsync(
        Func<Task> checkpointWal,
        Func<string, Task<int>> execute,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(checkpointWal);
        ArgumentNullException.ThrowIfNull(execute);
        cancellationToken.ThrowIfCancellationRequested();
        await checkpointWal();
        cancellationToken.ThrowIfCancellationRequested();
        await execute("VACUUM;");
    }

    internal static async Task CheckpointWalAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var rows = await SQLiteHelper.Instance.QueryAsync<WalCheckpointRow>(
            "PRAGMA wal_checkpoint(TRUNCATE);");
        cancellationToken.ThrowIfCancellationRequested();

        if (rows.Count != 1)
        {
            throw new InvalidOperationException(
                $"SQLite WAL checkpoint returned {rows.Count} rows; expected exactly one.");
        }

        var row = rows[0];
        ValidateWalCheckpointResult(row.Busy, row.LogFrames, row.CheckpointedFrames);
    }

    internal static void ValidateWalCheckpointResult(
        int busy,
        int logFrames,
        int checkpointedFrames)
    {
        if (busy != 0)
        {
            throw new InvalidOperationException(
                $"SQLite WAL checkpoint could not obtain the required lock (busy={busy}, log={logFrames}, checkpointed={checkpointedFrames}).");
        }

        // SQLite returns (-1, -1) when there is no WAL to checkpoint. In that case
        // wal_checkpoint is a documented harmless no-op, not a durability failure.
        if (logFrames == -1 && checkpointedFrames == -1)
        {
            return;
        }

        if (logFrames < 0 || checkpointedFrames < 0)
        {
            throw new InvalidOperationException(
                $"SQLite WAL checkpoint returned invalid frame counts (log={logFrames}, checkpointed={checkpointedFrames}).");
        }
    }

    public static bool IsSameDatabaseState(SQLiteCompactionPlan expected, SQLiteCompactionPlan actual)
        => PathEquals(expected.DatabasePath, actual.DatabasePath)
           && expected.DatabaseLengthBytes == actual.DatabaseLengthBytes
           && expected.LastWriteUtcTicks == actual.LastWriteUtcTicks
           && expected.PageSizeBytes == actual.PageSizeBytes
           && expected.PageCount == actual.PageCount
           && expected.FreePageCount == actual.FreePageCount;

    public static long ComputeEstimatedReclaim(long pageSizeBytes, long freePageCount)
    {
        if (pageSizeBytes <= 0 || freePageCount <= 0)
        {
            return 0;
        }
        try
        {
            return checked(pageSizeBytes * freePageCount);
        }
        catch (OverflowException)
        {
            return long.MaxValue;
        }
    }

    private static async Task<long> ReadPragmaAsync<T>(
        string sql,
        Func<T, long> value)
        where T : new()
    {
        var rows = await SQLiteHelper.Instance.QueryAsync<T>(sql);
        if (rows.Count == 0)
        {
            throw new InvalidOperationException($"SQLite pragma returned no value: {sql}");
        }
        return value(rows[0]);
    }

    private static bool PathEquals(string left, string right)
        => string.Equals(
            Path.GetFullPath(left),
            Path.GetFullPath(right),
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    private sealed class WalCheckpointRow
    {
        [Column("busy")]
        public int Busy { get; set; }

        [Column("log")]
        public int LogFrames { get; set; }

        [Column("checkpointed")]
        public int CheckpointedFrames { get; set; }
    }

    private sealed class PageSizeRow
    {
        [Column("page_size")]
        public long Value { get; set; }
    }

    private sealed class PageCountRow
    {
        [Column("page_count")]
        public long Value { get; set; }
    }

    private sealed class FreeListRow
    {
        [Column("freelist_count")]
        public long Value { get; set; }
    }
}
