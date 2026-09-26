namespace ServiceLib.Discovery.Models;

public sealed record SQLiteCompactionPlan
{
    public DateTimeOffset CreatedAt { get; init; }
    public required string DatabasePath { get; init; }
    public long DatabaseLengthBytes { get; init; }
    public long LastWriteUtcTicks { get; init; }
    public long PageSizeBytes { get; init; }
    public long PageCount { get; init; }
    public long FreePageCount { get; init; }
    public long EstimatedReclaimBytes { get; init; }
}

public sealed record SQLiteCompactionResult
{
    public required SQLiteCompactionPlan Before { get; init; }
    public required SQLiteCompactionPlan After { get; init; }
    public long FileBytesReclaimed { get; init; }
}
