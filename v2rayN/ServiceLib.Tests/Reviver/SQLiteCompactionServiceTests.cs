using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;

namespace ServiceLib.Tests.Reviver;

public class SQLiteCompactionServiceTests
{
    [Test]
    public async Task ComputeEstimatedReclaim_ShouldHandleNormalZeroAndOverflowCases()
    {
        await SQLiteCompactionService.ComputeEstimatedReclaim(4096, 10).Should().BeEqualTo(40960);
        await SQLiteCompactionService.ComputeEstimatedReclaim(4096, 0).Should().BeEqualTo(0);
        await SQLiteCompactionService.ComputeEstimatedReclaim(0, 10).Should().BeEqualTo(0);
        await SQLiteCompactionService.ComputeEstimatedReclaim(long.MaxValue, 2).Should().BeEqualTo(long.MaxValue);
    }

    [Test]
    public async Task IsSameDatabaseState_ShouldRejectAnyFrozenStateDrift()
    {
        var path = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "pattn-db-test.db"));
        var baseline = new SQLiteCompactionPlan
        {
            CreatedAt = DateTimeOffset.UtcNow,
            DatabasePath = path,
            DatabaseLengthBytes = 1000,
            LastWriteUtcTicks = 123,
            PageSizeBytes = 4096,
            PageCount = 20,
            FreePageCount = 5,
            EstimatedReclaimBytes = 20480,
        };

        await SQLiteCompactionService.IsSameDatabaseState(baseline, baseline with { })
            .Should().BeTrue();
        await SQLiteCompactionService.IsSameDatabaseState(
                baseline,
                baseline with { FreePageCount = 6 })
            .Should().BeFalse();
        await SQLiteCompactionService.IsSameDatabaseState(
                baseline,
                baseline with { LastWriteUtcTicks = 124 })
            .Should().BeFalse();
        await SQLiteCompactionService.IsSameDatabaseState(
                baseline,
                baseline with { DatabaseLengthBytes = 1001 })
            .Should().BeFalse();
    }

    [Test]
    public async Task ValidateWalCheckpointResult_ShouldAcceptNoWalSentinelAndRejectMalformedOrBusyResults()
    {
        SQLiteCompactionService.ValidateWalCheckpointResult(0, -1, -1);
        SQLiteCompactionService.ValidateWalCheckpointResult(0, 0, 0);

        var malformedThrew = false;
        try
        {
            SQLiteCompactionService.ValidateWalCheckpointResult(0, -1, 0);
        }
        catch (InvalidOperationException)
        {
            malformedThrew = true;
        }
        await malformedThrew.Should().BeTrue();

        var busyThrew = false;
        try
        {
            SQLiteCompactionService.ValidateWalCheckpointResult(1, -1, -1);
        }
        catch (InvalidOperationException)
        {
            busyThrew = true;
        }
        await busyThrew.Should().BeTrue();
    }

    [Test]
    public async Task ExecuteCompactionCommands_WhenVacuumFails_ShouldSurfaceFailureAfterCheckpoint()
    {
        var commands = new List<string>();
        var threw = false;
        try
        {
            await SQLiteCompactionService.ExecuteCompactionCommandsAsync(
                () =>
                {
                    commands.Add("PRAGMA wal_checkpoint(TRUNCATE);");
                    return Task.CompletedTask;
                },
                sql =>
                {
                    commands.Add(sql);
                    if (sql == "VACUUM;")
                    {
                        throw new IOException("simulated vacuum interruption");
                    }
                    return Task.FromResult(0);
                },
                CancellationToken.None);
        }
        catch (IOException ex)
        {
            threw = ex.Message == "simulated vacuum interruption";
        }

        await threw.Should().BeTrue();
        await commands.SequenceEqual(["PRAGMA wal_checkpoint(TRUNCATE);", "VACUUM;"]).Should().BeTrue();
    }

    [Test]
    public async Task ExecuteCompactionCommands_WhenCancelledAfterCheckpoint_ShouldNotStartVacuum()
    {
        using var cts = new CancellationTokenSource();
        var commands = new List<string>();

        var cancelled = false;
        try
        {
            await SQLiteCompactionService.ExecuteCompactionCommandsAsync(
                () =>
                {
                    commands.Add("PRAGMA wal_checkpoint(TRUNCATE);");
                    cts.Cancel();
                    return Task.CompletedTask;
                },
                sql =>
                {
                    commands.Add(sql);
                    return Task.FromResult(0);
                },
                cts.Token);
        }
        catch (OperationCanceledException)
        {
            cancelled = true;
        }

        await cancelled.Should().BeTrue();
        await commands.SequenceEqual(["PRAGMA wal_checkpoint(TRUNCATE);"]).Should().BeTrue();
    }
}
