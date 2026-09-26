using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;
using ServiceLib.Models.Entities;

namespace ServiceLib.Tests.Reviver;

public class LifecycleRetentionServiceTests
{
    [Test]
    public async Task SelectCandidateIds_ShouldBeOldestFirstStrictlyBeforeCutoffAndBounded()
    {
        var rows = new[]
        {
            new Row("new", 300),
            new Row("oldest", 10),
            new Row("cutoff", 100),
            new Row("middle", 50),
            new Row("middle", 40),
        };

        var ids = LifecycleRetentionService.SelectCandidateIds(
            rows,
            cutoffUnixMs: 100,
            maximum: 2,
            x => x.At,
            x => x.Id);

        await ids.SequenceEqual(["oldest", "middle"]).Should().BeTrue();
    }

    [Test]
    public async Task RemoteProvenanceEligibility_ShouldPreserveSurvivingRevisionEvidence()
    {
        var cutoff = 1_000L;
        var old = new ProviderAsnCatalogRemoteApplyProvenanceItem
        {
            RevisionId = "revision-1",
            AppliedAtUnixMs = 100,
        };
        var activeRevision = new ProviderAsnCatalogRevisionItem
        {
            Id = "revision-1",
            RolledBackAtUnixMs = null,
        };
        var rolledBackRevision = new ProviderAsnCatalogRevisionItem
        {
            Id = "revision-1",
            RolledBackAtUnixMs = 500,
        };

        await LifecycleRetentionService.IsRemoteProvenanceRetentionEligible(old, activeRevision, cutoff)
            .Should().BeFalse();
        await LifecycleRetentionService.IsRemoteProvenanceRetentionEligible(old, rolledBackRevision, cutoff)
            .Should().BeTrue();
        await LifecycleRetentionService.IsRemoteProvenanceRetentionEligible(old, null, cutoff)
            .Should().BeTrue();

        old.AppliedAtUnixMs = cutoff;
        await LifecycleRetentionService.IsRemoteProvenanceRetentionEligible(old, rolledBackRevision, cutoff)
            .Should().BeFalse();
    }

    [Test]
    public async Task Apply_ShouldRejectDuplicateTablePlansBeforeTouchingStorage()
    {
        var service = new LifecycleRetentionService();
        var createdAt = new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero);
        var policy = new LifecycleRetentionPolicy { MaximumDeletesPerTable = 10 };
        var cutoff = createdAt.Subtract(policy.DnsRepairHistoryRetention).ToUnixTimeMilliseconds();
        var plan = new LifecycleRetentionPlan
        {
            CreatedAt = createdAt,
            Policy = policy,
            Tables =
            [
                new LifecycleRetentionTablePlan
                {
                    Table = nameof(DnsRepairHistoryItem),
                    CutoffUnixMs = cutoff,
                    CandidateIds = ["a"],
                },
                new LifecycleRetentionTablePlan
                {
                    Table = nameof(DnsRepairHistoryItem),
                    CutoffUnixMs = cutoff,
                    CandidateIds = ["b"],
                },
            ],
        };

        var threw = false;
        try
        {
            await service.ApplyAsync(plan);
        }
        catch (InvalidOperationException)
        {
            threw = true;
        }

        await threw.Should().BeTrue();
    }

    [Test]
    public async Task Apply_ShouldRejectDuplicateIdsAndUnknownTablesBeforeTouchingStorage()
    {
        var service = new LifecycleRetentionService();
        var createdAt = new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero);
        var policy = new LifecycleRetentionPolicy { MaximumDeletesPerTable = 10 };

        foreach (var plan in new[]
        {
            new LifecycleRetentionPlan
            {
                CreatedAt = createdAt,
                Policy = policy,
                Tables =
                [
                    new LifecycleRetentionTablePlan
                    {
                        Table = nameof(DnsResolverTelemetryItem),
                        CutoffUnixMs = createdAt.Subtract(policy.ResolverTelemetryRetention).ToUnixTimeMilliseconds(),
                        CandidateIds = ["same", "same"],
                    }
                ],
            },
            new LifecycleRetentionPlan
            {
                CreatedAt = createdAt,
                Policy = policy,
                Tables =
                [
                    new LifecycleRetentionTablePlan
                    {
                        Table = "not-a-real-table",
                        CutoffUnixMs = 1,
                        CandidateIds = ["a"],
                    }
                ],
            },
        })
        {
            var threw = false;
            try
            {
                await service.ApplyAsync(plan);
            }
            catch (InvalidOperationException)
            {
                threw = true;
            }
            await threw.Should().BeTrue();
        }
    }

    [Test]
    public async Task Apply_ShouldRejectCutoffThatDoesNotMatchFrozenPolicy()
    {
        var service = new LifecycleRetentionService();
        var createdAt = new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero);
        var policy = new LifecycleRetentionPolicy { MaximumDeletesPerTable = 10 };
        var plan = new LifecycleRetentionPlan
        {
            CreatedAt = createdAt,
            Policy = policy,
            Tables =
            [
                new LifecycleRetentionTablePlan
                {
                    Table = nameof(RepairPromotionHistoryItem),
                    CutoffUnixMs = createdAt.AddDays(30).ToUnixTimeMilliseconds(),
                    CandidateIds = ["a"],
                }
            ],
        };

        var threw = false;
        try
        {
            await service.ApplyAsync(plan);
        }
        catch (InvalidOperationException)
        {
            threw = true;
        }

        await threw.Should().BeTrue();
    }

    [Test]
    public async Task Apply_ShouldRejectRemoteProvenanceCutoffThatDoesNotMatchFrozenPolicy()
    {
        var service = new LifecycleRetentionService();
        var createdAt = new DateTimeOffset(2026, 9, 24, 12, 0, 0, TimeSpan.Zero);
        var policy = new LifecycleRetentionPolicy
        {
            MaximumDeletesPerTable = 10,
            RemoteCatalogProvenanceRetention = TimeSpan.FromDays(730),
        };
        var plan = new LifecycleRetentionPlan
        {
            CreatedAt = createdAt,
            Policy = policy,
            Tables =
            [
                new LifecycleRetentionTablePlan
                {
                    Table = nameof(ProviderAsnCatalogRemoteApplyProvenanceItem),
                    CutoffUnixMs = createdAt.Subtract(TimeSpan.FromDays(1)).ToUnixTimeMilliseconds(),
                    CandidateIds = ["revision-1"],
                }
            ],
        };

        var threw = false;
        try
        {
            await service.ApplyAsync(plan);
        }
        catch (InvalidOperationException)
        {
            threw = true;
        }

        await threw.Should().BeTrue();
    }

    [Test]
    public async Task Apply_ShouldRejectRemoteSourceRevisionCutoffThatDoesNotMatchFrozenPolicy()
    {
        var service = new LifecycleRetentionService();
        var createdAt = new DateTimeOffset(2026, 9, 24, 12, 0, 0, TimeSpan.Zero);
        var policy = new LifecycleRetentionPolicy
        {
            MaximumDeletesPerTable = 10,
            RemoteSourceRevisionRetention = TimeSpan.FromDays(730),
        };
        var plan = new LifecycleRetentionPlan
        {
            CreatedAt = createdAt,
            Policy = policy,
            Tables =
            [
                new LifecycleRetentionTablePlan
                {
                    Table = nameof(ProviderAsnCatalogRemoteSourceRevisionItem),
                    CutoffUnixMs = createdAt.Subtract(TimeSpan.FromDays(1)).ToUnixTimeMilliseconds(),
                    CandidateIds = ["trust-revision-1"],
                }
            ],
        };

        var threw = false;
        try
        {
            await service.ApplyAsync(plan);
        }
        catch (InvalidOperationException)
        {
            threw = true;
        }

        await threw.Should().BeTrue();
    }

    [Test]
    public async Task DeleteRowsAsync_WhenInterrupted_ShouldSurfaceFailureAndRemainRetryable()
    {
        var table = new LifecycleRetentionTablePlan
        {
            Table = nameof(DnsRepairHistoryItem),
            CutoffUnixMs = 100,
            CandidateIds = ["a", "b", "c"],
        };
        var rows = new[] { new Row("a", 1), new Row("b", 2), new Row("c", 3) };
        var attempted = new List<string>();

        var threw = false;
        try
        {
            await LifecycleRetentionService.DeleteRowsAsync(
                table,
                rows,
                x => x.Id,
                CancellationToken.None,
                (row, _) =>
                {
                    attempted.Add(row.Id);
                    if (row.Id == "b")
                    {
                        throw new IOException("simulated interruption");
                    }
                    return Task.FromResult(1);
                });
        }
        catch (IOException ex)
        {
            threw = ex.Message == "simulated interruption";
        }

        await threw.Should().BeTrue();
        await attempted.SequenceEqual(["a", "b"]).Should().BeTrue();

        // A maintenance retry is idempotent: the already-deleted row is counted as
        // missing while the surviving planned rows can still be removed.
        var retry = await LifecycleRetentionService.DeleteRowsAsync(
            table,
            rows,
            x => x.Id,
            CancellationToken.None,
            (row, _) => Task.FromResult(row.Id == "a" ? 0 : 1));

        await retry.Planned.Should().BeEqualTo(3);
        await retry.Deleted.Should().BeEqualTo(2);
        await retry.AlreadyMissing.Should().BeEqualTo(1);
    }

    private sealed record Row(string Id, long At);
}
