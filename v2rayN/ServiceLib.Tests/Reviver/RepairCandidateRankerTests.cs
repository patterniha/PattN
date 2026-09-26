using ServiceLib.Reviver.Models;
using ServiceLib.Reviver.Ranking;

namespace ServiceLib.Tests.Reviver;

public class RepairCandidateRankerTests
{
    [Test]
    public async Task Rank_ShouldPreferReliableLowRiskRepairOverSlightlyFasterFragileRepair()
    {
        var stable = Candidate(
            "stable",
            ERepairConfidence.LowRisk,
            attempts: 3,
            successes: 3,
            consecutive: 3,
            latencyMs: 62,
            loss: 0);
        var fragile = Candidate(
            "fragile",
            ERepairConfidence.EvidenceBacked,
            attempts: 3,
            successes: 2,
            consecutive: 1,
            latencyMs: 35,
            loss: 1d / 3d);

        var ranked = new RepairCandidateRanker().Rank([fragile, stable]);

        await ranked.Count.Should().BeEqualTo(2);
        await ranked[0].Id.Should().BeEqualTo("stable");
        await (ranked[0].Score > ranked[1].Score).Should().BeTrue();
    }

    [Test]
    public async Task Rank_ShouldExcludeCandidatesThatDidNotPassRuntimeValidation()
    {
        var valid = Candidate("valid", ERepairConfidence.LowRisk, 3, 3, 3, 50, 0);
        var failed = Candidate("failed", ERepairConfidence.Equivalent, 3, 3, 3, 5, 0);
        failed.State = ERepairCandidateState.Failed;

        var ranked = new RepairCandidateRanker().Rank([failed, valid]);

        await ranked.Count.Should().BeEqualTo(1);
        await ranked[0].Id.Should().BeEqualTo("valid");
    }

    private static RepairCandidate Candidate(
        string id,
        ERepairConfidence confidence,
        int attempts,
        int successes,
        int consecutive,
        double latencyMs,
        double loss)
    {
        return new RepairCandidate
        {
            Id = id,
            SessionId = "session",
            Profile = new ProfileItem(),
            Mutations =
            [
                new RepairMutation
                {
                    Kind = ERepairMutationKind.ReplaceEndpoint,
                    Field = nameof(ProfileItem.Address),
                    From = "old.example.com",
                    To = "203.0.113.1",
                    Reason = "test",
                    Confidence = confidence,
                }
            ],
            State = ERepairCandidateState.RuntimeValidated,
            Validation = new RepairValidationEvidence
            {
                Attempts = attempts,
                Successes = successes,
                ConsecutiveSuccesses = consecutive,
                MedianLatencyMs = latencyMs,
                LossRate = loss,
            },
        };
    }
}
