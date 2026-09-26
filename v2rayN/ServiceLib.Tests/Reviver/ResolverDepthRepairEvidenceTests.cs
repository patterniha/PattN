using ServiceLib.Discovery.Protocol;
using ServiceLib.Reviver.Models;
using ServiceLib.Reviver.Ranking;
using ServiceLib.Reviver.Services;

namespace ServiceLib.Tests.Reviver;

public class ResolverDepthRepairEvidenceTests
{
    [Test]
    public async Task Create_ShouldPreserveExplainableResolverDepthEvidence()
    {
        var profile = new DiscoveryResolverProfileResult
        {
            Quality = "strong",
            Status = "usable",
            ReliabilityFloor = 1,
            QuorumTransportCount = 4,
            EdnsCompatible = true,
            EncryptedDnsAvailable = true,
            ClassicEncryptedAgree = true,
            Dot = new DiscoveryResolverProfileProbe
            {
                Attempts = 3,
                Successes = 3,
                QuorumMet = true,
                Reliability = 1,
                MedianLatencyMs = 32,
                Alpn = "dot",
            },
            Doh = new DiscoveryResolverProfileProbe
            {
                Attempts = 3,
                Successes = 3,
                QuorumMet = true,
                Reliability = 1,
                MedianLatencyMs = 28,
                Alpn = "h2",
                HttpVersion = "HTTP/2.0",
            },
        };

        var evidence = ResolverDepthRepairEvidence.Create(profile);

        await evidence.Kind.Should().BeEqualTo(ResolverDepthRepairEvidence.EvidenceKind);
        await evidence.Data["quality"].Should().BeEqualTo("strong");
        await evidence.Data["dot.quorumMet"].Should().BeEqualTo("true");
        await evidence.Data["doh.alpn"].Should().BeEqualTo("h2");
        await evidence.Data["doh.httpVersion"].Should().BeEqualTo("HTTP/2.0");
    }

    [Test]
    public async Task Rank_ShouldUseResolverDepthAsSmallTieBreakerAfterRuntimeValidation()
    {
        var strong = Candidate("strong", ResolverDepthRepairEvidence.Create(new DiscoveryResolverProfileResult
        {
            Quality = "strong",
            ReliabilityFloor = 1,
            QuorumTransportCount = 4,
            EncryptedDnsAvailable = true,
        }));
        var suspicious = Candidate("suspicious", ResolverDepthRepairEvidence.Create(new DiscoveryResolverProfileResult
        {
            Quality = "suspicious",
            ReliabilityFloor = 1,
            QuorumTransportCount = 4,
            InterceptionSuspected = true,
            InterceptionReasons = ["classic-encrypted-answer-divergence"],
        }));

        var ranked = new RepairCandidateRanker().Rank([suspicious, strong]);

        await ranked[0].Id.Should().BeEqualTo("strong");
        await ranked[0].ScoreBreakdown!.ResolverQuality.Should().BeGreaterThan(ranked[1].ScoreBreakdown!.ResolverQuality);
        await ranked[0].Score.HasValue.Should().BeTrue();
        await ranked[1].Score.HasValue.Should().BeTrue();
        await ranked[0].Score.GetValueOrDefault().Should().BeGreaterThan(ranked[1].Score.GetValueOrDefault());
    }

    [Test]
    public async Task Rank_ShouldTreatMissingResolverDepthAsNeutral()
    {
        var candidate = Candidate("neutral", null);
        var score = new RepairCandidateRanker().Score(candidate);
        await score.ResolverQuality.Should().BeEqualTo(0.5);
    }

    private static RepairCandidate Candidate(string id, RepairEvidence? evidence)
        => new()
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
                    Confidence = ERepairConfidence.LowRisk,
                }
            ],
            Evidence = evidence is null ? [] : [evidence],
            State = ERepairCandidateState.RuntimeValidated,
            Validation = new RepairValidationEvidence
            {
                Attempts = 3,
                Successes = 3,
                ConsecutiveSuccesses = 3,
                MedianLatencyMs = 50,
                LossRate = 0,
            },
        };
}
