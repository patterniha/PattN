using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;
using ServiceLib.Models.Entities;
using ServiceLib.Reviver.Models;
using ServiceLib.Reviver.Promotion;

namespace ServiceLib.Tests.Reviver;

public class EndpointPoolPromotionServiceTests
{
    [Test]
    public async Task Promote_ShouldScopeValidatedEndpointToOriginalLogicalIdentity()
    {
        var original = new ProfileItem
        {
            IndexId = "original",
            ConfigType = EConfigType.VLESS,
            CoreType = ECoreType.Xray,
            Address = "origin.example",
            Port = 443,
            Network = nameof(ETransport.ws),
            StreamSecurity = Global.StreamSecurityReality,
            Sni = "front.example",
        };
        original.SetProtocolExtra(new ProtocolExtraItem { VlessEncryption = Global.None });
        original.SetTransportExtra(new TransportExtraItem { Host = "host.example" });

        var session = new RepairSession
        {
            Id = "session",
            Original = ProfileSnapshot.Capture(original),
        };
        var candidate = new RepairCandidate
        {
            Id = "candidate",
            SessionId = session.Id,
            Profile = JsonUtils.DeepCopy(original)!,
            Mutations =
            [
                new RepairMutation
                {
                    Kind = ERepairMutationKind.ReplaceEndpoint,
                    Field = nameof(ProfileItem.Address),
                    From = "origin.example",
                    To = "203.0.113.10",
                    Reason = "test",
                    Confidence = ERepairConfidence.EvidenceBacked,
                }
            ],
            State = ERepairCandidateState.RuntimeValidated,
            Validation = new RepairValidationEvidence
            {
                Attempts = 3,
                Successes = 3,
                ConsecutiveSuccesses = 3,
                MedianLatencyMs = 42,
                LossRate = 0,
            },
            Evidence =
            [
                new RepairEvidence
                {
                    Kind = "discovery.endpoint",
                    Summary = "test",
                    Data = new Dictionary<string, string>
                    {
                        ["provider"] = "cloudflare",
                        ["pop"] = "FRA",
                    },
                }
            ],
        };
        candidate.Profile.Address = "203.0.113.10";

        var pool = new CapturingPoolStore();
        var service = new EndpointPoolPromotionService(pool);

        var item = await service.PromoteAsync(session, candidate, pinned: true, label: "known-good");

        await pool.Request.Should().NotBeNull();
        await pool.Request!.LogicalHost.Should().BeEqualTo("front.example");
        await pool.Request.HttpHost.Should().BeEqualTo("host.example");
        await pool.Request.OriginalPort.Should().BeEqualTo(443);
        await pool.Request.Network.Should().BeEqualTo(nameof(ETransport.ws));
        await pool.Candidate!.Address.Should().BeEqualTo("203.0.113.10");
        await pool.Candidate.Provider.Should().BeEqualTo("cloudflare");
        await pool.Candidate.Pop.Should().BeEqualTo("FRA");
        await pool.Pinned.Should().BeTrue();
        await pool.Label.Should().BeEqualTo("known-good");
        await item.Address.Should().BeEqualTo("203.0.113.10");
    }

    [Test]
    public async Task Promote_ShouldRejectCandidateThatDidNotPassRuntimeValidation()
    {
        var profile = new ProfileItem
        {
            ConfigType = EConfigType.VLESS,
            Address = "origin.example",
            Port = 443,
            Sni = "front.example",
        };
        var session = new RepairSession { Id = "session", Original = ProfileSnapshot.Capture(profile) };
        var candidate = new RepairCandidate
        {
            SessionId = session.Id,
            Profile = JsonUtils.DeepCopy(profile)!,
            Mutations =
            [
                new RepairMutation
                {
                    Kind = ERepairMutationKind.ReplaceEndpoint,
                    Field = nameof(ProfileItem.Address),
                    From = "origin.example",
                    To = "203.0.113.10",
                    Reason = "test",
                    Confidence = ERepairConfidence.EvidenceBacked,
                }
            ],
            State = ERepairCandidateState.StaticValidated,
        };
        candidate.Profile.Address = "203.0.113.10";

        var threw = false;
        try
        {
            await new EndpointPoolPromotionService(new CapturingPoolStore())
                .PromoteAsync(session, candidate, pinned: false);
        }
        catch (InvalidOperationException)
        {
            threw = true;
        }

        await threw.Should().BeTrue();
    }


    [Test]
    public async Task Promote_ShouldRejectCandidateThatChangesMoreThanPhysicalAddress()
    {
        var original = new ProfileItem
        {
            ConfigType = EConfigType.VLESS,
            CoreType = ECoreType.Xray,
            Address = "origin.example",
            Port = 443,
            Network = nameof(ETransport.ws),
            Sni = "front.example",
        };
        original.SetProtocolExtra(new ProtocolExtraItem { VlessEncryption = Global.None });
        original.SetTransportExtra(new TransportExtraItem());

        var session = new RepairSession { Id = "session", Original = ProfileSnapshot.Capture(original) };
        var profile = JsonUtils.DeepCopy(original)!;
        profile.Address = "203.0.113.10";
        profile.Network = nameof(ETransport.grpc);
        var candidate = new RepairCandidate
        {
            SessionId = session.Id,
            Profile = profile,
            Mutations =
            [
                new RepairMutation
                {
                    Kind = ERepairMutationKind.ReplaceEndpoint,
                    Field = nameof(ProfileItem.Address),
                    From = original.Address,
                    To = profile.Address,
                    Reason = "test",
                    Confidence = ERepairConfidence.EvidenceBacked,
                }
            ],
            State = ERepairCandidateState.RuntimeValidated,
            Validation = new RepairValidationEvidence { Attempts = 3, Successes = 3, ConsecutiveSuccesses = 3 },
        };

        var threw = false;
        try
        {
            await new EndpointPoolPromotionService(new CapturingPoolStore())
                .PromoteAsync(session, candidate, pinned: false);
        }
        catch (InvalidOperationException)
        {
            threw = true;
        }

        await threw.Should().BeTrue();
    }

    [Test]
    public async Task Promote_ShouldRejectMutationEvidenceThatDoesNotMatchValidatedAddress()
    {
        var original = new ProfileItem
        {
            ConfigType = EConfigType.VLESS,
            CoreType = ECoreType.Xray,
            Address = "origin.example",
            Port = 443,
            Network = nameof(ETransport.ws),
            Sni = "front.example",
        };
        original.SetProtocolExtra(new ProtocolExtraItem { VlessEncryption = Global.None });
        original.SetTransportExtra(new TransportExtraItem());

        var session = new RepairSession { Id = "session", Original = ProfileSnapshot.Capture(original) };
        var profile = JsonUtils.DeepCopy(original)!;
        profile.Address = "203.0.113.10";
        var candidate = new RepairCandidate
        {
            SessionId = session.Id,
            Profile = profile,
            Mutations =
            [
                new RepairMutation
                {
                    Kind = ERepairMutationKind.ReplaceEndpoint,
                    Field = nameof(ProfileItem.Address),
                    From = original.Address,
                    To = "203.0.113.99",
                    Reason = "mismatched evidence",
                    Confidence = ERepairConfidence.EvidenceBacked,
                }
            ],
            State = ERepairCandidateState.RuntimeValidated,
            Validation = new RepairValidationEvidence { Attempts = 3, Successes = 3, ConsecutiveSuccesses = 3 },
        };

        var threw = false;
        try
        {
            await new EndpointPoolPromotionService(new CapturingPoolStore())
                .PromoteAsync(session, candidate, pinned: false);
        }
        catch (InvalidOperationException)
        {
            threw = true;
        }

        await threw.Should().BeTrue();
    }

    private sealed class CapturingPoolStore : IEndpointPoolStore
    {
        public DiscoveryCandidateRequest? Request { get; private set; }
        public DiscoveryEndpointCandidate? Candidate { get; private set; }
        public bool Pinned { get; private set; }
        public string? Label { get; private set; }

        public Task<IReadOnlyList<DiscoveryEndpointCandidate>> GetCandidatesAsync(
            DiscoveryCandidateRequest request,
            int maxCandidates,
            CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<DiscoveryEndpointCandidate>>([]);

        public Task<EndpointPoolItem> UpsertAsync(
            DiscoveryCandidateRequest request,
            DiscoveryEndpointCandidate candidate,
            bool pinned = false,
            string? label = null,
            CancellationToken cancellationToken = default)
        {
            Request = request;
            Candidate = candidate;
            Pinned = pinned;
            Label = label;
            return Task.FromResult(new EndpointPoolItem
            {
                Id = "pool",
                LogicalHost = request.LogicalHost ?? string.Empty,
                HttpHost = request.HttpHost ?? string.Empty,
                Port = request.OriginalPort,
                Address = candidate.Address,
                Pinned = pinned,
                Label = label ?? string.Empty,
            });
        }

        public Task RemoveAsync(string id, CancellationToken cancellationToken = default)
            => Task.CompletedTask;
    }
}
