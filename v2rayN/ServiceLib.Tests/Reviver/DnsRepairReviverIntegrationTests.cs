using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;
using ServiceLib.Reviver.Models;
using ServiceLib.Reviver.Normalization;
using ServiceLib.Reviver.Services;
using ServiceLib.Reviver.Strategies;
using ServiceLib.Reviver.Validation;

namespace ServiceLib.Tests.Reviver;

public class DnsRepairReviverIntegrationTests
{
    [Test]
    public async Task Revive_ShouldPlanValidateAndRecommendAddressFamilyRepair()
    {
        var profile = new ProfileItem
        {
            ConfigType = EConfigType.VLESS,
            CoreType = ECoreType.Xray,
            Address = "proxy.example",
            Port = 443,
            Password = Guid.NewGuid().ToString(),
            Network = nameof(ETransport.ws),
            StreamSecurity = Global.StreamSecurity,
        };

        var dnsEvidence = new StubDnsEvidenceProvider(new DnsRepairObservation
        {
            Host = "proxy.example",
            IPv4 = new DnsFamilyObservation
            {
                Family = "ipv4",
                Addresses = ["203.0.113.7"],
                TraceComplete = true,
                DnssecAuthenticated = true,
                DnssecStatus = "root-anchored-authenticated-answer",
            },
            IPv6 = new DnsFamilyObservation
            {
                Family = "ipv6",
                TraceComplete = true,
                DnssecStatus = "unsigned",
            },
        });
        var strategies = ReviverStrategyCatalog.CreateDefault(
            new EmptyCandidateProvider(),
            dnsEvidence,
            new ProfileCoreCompatibility());
        var reviver = new ReviverService(
            new ProfileNormalizer(),
            new ProfileInvariantRegistry(),
            strategies);

        var result = await reviver.ReviveAsync(
            profile,
            new StubDiagnostic(),
            new SuccessfulValidator());

        await result.Diagnosis.FailureClass.Should().BeEqualTo(ERepairFailureClass.DnsResolutionFailure);
        await result.Session.BaselineValidation.Should().NotBeNull();
        await result.Session.BaselineValidation!.Successes.Should().BeEqualTo(1);
        await result.PlannedCandidates.Count.Should().BeEqualTo(1);
        await result.ValidatedCandidates.Count.Should().BeEqualTo(1);
        await result.RecommendedCandidate.Should().NotBeNull();
        await result.RecommendedCandidate!.Profile.TargetStrategy.Should().BeEqualTo("UseIPv4");
        await result.RecommendedCandidate.State.Should().BeEqualTo(ERepairCandidateState.RuntimeValidated);
        await result.RecommendedCandidate.Validation!.MeetsQuorum().Should().BeTrue();
        await result.RecommendedCandidate.Evidence.Any(x => x.Kind == "discovery.dns.address-family").Should().BeTrue();
    }

    private sealed class StubDiagnostic : IRepairBaselineDiagnostic
    {
        public Task<RepairDiagnosis> DiagnoseAsync(RepairSession session, CancellationToken cancellationToken = default)
            => Task.FromResult(new RepairDiagnosis
            {
                FailureClass = ERepairFailureClass.DnsResolutionFailure,
                RuntimeValidation = new RepairValidationEvidence
                {
                    Attempts = 3,
                    Successes = 1,
                    ConsecutiveSuccesses = 1,
                    MedianLatencyMs = 120,
                    LossRate = 2d / 3d,
                },
                Evidence =
                [
                    new RepairEvidence
                    {
                        Kind = "baseline.dns",
                        Summary = "Endpoint hostname failed baseline resolution.",
                    }
                ],
            });
    }

    private sealed class SuccessfulValidator : IRepairCandidateValidator
    {
        public Task<RepairValidationEvidence> ValidateAsync(
            RepairCandidate candidate,
            CancellationToken cancellationToken = default)
            => Task.FromResult(new RepairValidationEvidence
            {
                Attempts = 3,
                Successes = 3,
                ConsecutiveSuccesses = 3,
                MedianLatencyMs = 45,
                LossRate = 0,
            });
    }

    private sealed class StubDnsEvidenceProvider(DnsRepairObservation observation) : IDnsRepairEvidenceProvider
    {
        public Task<DnsRepairObservation> InspectAsync(string host, CancellationToken cancellationToken = default)
            => Task.FromResult(observation);
    }

    private sealed class EmptyCandidateProvider : IDiscoveryCandidateProvider
    {
        public async IAsyncEnumerable<DiscoveryEndpointCandidate> GetCandidatesAsync(
            DiscoveryCandidateRequest request,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            yield break;
        }
    }
}
