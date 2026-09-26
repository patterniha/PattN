using ServiceLib.Reviver.Models;
using ServiceLib.Reviver.Normalization;
using ServiceLib.Reviver.Services;
using ServiceLib.Reviver.Validation;

namespace ServiceLib.Tests.Reviver;

public class RepairBaselineDiagnosticTests
{
    [Test]
    public async Task Diagnose_ShouldStopAtStaticInvariantFailure()
    {
        var profile = BaseProfile();
        profile.Address = string.Empty;
        var session = new RepairSession { Original = ProfileSnapshot.Capture(profile) };
        var diagnostic = CreateDiagnostic(new ThrowingPreflight(), new ThrowingValidator());

        var result = await diagnostic.DiagnoseAsync(session);

        await result.FailureClass.Should().BeEqualTo(ERepairFailureClass.ProfileSemanticallyInvalid);
        await result.InvariantViolations.Any(x => x.Code == "endpoint.address.empty").Should().BeTrue();
    }

    [Test]
    public async Task Diagnose_ShouldPreserveEndpointFailureInsteadOfMaskingItAsCoreFailure()
    {
        var profile = BaseProfile();
        var session = new RepairSession { Original = ProfileSnapshot.Capture(profile) };
        var diagnostic = CreateDiagnostic(
            new StubPreflight(new EndpointPreflightResult
            {
                Applicable = true,
                Reachable = false,
                FailureClass = ERepairFailureClass.ConnectionTimeout,
                ResolvedAddresses = ["203.0.113.10"],
            }),
            new ThrowingValidator());

        var result = await diagnostic.DiagnoseAsync(session);

        await result.FailureClass.Should().BeEqualTo(ERepairFailureClass.ConnectionTimeout);
        await result.ResolvedAddresses.Single().Should().BeEqualTo("203.0.113.10");
    }

    [Test]
    public async Task Diagnose_ShouldMarkBaselineHealthyOnlyAfterRuntimeQuorum()
    {
        var profile = BaseProfile();
        var session = new RepairSession { Original = ProfileSnapshot.Capture(profile) };
        var diagnostic = CreateDiagnostic(
            new StubPreflight(new EndpointPreflightResult { Applicable = true, Reachable = true, ResolvedAddresses = ["203.0.113.10"] }),
            new StubValidator(new RepairValidationEvidence { Attempts = 3, Successes = 2, ConsecutiveSuccesses = 2 }));

        var result = await diagnostic.DiagnoseAsync(session);

        await result.IsHealthy.Should().BeTrue();
        await result.FailureClass.Should().BeEqualTo(ERepairFailureClass.Unknown);
    }

    private static RepairBaselineDiagnostic CreateDiagnostic(IReviverEndpointPreflight preflight, IRepairCandidateValidator validator)
        => new(new ProfileInvariantRegistry(), new ProfileCoreCompatibility(), preflight, validator);

    private static ProfileItem BaseProfile()
        => new()
        {
            ConfigType = EConfigType.VLESS,
            CoreType = ECoreType.Xray,
            Address = "example.com",
            Port = 443,
            Password = Guid.NewGuid().ToString(),
            Network = nameof(ETransport.ws),
            StreamSecurity = Global.StreamSecurity,
        };

    private sealed class StubPreflight(EndpointPreflightResult result) : IReviverEndpointPreflight
    {
        public Task<EndpointPreflightResult> CheckAsync(ProfileItem profile, CancellationToken cancellationToken = default)
            => Task.FromResult(result);
    }

    private sealed class ThrowingPreflight : IReviverEndpointPreflight
    {
        public Task<EndpointPreflightResult> CheckAsync(ProfileItem profile, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("Preflight should not be called.");
    }

    private sealed class StubValidator(RepairValidationEvidence evidence) : IRepairCandidateValidator
    {
        public Task<RepairValidationEvidence> ValidateAsync(RepairCandidate candidate, CancellationToken cancellationToken = default)
            => Task.FromResult(evidence);
    }

    private sealed class ThrowingValidator : IRepairCandidateValidator
    {
        public Task<RepairValidationEvidence> ValidateAsync(RepairCandidate candidate, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("Runtime validator should not be called.");
    }
}
