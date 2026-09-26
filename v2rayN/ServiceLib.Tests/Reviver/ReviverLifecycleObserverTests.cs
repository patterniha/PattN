using ServiceLib.Reviver.Models;
using ServiceLib.Reviver.Normalization;
using ServiceLib.Reviver.Services;
using ServiceLib.Reviver.Strategies;
using ServiceLib.Reviver.Validation;

namespace ServiceLib.Tests.Reviver;

public class ReviverLifecycleObserverTests
{
    [Test]
    public async Task Reviver_ShouldNotifyObserverAfterPlanningAndValidation()
    {
        var observer = new CapturingObserver();
        var reviver = new ReviverService(
            new ProfileNormalizer(),
            new ProfileInvariantRegistry(),
            [new SingleCandidateStrategy()],
            observers: [observer]);
        var session = reviver.StartSession(Profile());
        var planned = await reviver.PlanAsync(session, ERepairFailureClass.DnsResolutionFailure);
        var validated = await reviver.ValidateAsync(planned, new SuccessfulValidator());

        await observer.Planned.Count.Should().BeEqualTo(1);
        await observer.Validated.Count.Should().BeEqualTo(1);
        await observer.Validated[0].State.Should().BeEqualTo(ERepairCandidateState.RuntimeValidated);
        await validated.Count.Should().BeEqualTo(1);
    }

    [Test]
    public async Task Reviver_ShouldIgnoreObserverFailureButPropagateCancellation()
    {
        var reviver = new ReviverService(
            new ProfileNormalizer(),
            new ProfileInvariantRegistry(),
            [new SingleCandidateStrategy()],
            observers: [new ThrowingObserver()]);
        var session = reviver.StartSession(Profile());

        var planned = await reviver.PlanAsync(session, ERepairFailureClass.DnsResolutionFailure);
        await planned.Count.Should().BeEqualTo(1);
    }

    private static ProfileItem Profile()
        => new()
        {
            ConfigType = EConfigType.VLESS,
            CoreType = ECoreType.Xray,
            Address = "proxy.example",
            Port = 443,
            Password = Guid.NewGuid().ToString(),
            Network = nameof(ETransport.ws),
            StreamSecurity = Global.StreamSecurity,
        };

    private sealed class SingleCandidateStrategy : IRepairStrategy
    {
        public string Id => "test";
        public ERepairConfidence Confidence => ERepairConfidence.LowRisk;
        public int PriorityFor(ERepairFailureClass failureClass) => 0;
        public bool CanApply(ProfileItem profile, ERepairFailureClass failureClass) => true;

        public async IAsyncEnumerable<RepairCandidate> GenerateAsync(
            RepairSession session,
            ERepairFailureClass failureClass,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var profile = session.Original.CreateWorkingCopy();
            profile.TargetStrategy = "UseIPv4";
            yield return new RepairCandidate
            {
                SessionId = session.Id,
                Profile = profile,
                FailureClassAddressed = failureClass,
                Mutations =
                [
                    new RepairMutation
                    {
                        Kind = ERepairMutationKind.PreferAddressFamily,
                        Field = nameof(ProfileItem.TargetStrategy),
                        From = Global.AsIs,
                        To = "UseIPv4",
                        Reason = "test",
                        Confidence = ERepairConfidence.LowRisk,
                    }
                ],
            };
            await Task.Yield();
        }
    }

    private sealed class SuccessfulValidator : IRepairCandidateValidator
    {
        public Task<RepairValidationEvidence> ValidateAsync(RepairCandidate candidate, CancellationToken cancellationToken = default)
            => Task.FromResult(new RepairValidationEvidence
            {
                Attempts = 3,
                Successes = 3,
                ConsecutiveSuccesses = 3,
            });
    }

    private sealed class CapturingObserver : IRepairLifecycleObserver
    {
        public List<RepairCandidate> Planned { get; } = [];
        public List<RepairCandidate> Validated { get; } = [];

        public Task CandidatePlannedAsync(RepairCandidate candidate, CancellationToken cancellationToken = default)
        {
            Planned.Add(candidate);
            return Task.CompletedTask;
        }

        public Task CandidateValidatedAsync(RepairCandidate candidate, CancellationToken cancellationToken = default)
        {
            Validated.Add(candidate);
            return Task.CompletedTask;
        }
    }

    private sealed class ThrowingObserver : IRepairLifecycleObserver
    {
        public Task CandidatePlannedAsync(RepairCandidate candidate, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("observer failure");

        public Task CandidateValidatedAsync(RepairCandidate candidate, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("observer failure");
    }
}
