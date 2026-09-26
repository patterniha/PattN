using ServiceLib.Reviver.Models;
using ServiceLib.Reviver.Normalization;

namespace ServiceLib.Reviver.Strategies;

/// <summary>
/// Tries the same canonical remote profile through another PattN-supported local core. This is a low-risk repair:
/// endpoint, credentials, TLS identity and transport semantics remain unchanged.
/// </summary>
public sealed class CoreFallbackStrategy(ProfileCoreCompatibility compatibility) : IRepairStrategy
{
    public string Id => "core-fallback";
    public ERepairConfidence Confidence => ERepairConfidence.LowRisk;

    public int PriorityFor(ERepairFailureClass failureClass) => failureClass switch
    {
        ERepairFailureClass.CoreUnsupported => 0,
        ERepairFailureClass.CoreConfigurationInvalid => 1,
        ERepairFailureClass.CoreStartupFailure => 2,
        ERepairFailureClass.ProtocolFailure => 20,
        _ => 1000,
    };

    public bool CanApply(ProfileItem profile, ERepairFailureClass failureClass)
    {
        var current = profile.CoreType ?? ECoreType.Xray;
        return PriorityFor(failureClass) < 1000 && compatibility.Alternatives(profile, current).Count > 0;
    }

    public async IAsyncEnumerable<RepairCandidate> GenerateAsync(
        RepairSession session,
        ERepairFailureClass failureClass,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var baseline = session.Original.CreateWorkingCopy();
        var current = baseline.CoreType ?? ECoreType.Xray;
        foreach (var core in compatibility.Alternatives(baseline, current))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var candidate = session.Original.CreateWorkingCopy();
            candidate.CoreType = core;
            if (!ProfileMutationGuard.ChangesOnly(baseline, candidate, nameof(ProfileItem.CoreType)))
            {
                throw new InvalidOperationException("Core fallback modified fields outside CoreType.");
            }

            yield return new RepairCandidate
            {
                SessionId = session.Id,
                Profile = candidate,
                FailureClassAddressed = failureClass,
                Mutations =
                [
                    new RepairMutation
                    {
                        Kind = ERepairMutationKind.ChangeCore,
                        Field = nameof(ProfileItem.CoreType),
                        From = current.ToString(),
                        To = core.ToString(),
                        Reason = "The remote profile is preserved while PattN validates it through another compatible local core.",
                        Confidence = ERepairConfidence.LowRisk,
                    }
                ],
                Evidence =
                [
                    new RepairEvidence
                    {
                        Kind = "pattn.core-capability",
                        Summary = $"PattN has a structured {core} generator for this profile shape.",
                        Source = "ProfileCoreCompatibility",
                    }
                ],
            };
            await Task.Yield();
        }
    }
}
