using ServiceLib.Reviver.Models;

namespace ServiceLib.Reviver.Services;

public sealed record EndpointPreflightResult
{
    public bool Applicable { get; init; }
    public bool Reachable { get; init; }
    public ERepairFailureClass FailureClass { get; init; } = ERepairFailureClass.Unknown;
    public IReadOnlyList<string> ResolvedAddresses { get; init; } = [];
    public IReadOnlyList<RepairEvidence> Evidence { get; init; } = [];
}

public interface IReviverEndpointPreflight
{
    Task<EndpointPreflightResult> CheckAsync(ProfileItem profile, CancellationToken cancellationToken = default);
}
