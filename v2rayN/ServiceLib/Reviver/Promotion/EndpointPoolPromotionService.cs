using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;
using ServiceLib.Models.Entities;
using ServiceLib.Reviver.Models;
using ServiceLib.Reviver.Normalization;

namespace ServiceLib.Reviver.Promotion;

/// <summary>
/// Explicitly promotes a runtime-validated physical endpoint into PattN's endpoint pool.
/// This service is never invoked automatically by Reviver.
/// </summary>
public sealed class EndpointPoolPromotionService(IEndpointPoolStore pool)
{
    public async Task<EndpointPoolItem> PromoteAsync(
        RepairSession session,
        RepairCandidate candidate,
        bool pinned,
        string? label = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(candidate);
        cancellationToken.ThrowIfCancellationRequested();

        if (!string.Equals(candidate.SessionId, session.Id, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Candidate belongs to a different repair session.");
        }
        if (candidate.State != ERepairCandidateState.RuntimeValidated
            || candidate.Validation is null
            || !candidate.Validation.MeetsQuorum())
        {
            throw new InvalidOperationException("Only runtime-validated endpoint repairs can be promoted to the endpoint pool.");
        }

        var endpointMutation = candidate.Mutations.SingleOrDefault(
            x => x.Kind == ERepairMutationKind.ReplaceEndpoint
                 && x.Field == nameof(ProfileItem.Address));
        if (endpointMutation is null)
        {
            throw new InvalidOperationException("Candidate does not contain an endpoint-address repair.");
        }

        var original = session.Original.CreateWorkingCopy();
        if (!ProfileMutationGuard.ChangesOnly(original, candidate.Profile, nameof(ProfileItem.Address)))
        {
            throw new InvalidOperationException("Endpoint-pool promotion requires an address-only repair candidate.");
        }

        if (!DiscoveryEndpointAddress.TryNormalizeLiteral(candidate.Profile.Address, out var address))
        {
            throw new InvalidOperationException("Only a validated literal-IP endpoint can be promoted to the endpoint pool.");
        }

        var mutationAddress = DiscoveryEndpointAddress.NormalizeIfLiteral(endpointMutation.To);
        if (!string.Equals(mutationAddress, address, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Endpoint mutation evidence does not match the validated candidate address.");
        }

        var logicalHost = ProfileIdentityResolver.ResolveServerName(original);
        var httpHost = ProfileIdentityResolver.ResolveHttpHost(original);
        if (logicalHost.IsNullOrEmpty())
        {
            throw new InvalidOperationException("The original profile has no logical host identity for endpoint-pool scoping.");
        }

        var endpointEvidence = candidate.Evidence.LastOrDefault(x => x.Kind == "discovery.endpoint");
        var request = new DiscoveryCandidateRequest
        {
            OriginalAddress = original.Address,
            OriginalPort = original.Port,
            LogicalHost = logicalHost,
            HttpHost = httpHost,
            Network = original.Network,
            StreamSecurity = original.StreamSecurity,
        };

        var reliability = candidate.Validation.Attempts <= 0
            ? (double?)null
            : Math.Clamp((double)candidate.Validation.Successes / candidate.Validation.Attempts, 0d, 1d);
        var endpoint = new DiscoveryEndpointCandidate
        {
            Address = address,
            Port = original.Port,
            Source = "reviver.validated",
            Provider = EvidenceValue(endpointEvidence, "provider"),
            Asn = EvidenceValue(endpointEvidence, "asn"),
            Pop = EvidenceValue(endpointEvidence, "pop"),
            Reliability = reliability,
            LossRate = candidate.Validation.LossRate,
            LatencyMs = candidate.Validation.MedianLatencyMs,
            ObservedAt = DateTimeOffset.UtcNow,
            Metadata = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["reviverSessionId"] = session.Id,
                ["reviverCandidateId"] = candidate.Id,
                ["runtimeValidated"] = "true",
            },
        };

        return await pool.UpsertAsync(
            request,
            endpoint,
            pinned,
            label.NullIfEmpty() ?? $"{logicalHost} validated endpoint",
            cancellationToken);
    }

    private static string? EvidenceValue(RepairEvidence? evidence, string key)
        => evidence is not null
           && evidence.Data.TryGetValue(key, out var value)
           && !value.IsNullOrEmpty()
            ? value
            : null;
}
