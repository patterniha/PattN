using ServiceLib.Discovery.Models;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Adapts an injected provider/ASN endpoint catalog into Discovery candidates.
/// It consumes only pre-enumerated literal IPs and never expands CIDRs or scans address space.
/// Catalog audit metadata is advisory evidence only and never bypasses current probing/Reviver validation.
/// </summary>
public sealed class ProviderAsnCandidateSource : IDiscoveryCandidateSource
{
    private readonly IProviderAsnEndpointCatalog _catalog;
    private readonly int _maxCandidates;
    private readonly ProviderAsnCatalogAudit? _audit;

    public ProviderAsnCandidateSource(
        IProviderAsnEndpointCatalog catalog,
        int maxCandidates = 32,
        ProviderAsnCatalogAudit? audit = null)
    {
        _catalog = catalog ?? throw new ArgumentNullException(nameof(catalog));
        _maxCandidates = maxCandidates;
        _audit = audit;
    }

    public async IAsyncEnumerable<DiscoveryEndpointCandidate> GetCandidatesAsync(
        DiscoveryCandidateRequest request,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var budget = Math.Min(Math.Max(1, _maxCandidates), Math.Max(1, request.MaxCandidates * 2));
        var entries = await _catalog.ListAsync(request, budget, cancellationToken);
        var accepted = 0;

        foreach (var entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!entry.Enabled || accepted >= budget)
            {
                continue;
            }

            if (!DiscoveryEndpointAddress.TryNormalizeLiteral(entry.Address, out var address))
            {
                continue;
            }
            if (entry.Port is not null && entry.Port != request.OriginalPort)
            {
                continue;
            }
            if (!ScopeMatches(entry, request))
            {
                continue;
            }

            var metadata = entry.Metadata is null
                ? new Dictionary<string, string>(StringComparer.Ordinal)
                : new Dictionary<string, string>(entry.Metadata, StringComparer.Ordinal);
            metadata["catalogSourceId"] = entry.SourceId ?? string.Empty;
            if (!entry.Provider.IsNullOrEmpty())
            {
                metadata["provider"] = entry.Provider;
            }
            if (!entry.Asn.IsNullOrEmpty())
            {
                metadata["asn"] = entry.Asn;
            }
            if (!entry.Pop.IsNullOrEmpty())
            {
                metadata["pop"] = entry.Pop;
            }
            AddAuditMetadata(metadata, _audit);

            yield return new DiscoveryEndpointCandidate
            {
                Address = address,
                Port = request.OriginalPort,
                Source = "catalog.provider-asn",
                Provider = entry.Provider.NullIfEmpty(),
                Asn = entry.Asn.NullIfEmpty(),
                Pop = entry.Pop.NullIfEmpty(),
                ObservedAt = entry.ObservedAt ?? DateTimeOffset.UtcNow,
                Metadata = metadata,
            };
            accepted++;
        }
    }

    private static void AddAuditMetadata(
        IDictionary<string, string> metadata,
        ProviderAsnCatalogAudit? audit)
    {
        if (audit is null)
        {
            return;
        }

        metadata["catalogAuditValid"] = audit.Valid ? "true" : "false";
        metadata["catalogFreshnessKnown"] = audit.FreshnessKnown ? "true" : "false";
        metadata["catalogStale"] = audit.Stale ? "true" : "false";
        metadata["catalogAuditedAt"] = audit.AuditedAt.ToString("O");
        metadata["catalogDuplicateSourceIdGroups"] = audit.DuplicateSourceIdGroups.ToString();
        metadata["catalogExactDuplicateGroups"] = audit.ExactDuplicateGroups.ToString();
        metadata["catalogBroadScopeEntries"] = audit.BroadScopeEntries.ToString();
        if (audit.AgeDays is not null)
        {
            metadata["catalogAgeDays"] = audit.AgeDays.Value.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture);
        }
        if (audit.Warnings.Count > 0)
        {
            metadata["catalogAuditWarnings"] = string.Join(",", audit.Warnings);
        }
        if (audit.Errors.Count > 0)
        {
            metadata["catalogAuditErrors"] = string.Join(",", audit.Errors);
        }
    }

    private static bool ScopeMatches(
        ProviderAsnEndpointCatalogEntry entry,
        DiscoveryCandidateRequest request)
    {
        var host = NormalizeHost(request.LogicalHost);
        if (entry.LogicalHosts is { Count: > 0 }
            && !entry.LogicalHosts.Select(NormalizeHost).Contains(host, StringComparer.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!entry.Network.IsNullOrEmpty()
            && !entry.Network.Trim().Equals(request.Network?.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!entry.StreamSecurity.IsNullOrEmpty()
            && !entry.StreamSecurity.Trim().Equals(request.StreamSecurity?.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return true;
    }

    private static string NormalizeHost(string? value)
        => (value ?? string.Empty).Trim().Trim('[', ']').TrimEnd('.').ToLowerInvariant();
}
