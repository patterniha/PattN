using ServiceLib.Discovery.Models;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Aggregates explicitly enabled registry resources into the existing provider/ASN catalog contract.
/// It performs no refresh or network activity. On-disk drift is rejected by the registry service before use.
/// </summary>
public sealed class RegistryProviderAsnEndpointCatalog(
    ProviderAsnCatalogRegistryService registry) : IProviderAsnEndpointCatalog
{
    public async Task<IReadOnlyList<ProviderAsnEndpointCatalogEntry>> ListAsync(
        DiscoveryCandidateRequest request,
        int maxItems,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (maxItems is < 1 or > 1000)
        {
            throw new ArgumentOutOfRangeException(nameof(maxItems));
        }

        var catalogs = await registry.LoadEnabledCatalogsAsync(cancellationToken);
        var result = new List<ProviderAsnEndpointCatalogEntry>(Math.Min(maxItems, 64));
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var catalog in catalogs)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var remaining = maxItems - result.Count;
            if (remaining <= 0)
            {
                break;
            }

            var audit = catalog.Audit();
            var values = await catalog.ListAsync(request, remaining, cancellationToken);
            foreach (var value in values)
            {
                var key = CandidateKey(value);
                if (!seen.Add(key))
                {
                    continue;
                }

                var metadata = value.Metadata is null
                    ? new Dictionary<string, string>(StringComparer.Ordinal)
                    : new Dictionary<string, string>(value.Metadata, StringComparer.Ordinal);
                AddAuditMetadata(metadata, audit);
                result.Add(value with { Metadata = metadata });
                if (result.Count >= maxItems)
                {
                    break;
                }
            }
        }

        return result;
    }

    private static void AddAuditMetadata(
        IDictionary<string, string> metadata,
        ProviderAsnCatalogAudit audit)
    {
        metadata["catalogAuditValid"] = audit.Valid ? "true" : "false";
        metadata["catalogFreshnessKnown"] = audit.FreshnessKnown ? "true" : "false";
        metadata["catalogStale"] = audit.Stale ? "true" : "false";
        metadata["catalogAuditedAt"] = audit.AuditedAt.ToString("O");
        metadata["catalogDuplicateSourceIdGroups"] = audit.DuplicateSourceIdGroups.ToString(System.Globalization.CultureInfo.InvariantCulture);
        metadata["catalogExactDuplicateGroups"] = audit.ExactDuplicateGroups.ToString(System.Globalization.CultureInfo.InvariantCulture);
        metadata["catalogBroadScopeEntries"] = audit.BroadScopeEntries.ToString(System.Globalization.CultureInfo.InvariantCulture);
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

    private static string CandidateKey(ProviderAsnEndpointCatalogEntry value)
        => string.Join(
            "|",
            value.Address.Trim().Trim('[', ']'),
            value.Port?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty,
            value.Network?.Trim().ToLowerInvariant() ?? string.Empty,
            value.StreamSecurity?.Trim().ToLowerInvariant() ?? string.Empty);
}
