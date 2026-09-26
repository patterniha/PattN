using ServiceLib.Discovery.Models;
using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Read-only search over revision-linked remote apply provenance. No fetch, source mutation, catalog update,
/// rollback, retention, or archive operation occurs through this service.
/// </summary>
public sealed class ProviderAsnCatalogRemoteProvenanceQueryService
{
    private const int MaximumScanItems = 5000;

    public async Task<ProviderAsnCatalogRemoteProvenanceSummary> QueryAsync(
        ProviderAsnCatalogRemoteProvenanceQuery? query = null,
        CancellationToken cancellationToken = default)
    {
        query ??= new ProviderAsnCatalogRemoteProvenanceQuery();
        Validate(query);
        cancellationToken.ThrowIfCancellationRequested();

        var cutoff = DateTimeOffset.UtcNow.Subtract(query.MaxAge).ToUnixTimeMilliseconds();
        var rows = await SQLiteHelper.Instance.TableAsync<ProviderAsnCatalogRemoteApplyProvenanceItem>()
            .Where(x => x.AppliedAtUnixMs >= cutoff)
            .OrderByDescending(x => x.AppliedAtUnixMs)
            .Take(MaximumScanItems)
            .ToListAsync();

        return FilterAndSummarize(rows, query);
    }

    public static ProviderAsnCatalogRemoteProvenanceSummary FilterAndSummarize(
        IReadOnlyList<ProviderAsnCatalogRemoteApplyProvenanceItem> rows,
        ProviderAsnCatalogRemoteProvenanceQuery query)
    {
        ArgumentNullException.ThrowIfNull(rows);
        ArgumentNullException.ThrowIfNull(query);
        Validate(query);

        return Summarize(
            rows.Where(x => Match(query, x))
                .OrderByDescending(x => x.AppliedAtUnixMs)
                .Take(query.MaxItems)
                .ToArray());
    }

    public static ProviderAsnCatalogRemoteProvenanceSummary Summarize(
        IReadOnlyList<ProviderAsnCatalogRemoteApplyProvenanceItem> rows)
    {
        ArgumentNullException.ThrowIfNull(rows);
        var entries = rows
            .OrderByDescending(x => x.AppliedAtUnixMs)
            .Select(ProviderAsnCatalogRemoteProvenanceProjector.Project)
            .ToArray();

        return new ProviderAsnCatalogRemoteProvenanceSummary
        {
            Total = entries.Length,
            SignatureAttempted = entries.Count(x => x.SignatureValidation?.Attempted == true),
            SignatureValid = entries.Count(x => x.SignatureValidation?.Valid == true),
            SignaturePolicySatisfied = entries.Count(x => x.SignatureValidation?.PolicySatisfied == true),
            TransportPinned = entries.Count(x => x.TlsSpkiPinsSha256.Count > 0),
            ServerNotModified = entries.Count(x => x.ServerNotModified),
            LatestAppliedAt = entries.Length == 0 ? null : entries[0].AppliedAt,
            Entries = entries,
        };
    }

    private static bool Match(
        ProviderAsnCatalogRemoteProvenanceQuery query,
        ProviderAsnCatalogRemoteApplyProvenanceItem row)
    {
        if (!query.RegistryId.IsNullOrEmpty()
            && !string.Equals(row.RegistryId, query.RegistryId, StringComparison.Ordinal))
        {
            return false;
        }
        if (!query.RevisionId.IsNullOrEmpty()
            && !string.Equals(row.RevisionId, query.RevisionId, StringComparison.Ordinal))
        {
            return false;
        }
        if (!query.TrustedKeyId.IsNullOrEmpty()
            && !string.Equals(row.TrustedKeyId, query.TrustedKeyId, StringComparison.Ordinal))
        {
            return false;
        }
        var pinFilter = query.TlsSpkiPinSha256?.Trim();
        if (!pinFilter.IsNullOrEmpty())
        {
            var normalized = ProviderAsnCatalogTransportPinning.NormalizePins([pinFilter]);
            var pin = normalized[0];
            var rowPins = ProviderAsnCatalogTransportPinning.DeserializePins(
                row.TlsSpkiPinsSha256Json);
            if (!rowPins.Contains(pin, StringComparer.Ordinal))
            {
                return false;
            }
        }
        if (!query.SignatureStatus.IsNullOrEmpty()
            && !string.Equals(row.SignatureStatus, query.SignatureStatus, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        if (query.SignatureValid is not null && row.SignatureValid != query.SignatureValid.Value)
        {
            return false;
        }
        if (query.SignaturePolicySatisfied is not null
            && row.SignaturePolicySatisfied != query.SignaturePolicySatisfied.Value)
        {
            return false;
        }
        if (!query.SourceHost.IsNullOrEmpty())
        {
            if (!Uri.TryCreate(row.SourceUri, UriKind.Absolute, out var uri)
                || !string.Equals(uri.Host, query.SourceHost.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }
        return true;
    }

    private static void Validate(ProviderAsnCatalogRemoteProvenanceQuery query)
    {
        if (query.MaxAge <= TimeSpan.Zero || query.MaxAge > TimeSpan.FromDays(3650))
        {
            throw new ArgumentOutOfRangeException(nameof(query.MaxAge), "Remote provenance age must be greater than zero and no more than 10 years.");
        }
        if (query.MaxItems is < 1 or > 1000)
        {
            throw new ArgumentOutOfRangeException(nameof(query.MaxItems), "Remote provenance item limit must be between 1 and 1000.");
        }
        var pinFilter = query.TlsSpkiPinSha256?.Trim();
        if (!pinFilter.IsNullOrEmpty())
        {
            var normalized = ProviderAsnCatalogTransportPinning.NormalizePins([pinFilter]);
            if (normalized.Count != 1)
            {
                throw new ArgumentException(
                    "Remote provenance TLS SPKI pin filter must contain exactly one SHA-256 pin.",
                    nameof(query.TlsSpkiPinSha256));
            }
        }
        if (!query.SourceHost.IsNullOrEmpty())
        {
            var host = query.SourceHost.Trim();
            if (host.Contains("://", StringComparison.Ordinal)
                || host.Contains('/', StringComparison.Ordinal)
                || host.Contains('@', StringComparison.Ordinal)
                || host.Contains('#', StringComparison.Ordinal)
                || host.Contains('?', StringComparison.Ordinal))
            {
                throw new ArgumentException("Remote provenance source host must be a hostname only.", nameof(query.SourceHost));
            }
        }
    }
}
