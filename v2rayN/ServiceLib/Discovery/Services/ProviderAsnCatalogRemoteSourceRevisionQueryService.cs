using ServiceLib.Discovery.Models;
using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

public sealed class ProviderAsnCatalogRemoteSourceRevisionQueryService(
    IProviderAsnCatalogRemoteSourceRevisionStore store)
{
    public async Task<ProviderAsnCatalogRemoteSourceRevisionSummary> QueryAsync(
        ProviderAsnCatalogRemoteSourceRevisionQuery? query = null,
        CancellationToken cancellationToken = default)
    {
        query ??= new ProviderAsnCatalogRemoteSourceRevisionQuery();
        Validate(query);
        cancellationToken.ThrowIfCancellationRequested();

        var cutoff = DateTimeOffset.UtcNow.Subtract(query.MaxAge).ToUnixTimeMilliseconds();
        var rows = await store.ListAsync(5000, cancellationToken);
        var filtered = rows
            .Where(x => x.ChangedAtUnixMs >= cutoff)
            .Where(x => Match(query, x))
            .OrderByDescending(x => x.ChangedAtUnixMs)
            .Take(query.MaxItems)
            .ToArray();

        return Summarize(filtered);
    }

    public static ProviderAsnCatalogRemoteSourceRevisionSummary Summarize(
        IReadOnlyList<ProviderAsnCatalogRemoteSourceRevisionItem> rows)
    {
        ArgumentNullException.ThrowIfNull(rows);
        var entries = rows
            .OrderByDescending(x => x.ChangedAtUnixMs)
            .Select(ProviderAsnCatalogRemoteSourceRevisionProjector.Project)
            .ToArray();

        return new ProviderAsnCatalogRemoteSourceRevisionSummary
        {
            Total = entries.Length,
            PinChanges = entries.Count(x => x.AddedTlsSpkiPinsSha256.Count > 0 || x.RemovedTlsSpkiPinsSha256.Count > 0),
            SourceUriChanges = entries.Count(x => !string.Equals(x.BeforeUri, x.AfterUri, StringComparison.Ordinal)),
            SignatureTrustChanges = entries.Count(x =>
                x.BeforeSignaturePolicy != x.AfterSignaturePolicy
                || !string.Equals(x.BeforeSignatureUri, x.AfterSignatureUri, StringComparison.Ordinal)
                || !string.Equals(x.BeforeTrustedKeyId, x.AfterTrustedKeyId, StringComparison.Ordinal)
                || !string.Equals(x.BeforeTrustedPublicKeySha256, x.AfterTrustedPublicKeySha256, StringComparison.Ordinal)),
            LatestChangedAt = entries.Length == 0 ? null : entries[0].ChangedAt,
            Entries = entries,
        };
    }

    private static bool Match(
        ProviderAsnCatalogRemoteSourceRevisionQuery query,
        ProviderAsnCatalogRemoteSourceRevisionItem item)
    {
        if (!query.RegistryId.IsNullOrEmpty()
            && !string.Equals(item.RegistryId, query.RegistryId, StringComparison.Ordinal))
        {
            return false;
        }
        if (!query.ChangeReason.IsNullOrEmpty()
            && !string.Equals(item.ChangeReason, query.ChangeReason, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        if (!query.TrustedKeyId.IsNullOrEmpty()
            && !string.Equals(item.BeforeTrustedKeyId, query.TrustedKeyId, StringComparison.Ordinal)
            && !string.Equals(item.AfterTrustedKeyId, query.TrustedKeyId, StringComparison.Ordinal))
        {
            return false;
        }
        if (!query.TlsSpkiPinSha256.IsNullOrEmpty())
        {
            var pin = query.TlsSpkiPinSha256.Trim().ToLowerInvariant();
            var before = SafePins(item.BeforeTlsSpkiPinsSha256Json);
            var after = SafePins(item.AfterTlsSpkiPinsSha256Json);
            if (!before.Contains(pin, StringComparer.Ordinal)
                && !after.Contains(pin, StringComparer.Ordinal))
            {
                return false;
            }
        }
        return true;
    }

    private static IReadOnlyList<string> SafePins(string value)
        => ProviderAsnCatalogTransportPinning.DeserializePins(value);

    private static void Validate(ProviderAsnCatalogRemoteSourceRevisionQuery query)
    {
        if (query.MaxAge <= TimeSpan.Zero || query.MaxAge > TimeSpan.FromDays(3650))
        {
            throw new ArgumentOutOfRangeException(nameof(query.MaxAge));
        }
        if (query.MaxItems is < 1 or > 1000)
        {
            throw new ArgumentOutOfRangeException(nameof(query.MaxItems));
        }
        if (!query.TlsSpkiPinSha256.IsNullOrEmpty())
        {
            _ = ProviderAsnCatalogTransportPinning.NormalizePins([query.TlsSpkiPinSha256!]);
        }
        if (!query.ChangeReason.IsNullOrEmpty() && query.ChangeReason.Trim().Length > 80)
        {
            throw new ArgumentOutOfRangeException(nameof(query.ChangeReason));
        }
    }
}
