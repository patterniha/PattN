using ServiceLib.Discovery.Models;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Simple immutable catalog useful for bundled datasets, tests, and callers that already parsed a governed source.
/// </summary>
public sealed class StaticProviderAsnEndpointCatalog(
    IEnumerable<ProviderAsnEndpointCatalogEntry> entries) : IProviderAsnEndpointCatalog
{
    private readonly ProviderAsnEndpointCatalogEntry[] _entries = entries?.ToArray()
        ?? throw new ArgumentNullException(nameof(entries));

    public Task<IReadOnlyList<ProviderAsnEndpointCatalogEntry>> ListAsync(
        DiscoveryCandidateRequest request,
        int maxItems,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (maxItems <= 0)
        {
            return Task.FromResult<IReadOnlyList<ProviderAsnEndpointCatalogEntry>>([]);
        }

        var host = NormalizeHost(request.LogicalHost);
        var network = NormalizeToken(request.Network);
        var security = NormalizeToken(request.StreamSecurity);

        return Task.FromResult<IReadOnlyList<ProviderAsnEndpointCatalogEntry>>(
            _entries
                .Where(x => x is not null && x.Enabled)
                .Where(x => x.Port is null || x.Port == request.OriginalPort)
                .Where(x => x.LogicalHosts is null
                            || x.LogicalHosts.Count == 0
                            || x.LogicalHosts.Select(NormalizeHost).Contains(host, StringComparer.OrdinalIgnoreCase))
                .Where(x => x.Network.IsNullOrEmpty()
                            || NormalizeToken(x.Network).Equals(network, StringComparison.Ordinal))
                .Where(x => x.StreamSecurity.IsNullOrEmpty()
                            || NormalizeToken(x.StreamSecurity).Equals(security, StringComparison.Ordinal))
                .Take(maxItems)
                .ToArray());
    }

    private static string NormalizeHost(string? value)
        => (value ?? string.Empty).Trim().Trim('[', ']').TrimEnd('.').ToLowerInvariant();

    private static string NormalizeToken(string? value)
        => (value ?? string.Empty).Trim().ToLowerInvariant();
}
