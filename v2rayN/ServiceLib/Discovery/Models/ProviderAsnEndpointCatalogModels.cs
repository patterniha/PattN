namespace ServiceLib.Discovery.Models;

/// <summary>
/// Pre-enumerated provider/ASN endpoint metadata. This is deliberately endpoint-level rather than CIDR-level:
/// the adapter never scans or expands address space.
/// </summary>
public sealed record ProviderAsnEndpointCatalogEntry
{
    public required string Address { get; init; }
    public int? Port { get; init; }
    public string Provider { get; init; } = string.Empty;
    public string Asn { get; init; } = string.Empty;
    public string Pop { get; init; } = string.Empty;
    public string SourceId { get; init; } = string.Empty;
    public IReadOnlyList<string> LogicalHosts { get; init; } = [];
    public string Network { get; init; } = string.Empty;
    public string StreamSecurity { get; init; } = string.Empty;
    public bool Enabled { get; init; } = true;
    public DateTimeOffset? ObservedAt { get; init; }
    public IReadOnlyDictionary<string, string> Metadata { get; init; } = new Dictionary<string, string>();
}

public interface IProviderAsnEndpointCatalog
{
    Task<IReadOnlyList<ProviderAsnEndpointCatalogEntry>> ListAsync(
        DiscoveryCandidateRequest request,
        int maxItems,
        CancellationToken cancellationToken = default);
}
