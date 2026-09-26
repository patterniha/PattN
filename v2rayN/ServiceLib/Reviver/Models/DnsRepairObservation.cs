namespace ServiceLib.Reviver.Models;

public sealed record DnsFamilyObservation
{
    public required string Family { get; init; }
    public IReadOnlyList<string> Addresses { get; init; } = [];
    public bool TraceComplete { get; init; }
    public bool DnssecAuthenticated { get; init; }
    public string DnssecStatus { get; init; } = string.Empty;
    public string Error { get; init; } = string.Empty;

    public bool HasAddresses => Addresses.Count > 0;
}

public sealed record DnsResolverRecommendation
{
    public required string CatalogId { get; init; }
    public required string Provider { get; init; }
    public required string Name { get; init; }
    public IReadOnlyList<string> IPv4 { get; init; } = [];
    public IReadOnlyList<string> IPv6 { get; init; } = [];
    public string DotServerName { get; init; } = string.Empty;
    public int DotPort { get; init; } = 853;
    public string DohUrl { get; init; } = string.Empty;
    public string Policy { get; init; } = string.Empty;
    public bool ReferenceEligible { get; init; }
}

public sealed record DnsRepairObservation
{
    public required string Host { get; init; }
    public DnsFamilyObservation IPv4 { get; init; } = new() { Family = "ipv4" };
    public DnsFamilyObservation IPv6 { get; init; } = new() { Family = "ipv6" };
    public string ResolverCatalogVersion { get; init; } = string.Empty;
    public IReadOnlyList<DnsResolverRecommendation> ResolverRecommendations { get; init; } = [];
    public DateTimeOffset ObservedAt { get; init; } = DateTimeOffset.UtcNow;

    public bool HasIPv4 => IPv4.HasAddresses;
    public bool HasIPv6 => IPv6.HasAddresses;
}
