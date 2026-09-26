namespace ServiceLib.Discovery.Models;

public sealed record DnsResolverHealthRow
{
    public required string CatalogId { get; init; }
    public required string Name { get; init; }
    public required string Provider { get; init; }
    public required string Policy { get; init; }
    public bool ReferenceEligible { get; init; }
    public required string Address { get; init; }
    public required string Quality { get; init; }
    public required string HealthClass { get; init; }
    public double Reliability { get; init; }
    public int QuorumTransportCount { get; init; }
    public double HealthScore { get; init; }
    public double? MedianLatencyMs { get; init; }
    public bool InterceptionSuspected { get; init; }
    public IReadOnlyList<string> Reasons { get; init; } = [];
    public string Error { get; init; } = string.Empty;
    public DateTimeOffset ObservedAt { get; init; }

    public string DisplayLine
    {
        get
        {
            var latency = MedianLatencyMs is >= 0 ? $" · {MedianLatencyMs:0.#} ms" : string.Empty;
            var policy = Policy.IsNullOrEmpty() ? string.Empty : $" · {Policy}";
            var reference = ReferenceEligible ? " · reference" : string.Empty;
            var reasons = Reasons.Count == 0 ? string.Empty : $" · {string.Join(",", Reasons)}";
            var error = Error.IsNullOrEmpty() ? string.Empty : $" · {Error}";
            return $"{Name}: {HealthClass} · {Quality} · reliability {Reliability:P0}{latency}{policy}{reference}{reasons}{error}";
        }
    }
}


public sealed record DnsResolverOption
{
    public required string CatalogId { get; init; }
    public required string Provider { get; init; }
    public required string Name { get; init; }
    public IReadOnlyList<string> IPv4 { get; init; } = [];
    public IReadOnlyList<string> IPv6 { get; init; } = [];
    public int Port { get; init; } = 53;
    public string DotServerName { get; init; } = string.Empty;
    public int DotPort { get; init; } = 853;
    public string DohUrl { get; init; } = string.Empty;
    public required string Policy { get; init; }
    public bool ReferenceEligible { get; init; }
    public required string HealthClass { get; init; }
    public string Quality { get; init; } = string.Empty;
    public int QuorumTransportCount { get; init; }
    public bool InterceptionSuspected { get; init; }

    public bool IsSafeToApply
        => QuorumTransportCount > 0
           && !InterceptionSuspected
           && HealthClass is "healthy" or "watch";

    public string DisplayName
        => $"{Name} · {HealthClass} · {Policy}";

    public override string ToString() => DisplayName;
}

public sealed record DnsHealthDashboardSnapshot
{
    public bool DiscoveryAvailable { get; init; }
    public string CatalogVersion { get; init; } = string.Empty;
    public bool CatalogAuditKnown { get; init; }
    public bool CatalogValid { get; init; }
    public int CatalogStaleCount { get; init; }
    public int CatalogMaxAgeDays { get; init; }
    public DateTimeOffset? CatalogAuditedAt { get; init; }
    public IReadOnlyList<DnsResolverHealthRow> Resolvers { get; init; } = [];
    public IReadOnlyList<DnsResolverOption> ResolverOptions { get; init; } = [];
    public DateTimeOffset? RefreshedAt { get; init; }
    public string Error { get; init; } = string.Empty;

    public int HealthyCount => Resolvers.Count(x => x.HealthClass == "healthy");
    public int WatchCount => Resolvers.Count(x => x.HealthClass == "watch");
    public int DegradedCount => Resolvers.Count(x => x.HealthClass is "degraded" or "suspicious" or "unavailable");
}
