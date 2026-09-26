namespace ServiceLib.Discovery.Models;

/// <summary>
/// Bounded request from Reviver to Discovery. TLS server-name identity and HTTP Host identity are carried
/// separately because fronted/transport-host profiles may intentionally use different values. Returned candidates
/// remain physical dial targets.
/// </summary>
public sealed record DiscoveryCandidateRequest
{
    public required string OriginalAddress { get; init; }
    public required int OriginalPort { get; init; }
    public string? LogicalHost { get; init; }
    public string? HttpHost { get; init; }
    public string? Network { get; init; }
    public string? StreamSecurity { get; init; }
    public int MaxCandidates { get; init; } = 32;
    public bool IncludeHistorical { get; init; } = true;
    public bool IncludeEndpointPools { get; init; } = true;
}
