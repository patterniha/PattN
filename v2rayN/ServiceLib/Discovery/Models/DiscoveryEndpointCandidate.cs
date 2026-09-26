namespace ServiceLib.Discovery.Models;

/// <summary>
/// A network endpoint observed by PattN Discovery. Discovery owns network evidence; it never edits profiles.
/// Logical protocol identity (SNI/Host/etc.) deliberately does not live here because Reviver must preserve it
/// from the source profile unless it has explicit evidence for a semantic change.
/// </summary>
public sealed record DiscoveryEndpointCandidate
{
    public required string Address { get; init; }
    public int? Port { get; init; }
    public string? Source { get; init; }
    public string? Provider { get; init; }
    public string? Asn { get; init; }
    public string? Pop { get; init; }
    public double? LatencyMs { get; init; }
    public double? LossRate { get; init; }
    public double? Reliability { get; init; }
    public DateTimeOffset ObservedAt { get; init; } = DateTimeOffset.UtcNow;
    public IReadOnlyDictionary<string, string> Metadata { get; init; } = new Dictionary<string, string>();
}
