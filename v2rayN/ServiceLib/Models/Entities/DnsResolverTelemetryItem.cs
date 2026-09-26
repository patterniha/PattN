namespace ServiceLib.Models.Entities;

[Serializable]
public class DnsResolverTelemetryItem
{
    [PrimaryKey]
    public string Id { get; set; } = string.Empty;

    public string ResolverCatalogId { get; set; } = string.Empty;
    public string CatalogVersion { get; set; } = string.Empty;
    public string Provider { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Address { get; set; } = string.Empty;
    public string Policy { get; set; } = string.Empty;
    public bool ReferenceEligible { get; set; }
    public string Quality { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public double ReliabilityFloor { get; set; }
    public int QuorumTransportCount { get; set; }
    public bool InterceptionSuspected { get; set; }
    public double? MedianLatencyMs { get; set; }
    public double HealthScore { get; set; }
    public string HealthClass { get; set; } = string.Empty;
    public string ReasonCodes { get; set; } = string.Empty;
    public string Error { get; set; } = string.Empty;
    public long ObservedAtUnixMs { get; set; }
}
