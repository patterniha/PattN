namespace ServiceLib.Models.Entities;

[Serializable]
public class EndpointObservationHistoryItem
{
    [PrimaryKey]
    public string Id { get; set; } = string.Empty;

    public string LogicalHost { get; set; } = string.Empty;
    public string HttpHost { get; set; } = string.Empty;
    public int Port { get; set; }
    public string Network { get; set; } = string.Empty;
    public string StreamSecurity { get; set; } = string.Empty;
    public string Address { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public string Provider { get; set; } = string.Empty;
    public string Asn { get; set; } = string.Empty;
    public string Pop { get; set; } = string.Empty;
    public int Attempts { get; set; }
    public int Successes { get; set; }
    public int ConsecutiveSuccesses { get; set; }
    public bool Qualified { get; set; }
    public double Reliability { get; set; }
    public double? MedianLatencyMs { get; set; }
    public string ErrorsJson { get; set; } = string.Empty;
    public long ObservedAtUnixMs { get; set; }
}
