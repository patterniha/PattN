namespace ServiceLib.Models.Entities;

[Serializable]
public class EndpointPoolItem
{
    [PrimaryKey]
    public string Id { get; set; } = string.Empty;

    public string LogicalHost { get; set; } = string.Empty;
    public string HttpHost { get; set; } = string.Empty;
    public int Port { get; set; }
    public string Network { get; set; } = string.Empty;
    public string StreamSecurity { get; set; } = string.Empty;
    public string Address { get; set; } = string.Empty;
    public string Label { get; set; } = string.Empty;
    public bool Enabled { get; set; } = true;
    public bool Pinned { get; set; }
    public string Provider { get; set; } = string.Empty;
    public string Asn { get; set; } = string.Empty;
    public string Pop { get; set; } = string.Empty;
    public long CreatedAtUnixMs { get; set; }
    public long UpdatedAtUnixMs { get; set; }
}
