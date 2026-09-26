namespace ServiceLib.Models.Entities;

[Serializable]
public class DnsResolverCatalogAuditItem
{
    [PrimaryKey]
    public string Id { get; set; } = "builtin";

    public string CatalogVersion { get; set; } = string.Empty;
    public bool Valid { get; set; }
    public int MaxAgeDays { get; set; }
    public int StaleCount { get; set; }
    public long AuditedAtUnixMs { get; set; }
    public string EntriesJson { get; set; } = string.Empty;
    public string Error { get; set; } = string.Empty;
}
