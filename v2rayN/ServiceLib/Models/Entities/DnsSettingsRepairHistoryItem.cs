namespace ServiceLib.Models.Entities;

[Serializable]
public class DnsSettingsRepairHistoryItem
{
    [PrimaryKey]
    public string Id { get; set; } = string.Empty;

    public string EventKind { get; set; } = string.Empty;
    public string PlanId { get; set; } = string.Empty;
    public string ResolverCatalogId { get; set; } = string.Empty;
    public string CatalogVersion { get; set; } = string.Empty;
    public string ReceiptJson { get; set; } = string.Empty;
    public long ObservedAtUnixMs { get; set; }
}
