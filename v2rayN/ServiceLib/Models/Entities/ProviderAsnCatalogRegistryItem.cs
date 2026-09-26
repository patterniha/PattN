namespace ServiceLib.Models.Entities;

[Serializable]
public class ProviderAsnCatalogRegistryItem
{
    [PrimaryKey]
    public string Id { get; set; } = string.Empty;

    public string FilePath { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public bool Enabled { get; set; } = true;

    public string CatalogId { get; set; } = string.Empty;
    public string CatalogVersion { get; set; } = string.Empty;
    public string CatalogSource { get; set; } = string.Empty;
    public string Sha256 { get; set; } = string.Empty;
    public long? CatalogUpdatedAtUnixMs { get; set; }

    public long RegisteredAtUnixMs { get; set; }
    public long UpdatedAtUnixMs { get; set; }
    public long? UnregisteredAtUnixMs { get; set; }
    public long LastAuditedAtUnixMs { get; set; }
    public string LastAuditJson { get; set; } = string.Empty;
    public string ActiveRevisionId { get; set; } = string.Empty;
}
