namespace ServiceLib.Models.Entities;

[Serializable]
public class ProviderAsnCatalogRevisionItem
{
    [PrimaryKey]
    public string Id { get; set; } = string.Empty;

    public string RegistryId { get; set; } = string.Empty;
    public string PlanId { get; set; } = string.Empty;
    public string DestinationPath { get; set; } = string.Empty;

    public bool DestinationExisted { get; set; }
    public string BeforeSha256 { get; set; } = string.Empty;
    public string AfterSha256 { get; set; } = string.Empty;
    public string BeforeCatalogId { get; set; } = string.Empty;
    public string BeforeCatalogVersion { get; set; } = string.Empty;
    public string AfterCatalogId { get; set; } = string.Empty;
    public string AfterCatalogVersion { get; set; } = string.Empty;
    public byte[] BeforeBytes { get; set; } = [];

    public long AppliedAtUnixMs { get; set; }
    public long? RolledBackAtUnixMs { get; set; }
    public bool RollbackForced { get; set; }

    public string AuditJson { get; set; } = string.Empty;
    public string DiffJson { get; set; } = string.Empty;
}
