namespace ServiceLib.Discovery.Models;

public sealed record ProviderAsnCatalogRemoteSourcePortableBundle
{
    public int FormatVersion { get; init; } = 1;
    public DateTimeOffset ExportedAt { get; init; }
    public string CatalogId { get; init; } = string.Empty;
    public string CatalogVersion { get; init; } = string.Empty;
    public string DisplayName { get; init; } = string.Empty;
    public ProviderAsnCatalogRemoteSourceConfig Source { get; init; } =
        new() { Uri = "https://invalid.example/" };
    public string TrustedPublicKeySha256 { get; init; } = string.Empty;
    public string Notes { get; init; } =
        "Portable remote-source configuration contains HTTPS source/signature locations and public trust material only. It excludes conditional-cache state, remote content bytes, signature bytes, and private keys.";
}

public sealed record ProviderAsnCatalogRemoteSourceImportPreview
{
    public required string TargetRegistryId { get; init; }
    public required string CatalogId { get; init; }
    public string CurrentCatalogVersion { get; init; } = string.Empty;
    public string BundleCatalogVersion { get; init; } = string.Empty;
    public string DisplayName { get; init; } = string.Empty;
    public ProviderAsnCatalogRemoteSourceConfig Source { get; init; } =
        new() { Uri = "https://invalid.example/" };
    public string TrustedPublicKeySha256 { get; init; } = string.Empty;
    public string ExistingConfigurationFingerprint { get; init; } = string.Empty;
    public string ImportedConfigurationFingerprint { get; init; } = string.Empty;
    public DateTimeOffset PreparedAt { get; init; }
    public IReadOnlyList<string> Warnings { get; init; } = [];
}
