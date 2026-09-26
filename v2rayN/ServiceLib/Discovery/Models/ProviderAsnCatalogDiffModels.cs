namespace ServiceLib.Discovery.Models;

public sealed record ProviderAsnCatalogDiffEntry
{
    public required string Identity { get; init; }
    public required string ChangeKind { get; init; }
    public ProviderAsnEndpointCatalogEntry? Before { get; init; }
    public ProviderAsnEndpointCatalogEntry? After { get; init; }
    public IReadOnlyList<string> ChangedFields { get; init; } = [];
}

public sealed record ProviderAsnCatalogDiff
{
    public string BeforeCatalogId { get; init; } = string.Empty;
    public string BeforeVersion { get; init; } = string.Empty;
    public string BeforeSha256 { get; init; } = string.Empty;
    public string AfterCatalogId { get; init; } = string.Empty;
    public string AfterVersion { get; init; } = string.Empty;
    public string AfterSha256 { get; init; } = string.Empty;
    public int Added { get; init; }
    public int Removed { get; init; }
    public int Modified { get; init; }
    public int Unchanged { get; init; }
    public IReadOnlyList<ProviderAsnCatalogDiffEntry> Entries { get; init; } = [];
}
