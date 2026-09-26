namespace ServiceLib.Discovery.Models;

public sealed record ProviderAsnEndpointCatalogDocument
{
    public const int CurrentSchemaVersion = 1;
    public const int MaximumEntries = 100_000;
    public const int MaximumDocumentBytes = 32 * 1024 * 1024;

    [JsonPropertyName("schemaVersion")]
    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    [JsonPropertyName("id")]
    public string Id { get; init; } = string.Empty;

    [JsonPropertyName("version")]
    public string Version { get; init; } = string.Empty;

    [JsonPropertyName("source")]
    public string Source { get; init; } = string.Empty;

    [JsonPropertyName("updatedAt")]
    public DateTimeOffset? UpdatedAt { get; init; }

    [JsonPropertyName("entries")]
    public IReadOnlyList<ProviderAsnEndpointCatalogEntry> Entries { get; init; } = [];
}
