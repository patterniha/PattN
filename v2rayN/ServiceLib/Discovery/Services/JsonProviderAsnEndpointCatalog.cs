using ServiceLib.Discovery.Models;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Versioned JSON-backed provider/ASN endpoint catalog. The source document is SHA-256 fingerprinted and
/// provenance is projected into every candidate. Loading validates all physical addresses up front.
/// </summary>
public sealed class JsonProviderAsnEndpointCatalog : IProviderAsnEndpointCatalog
{
    private readonly StaticProviderAsnEndpointCatalog _inner;

    private JsonProviderAsnEndpointCatalog(
        ProviderAsnEndpointCatalogDocument document,
        string sha256,
        IReadOnlyList<ProviderAsnEndpointCatalogEntry> entries)
    {
        Document = document;
        Sha256 = sha256;
        Entries = entries;
        _inner = new StaticProviderAsnEndpointCatalog(entries);
    }

    public ProviderAsnEndpointCatalogDocument Document { get; }
    public string Sha256 { get; }
    public IReadOnlyList<ProviderAsnEndpointCatalogEntry> Entries { get; }

    public static async Task<JsonProviderAsnEndpointCatalog> LoadAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var info = new FileInfo(path);
        if (info.Exists && info.Length > ProviderAsnEndpointCatalogDocument.MaximumDocumentBytes)
        {
            throw new InvalidOperationException(
                $"Provider/ASN catalog exceeds {ProviderAsnEndpointCatalogDocument.MaximumDocumentBytes} bytes.");
        }
        var bytes = await File.ReadAllBytesAsync(path, cancellationToken);
        return FromBytes(bytes);
    }

    public static JsonProviderAsnEndpointCatalog FromBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty)
        {
            throw new InvalidOperationException("Provider/ASN catalog document is empty.");
        }
        if (bytes.Length > ProviderAsnEndpointCatalogDocument.MaximumDocumentBytes)
        {
            throw new InvalidOperationException(
                $"Provider/ASN catalog exceeds {ProviderAsnEndpointCatalogDocument.MaximumDocumentBytes} bytes.");
        }

        ProviderAsnEndpointCatalogDocument document;
        try
        {
            document = JsonSerializer.Deserialize<ProviderAsnEndpointCatalogDocument>(
                    bytes,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                ?? throw new InvalidOperationException("Provider/ASN catalog document decoded to null.");
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException("Provider/ASN catalog JSON is invalid.", ex);
        }

        ValidateDocument(document);
        var sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        var entries = document.Entries
            .Select((entry, index) => DecorateEntry(document, sha256, entry, index))
            .ToArray();
        return new JsonProviderAsnEndpointCatalog(document, sha256, entries);
    }

    public ProviderAsnCatalogAudit Audit(
        DateTimeOffset? now = null,
        ProviderAsnCatalogAuditPolicy? policy = null)
        => ProviderAsnCatalogAuditService.Audit(this, now, policy);

    public Task<IReadOnlyList<ProviderAsnEndpointCatalogEntry>> ListAsync(
        DiscoveryCandidateRequest request,
        int maxItems,
        CancellationToken cancellationToken = default)
        => _inner.ListAsync(request, maxItems, cancellationToken);

    private static void ValidateDocument(ProviderAsnEndpointCatalogDocument document)
    {
        if (document.SchemaVersion != ProviderAsnEndpointCatalogDocument.CurrentSchemaVersion)
        {
            throw new InvalidOperationException(
                $"Unsupported provider/ASN catalog schema version {document.SchemaVersion}.");
        }
        if (string.IsNullOrWhiteSpace(document.Id))
        {
            throw new InvalidOperationException("Provider/ASN catalog ID is required.");
        }
        if (string.IsNullOrWhiteSpace(document.Version))
        {
            throw new InvalidOperationException("Provider/ASN catalog version is required.");
        }
        if (string.IsNullOrWhiteSpace(document.Source))
        {
            throw new InvalidOperationException("Provider/ASN catalog source is required.");
        }
        if (document.Entries is null)
        {
            throw new InvalidOperationException("Provider/ASN catalog entries cannot be null.");
        }
        if (document.Entries.Count > ProviderAsnEndpointCatalogDocument.MaximumEntries)
        {
            throw new InvalidOperationException(
                $"Provider/ASN catalog exceeds {ProviderAsnEndpointCatalogDocument.MaximumEntries} entries.");
        }

        for (var i = 0; i < document.Entries.Count; i++)
        {
            var entry = document.Entries[i]
                ?? throw new InvalidOperationException($"Provider/ASN catalog entry {i} cannot be null.");
            var address = (entry.Address ?? string.Empty).Trim().Trim('[', ']');
            if (!IPAddress.TryParse(address, out _))
            {
                throw new InvalidOperationException($"Provider/ASN catalog entry {i} has invalid IP address '{entry.Address}'.");
            }
            if (entry.Port.HasValue && (entry.Port.Value < 1 || entry.Port.Value > 65535))
            {
                throw new InvalidOperationException($"Provider/ASN catalog entry {i} has invalid port {entry.Port.Value}.");
            }
        }
    }

    private static ProviderAsnEndpointCatalogEntry DecorateEntry(
        ProviderAsnEndpointCatalogDocument document,
        string sha256,
        ProviderAsnEndpointCatalogEntry entry,
        int index)
    {
        var metadata = entry.Metadata is null
            ? new Dictionary<string, string>(StringComparer.Ordinal)
            : new Dictionary<string, string>(entry.Metadata, StringComparer.Ordinal);
        var generatedSourceId = string.IsNullOrWhiteSpace(entry.SourceId);
        metadata["catalogId"] = document.Id.Trim();
        metadata["catalogVersion"] = document.Version.Trim();
        metadata["catalogSource"] = document.Source.Trim();
        metadata["catalogSha256"] = sha256;
        metadata["catalogSourceIdGenerated"] = generatedSourceId ? "true" : "false";
        if (document.UpdatedAt is not null)
        {
            metadata["catalogUpdatedAt"] = document.UpdatedAt.Value.ToString("O");
        }

        return entry with
        {
            Address = (entry.Address ?? string.Empty).Trim().Trim('[', ']'),
            SourceId = generatedSourceId ? $"{document.Id.Trim()}:{index}" : entry.SourceId.Trim(),
            LogicalHosts = entry.LogicalHosts ?? [],
            Metadata = metadata,
        };
    }
}
