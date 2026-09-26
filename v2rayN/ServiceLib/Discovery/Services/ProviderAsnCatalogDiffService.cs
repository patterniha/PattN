using ServiceLib.Discovery.Models;

namespace ServiceLib.Discovery.Services;

public static class ProviderAsnCatalogDiffService
{
    private static readonly HashSet<string> ProvenanceMetadataKeys = new(StringComparer.Ordinal)
    {
        "catalogId",
        "catalogVersion",
        "catalogSource",
        "catalogSha256",
        "catalogUpdatedAt",
        "catalogSourceIdGenerated",
    };

    public static ProviderAsnCatalogDiff Compare(
        JsonProviderAsnEndpointCatalog before,
        JsonProviderAsnEndpointCatalog after)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);

        var left = Index(before);
        var right = Index(after);
        var identities = left.Keys
            .Concat(right.Keys)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(x => x, StringComparer.Ordinal)
            .ToArray();

        var changes = new List<ProviderAsnCatalogDiffEntry>(identities.Length);
        var added = 0;
        var removed = 0;
        var modified = 0;
        var unchanged = 0;

        foreach (var identity in identities)
        {
            left.TryGetValue(identity, out var oldEntry);
            right.TryGetValue(identity, out var newEntry);

            if (oldEntry is null)
            {
                added++;
                changes.Add(new ProviderAsnCatalogDiffEntry
                {
                    Identity = identity,
                    ChangeKind = "added",
                    After = newEntry,
                });
                continue;
            }
            if (newEntry is null)
            {
                removed++;
                changes.Add(new ProviderAsnCatalogDiffEntry
                {
                    Identity = identity,
                    ChangeKind = "removed",
                    Before = oldEntry,
                });
                continue;
            }

            var fields = ChangedFields(oldEntry, newEntry);
            if (fields.Count == 0)
            {
                unchanged++;
                continue;
            }

            modified++;
            changes.Add(new ProviderAsnCatalogDiffEntry
            {
                Identity = identity,
                ChangeKind = "modified",
                Before = oldEntry,
                After = newEntry,
                ChangedFields = fields,
            });
        }

        return new ProviderAsnCatalogDiff
        {
            BeforeCatalogId = before.Document.Id,
            BeforeVersion = before.Document.Version,
            BeforeSha256 = before.Sha256,
            AfterCatalogId = after.Document.Id,
            AfterVersion = after.Document.Version,
            AfterSha256 = after.Sha256,
            Added = added,
            Removed = removed,
            Modified = modified,
            Unchanged = unchanged,
            Entries = changes,
        };
    }

    private static Dictionary<string, ProviderAsnEndpointCatalogEntry> Index(
        JsonProviderAsnEndpointCatalog catalog)
    {
        var result = new Dictionary<string, ProviderAsnEndpointCatalogEntry>(StringComparer.Ordinal);
        foreach (var entry in catalog.Entries)
        {
            var identity = Identity(entry);
            if (!result.TryAdd(identity, entry))
            {
                throw new InvalidOperationException(
                    $"Provider/ASN catalog '{catalog.Document.Id}' contains ambiguous diff identity '{identity}'.");
            }
        }
        return result;
    }

    private static string Identity(ProviderAsnEndpointCatalogEntry entry)
    {
        var generated = false;
        if (entry.Metadata is not null
            && entry.Metadata.TryGetValue("catalogSourceIdGenerated", out var generatedValue))
        {
            generated = string.Equals(generatedValue, "true", StringComparison.OrdinalIgnoreCase);
        }
        if (!generated && !entry.SourceId.IsNullOrEmpty())
        {
            return "source:" + entry.SourceId.Trim();
        }
        return "endpoint:" + EndpointScopeKey(entry);
    }

    private static string EndpointScopeKey(ProviderAsnEndpointCatalogEntry entry)
    {
        var hosts = entry.LogicalHosts is null
            ? string.Empty
            : string.Join(",", entry.LogicalHosts.Select(NormalizeHost).OrderBy(x => x, StringComparer.Ordinal));
        return string.Join("|",
            NormalizeAddress(entry.Address),
            entry.Port?.ToString() ?? "*",
            NormalizeToken(entry.Network),
            NormalizeToken(entry.StreamSecurity),
            hosts);
    }

    private static IReadOnlyList<string> ChangedFields(
        ProviderAsnEndpointCatalogEntry before,
        ProviderAsnEndpointCatalogEntry after)
    {
        var fields = new List<string>();
        Add(fields, "address", NormalizeAddress(before.Address), NormalizeAddress(after.Address));
        Add(fields, "port", before.Port?.ToString(), after.Port?.ToString());
        Add(fields, "provider", NormalizeText(before.Provider), NormalizeText(after.Provider));
        Add(fields, "asn", NormalizeText(before.Asn), NormalizeText(after.Asn));
        Add(fields, "pop", NormalizeText(before.Pop), NormalizeText(after.Pop));
        Add(fields, "logicalHosts", NormalizeHosts(before.LogicalHosts), NormalizeHosts(after.LogicalHosts));
        Add(fields, "network", NormalizeToken(before.Network), NormalizeToken(after.Network));
        Add(fields, "streamSecurity", NormalizeToken(before.StreamSecurity), NormalizeToken(after.StreamSecurity));
        Add(fields, "enabled", before.Enabled.ToString(), after.Enabled.ToString());
        Add(fields, "observedAt", before.ObservedAt?.ToUniversalTime().ToString("O"), after.ObservedAt?.ToUniversalTime().ToString("O"));
        Add(fields, "metadata", NormalizeMetadata(before.Metadata), NormalizeMetadata(after.Metadata));
        return fields;
    }

    private static void Add(List<string> fields, string field, string? left, string? right)
    {
        if (!string.Equals(left ?? string.Empty, right ?? string.Empty, StringComparison.Ordinal))
        {
            fields.Add(field);
        }
    }

    private static string NormalizeMetadata(IReadOnlyDictionary<string, string>? metadata)
        => metadata is null
            ? string.Empty
            : string.Join(
                "\n",
                metadata
                    .Where(x => !ProvenanceMetadataKeys.Contains(x.Key))
                    .OrderBy(x => x.Key, StringComparer.Ordinal)
                    .Select(x => x.Key + "=" + (x.Value ?? string.Empty)));

    private static string NormalizeHosts(IReadOnlyList<string>? hosts)
        => hosts is null
            ? string.Empty
            : string.Join(",", hosts.Select(NormalizeHost).OrderBy(x => x, StringComparer.Ordinal));

    private static string NormalizeAddress(string? value)
        => (value ?? string.Empty).Trim().Trim('[', ']').ToLowerInvariant();

    private static string NormalizeHost(string? value)
        => (value ?? string.Empty).Trim().Trim('[', ']').TrimEnd('.').ToLowerInvariant();

    private static string NormalizeToken(string? value)
        => (value ?? string.Empty).Trim().ToLowerInvariant();

    private static string NormalizeText(string? value)
        => (value ?? string.Empty).Trim();
}
