using System.Security.Cryptography;
using ServiceLib.Discovery.Models;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Creates explicit, portable archives for retired provider/ASN catalogs. Export is read-only and never changes
/// registry state or catalog bytes. By default on-disk drift after retirement is rejected.
/// </summary>
public sealed class ProviderAsnCatalogArchiveService(
    ProviderAsnCatalogRegistryService catalogs,
    IProviderAsnCatalogRemoteApplyProvenanceStore? provenanceStore = null)
{
    public async Task<ProviderAsnCatalogArchiveBundle> PrepareAsync(
        string registryId,
        ProviderAsnCatalogArchiveOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        options ??= new ProviderAsnCatalogArchiveOptions();
        if (options.MaxRevisions is < 1 or > 5000)
        {
            throw new ArgumentOutOfRangeException(nameof(options.MaxRevisions));
        }

        var registry = await catalogs.GetAsync(registryId, cancellationToken);
        if (registry.Registered)
        {
            throw new InvalidOperationException("Catalog archive export is restricted to retired registry resources.");
        }
        if (!File.Exists(registry.FilePath))
        {
            throw new FileNotFoundException("Retired catalog file no longer exists.", registry.FilePath);
        }

        var bytes = await File.ReadAllBytesAsync(registry.FilePath, cancellationToken);
        var sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        if (!options.AllowFileDrift
            && !registry.Sha256.IsNullOrEmpty()
            && !string.Equals(registry.Sha256, sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Retired catalog file changed after its registered state was recorded. Refresh/re-register or explicitly allow drift before exporting.");
        }

        var revisions = await catalogs.ListRevisionsAsync(
            new ProviderAsnCatalogRevisionQuery
            {
                RegistryId = registry.Id,
                IncludeRolledBack = true,
                MaxItems = options.MaxRevisions,
            },
            cancellationToken);

        IReadOnlyList<ProviderAsnCatalogRemoteApplyProvenanceView> remoteProvenance = [];
        if (provenanceStore is not null && revisions.Count > 0)
        {
            var revisionIds = revisions.Select(x => x.Id).ToHashSet(StringComparer.Ordinal);
            remoteProvenance = (await provenanceStore.ListByRegistryAsync(
                    registry.Id,
                    options.MaxRevisions,
                    cancellationToken))
                .Where(x => revisionIds.Contains(x.RevisionId))
                .OrderBy(x => x.AppliedAtUnixMs)
                .Select(ProviderAsnCatalogRemoteProvenanceProjector.Project)
                .ToArray();
        }

        return new ProviderAsnCatalogArchiveBundle
        {
            CreatedAt = DateTimeOffset.UtcNow,
            Registry = registry,
            CatalogFileName = Path.GetFileName(registry.FilePath),
            CatalogFileSha256 = sha256,
            CatalogFileBase64 = Convert.ToBase64String(bytes),
            Revisions = revisions,
            RemoteProvenance = remoteProvenance,
        };
    }

    public async Task<ProviderAsnCatalogArchiveBundle> PrepareSignedAsync(
        string registryId,
        string keyId,
        ECDsa signer,
        ProviderAsnCatalogArchiveOptions? options = null,
        DateTimeOffset? signedAt = null,
        CancellationToken cancellationToken = default)
    {
        var bundle = await PrepareAsync(registryId, options, cancellationToken);
        return ProviderAsnCatalogArchiveSignatureService.Sign(
            bundle,
            keyId,
            signer,
            signedAt);
    }

    public async Task SaveAsync(
        ProviderAsnCatalogArchiveBundle bundle,
        string destinationPath,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        destinationPath = Path.GetFullPath(destinationPath);
        var directory = Path.GetDirectoryName(destinationPath)
            ?? throw new InvalidOperationException("Archive destination has no parent directory.");
        Directory.CreateDirectory(directory);

        var payload = JsonUtils.Serialize(bundle, true);
        var bytes = System.Text.Encoding.UTF8.GetBytes(payload);
        await DurableAtomicFile.WriteAsync(
            destinationPath,
            bytes,
            cancellationToken: cancellationToken);
    }
}
