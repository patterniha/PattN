using System.Security.Cryptography;
using ServiceLib.Discovery.Models;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Read-only inspection of exported provider/ASN catalog archives. Inspection validates embedded bytes and
/// metadata but never registers a catalog, writes the archive, or mutates any registry/source state.
/// </summary>
public sealed class ProviderAsnCatalogArchiveInspectionService
{
    public async Task<ProviderAsnCatalogArchiveInspection> InspectAsync(
        string archivePath,
        ProviderAsnCatalogArchiveInspectionOptions? options = null,
        DateTimeOffset? now = null,
        CancellationToken cancellationToken = default)
    {
        options ??= new ProviderAsnCatalogArchiveInspectionOptions();
        ValidateOptions(options);
        cancellationToken.ThrowIfCancellationRequested();

        var path = Path.GetFullPath(archivePath);
        var info = new FileInfo(path);
        if (!info.Exists)
        {
            throw new FileNotFoundException("Provider catalog archive was not found.", path);
        }
        if (info.Length <= 0 || info.Length > options.MaximumArchiveBytes)
        {
            throw new InvalidOperationException(
                $"Provider catalog archive size {info.Length} is outside the allowed range.");
        }

        var payload = await File.ReadAllTextAsync(path, cancellationToken);
        var bundle = JsonUtils.Deserialize<ProviderAsnCatalogArchiveBundle>(payload)
            ?? throw new InvalidOperationException("Provider catalog archive JSON could not be decoded.");

        if (bundle.FormatVersion is not (2 or 3))
        {
            throw new InvalidOperationException(
                $"Unsupported provider catalog archive format version {bundle.FormatVersion}; expected 2 or 3.");
        }
        if (bundle.Registry.Id.IsNullOrEmpty() || bundle.Registry.CatalogId.IsNullOrEmpty())
        {
            throw new InvalidOperationException("Provider catalog archive registry identity is incomplete.");
        }
        if (bundle.CatalogFileName.IsNullOrEmpty()
            || !string.Equals(Path.GetFileName(bundle.CatalogFileName), bundle.CatalogFileName, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Provider catalog archive file name must be a simple file name.");
        }

        byte[] catalogBytes;
        try
        {
            catalogBytes = Convert.FromBase64String(bundle.CatalogFileBase64);
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException("Provider catalog archive payload is not valid Base64.", ex);
        }
        if (catalogBytes.Length == 0
            || catalogBytes.Length > ProviderAsnEndpointCatalogDocument.MaximumDocumentBytes)
        {
            throw new InvalidOperationException("Provider catalog archive contains an invalid catalog payload size.");
        }

        var sha256 = Convert.ToHexString(SHA256.HashData(catalogBytes)).ToLowerInvariant();
        if (!string.Equals(bundle.CatalogFileSha256, sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Provider catalog archive SHA-256 does not match the embedded catalog bytes.");
        }

        var catalog = JsonProviderAsnEndpointCatalog.FromBytes(catalogBytes);
        if (!string.Equals(catalog.Document.Id.Trim(), bundle.Registry.CatalogId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Archive catalog ID '{catalog.Document.Id}' does not match registry catalog ID '{bundle.Registry.CatalogId}'.");
        }

        var revisionIds = bundle.Revisions.Select(x => x.Id).ToHashSet(StringComparer.Ordinal);
        if (bundle.RemoteProvenance.Any(x => !revisionIds.Contains(x.RevisionId)))
        {
            throw new InvalidOperationException(
                "Provider catalog archive contains remote provenance for a revision not included in the archive.");
        }

        var signatureValidation = ProviderAsnCatalogArchiveSignatureService.Verify(
            bundle,
            options.ArchiveSignatureTrust);
        if (!signatureValidation.PolicySatisfied)
        {
            throw new InvalidOperationException(
                $"Provider catalog archive signature policy was not satisfied: {signatureValidation.Status}.");
        }

        var audit = catalog.Audit(now ?? DateTimeOffset.UtcNow, options.AuditPolicy);
        var warnings = new List<string>();
        if (signatureValidation.Present && !signatureValidation.Attempted)
        {
            warnings.Add(signatureValidation.Status);
        }
        else if (signatureValidation.Present && !signatureValidation.Valid)
        {
            warnings.Add(signatureValidation.Status);
        }
        var registryHashMatches = bundle.Registry.Sha256.IsNullOrEmpty()
                                  || string.Equals(bundle.Registry.Sha256, sha256, StringComparison.OrdinalIgnoreCase);
        if (!registryHashMatches)
        {
            warnings.Add("registry-sha-differs-from-archived-payload");
        }
        if (!audit.Valid)
        {
            warnings.Add("catalog-audit-invalid");
        }
        else if (audit.FreshnessKnown && audit.Stale)
        {
            warnings.Add("catalog-metadata-stale");
        }

        return new ProviderAsnCatalogArchiveInspection
        {
            SourcePath = path,
            FormatVersion = bundle.FormatVersion,
            CreatedAt = bundle.CreatedAt,
            RegistryId = bundle.Registry.Id,
            CatalogId = catalog.Document.Id.Trim(),
            CatalogVersion = catalog.Document.Version.Trim(),
            CatalogFileName = bundle.CatalogFileName,
            CatalogFileSha256 = sha256,
            RegistryShaMatchesPayload = registryHashMatches,
            CatalogBytes = catalogBytes.Length,
            CatalogEntries = catalog.Document.Entries.Count,
            Revisions = bundle.Revisions.Count,
            RemoteProvenanceRecords = bundle.RemoteProvenance.Count,
            ArchiveSignatureValidation = signatureValidation,
            CatalogAudit = audit,
            Warnings = warnings,
        };
    }

    private static void ValidateOptions(ProviderAsnCatalogArchiveInspectionOptions options)
    {
        if (options.MaximumArchiveBytes is < 1024 or > 256 * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(options.MaximumArchiveBytes));
        }
        ArgumentNullException.ThrowIfNull(options.AuditPolicy);
        ArgumentNullException.ThrowIfNull(options.ArchiveSignatureTrust);
        if (options.ArchiveSignatureTrust.Required
            && (options.ArchiveSignatureTrust.TrustedKeyId.IsNullOrEmpty()
                || options.ArchiveSignatureTrust.TrustedPublicKeySpkiBase64.IsNullOrEmpty()))
        {
            throw new ArgumentException(
                "Required archive signature verification needs a trusted key ID and public key.",
                nameof(options.ArchiveSignatureTrust));
        }
        if (options.AuditPolicy.MaximumAge <= TimeSpan.Zero
            || options.AuditPolicy.MaximumAge > TimeSpan.FromDays(3650))
        {
            throw new ArgumentOutOfRangeException(nameof(options.AuditPolicy.MaximumAge));
        }
    }
}
