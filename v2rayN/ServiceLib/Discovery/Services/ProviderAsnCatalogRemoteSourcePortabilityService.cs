using System.Security.Cryptography;
using ServiceLib.Discovery.Models;
using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Export/import of remote catalog source configuration. Bundles intentionally contain only public trust
/// material and source URIs. Preview is read-only; apply only updates source/trust configuration and performs no fetch.
/// </summary>
public sealed class ProviderAsnCatalogRemoteSourcePortabilityService(
    ProviderAsnCatalogRegistryService catalogs,
    IProviderAsnCatalogRemoteSourceStore sources,
    ProviderAsnCatalogRemoteUpdateService remoteUpdates)
{
    public const int MaximumPortableBundleBytes = 256 * 1024;
    public async Task<ProviderAsnCatalogRemoteSourcePortableBundle> ExportAsync(
        string registryId,
        DateTimeOffset? now = null,
        CancellationToken cancellationToken = default)
    {
        var registry = await catalogs.GetAsync(registryId, cancellationToken);
        if (!registry.Registered)
        {
            throw new InvalidOperationException("Remote source configuration can be exported only for a registered catalog.");
        }

        var item = await sources.GetAsync(registryId, cancellationToken)
            ?? throw new InvalidOperationException("Registered catalog has no remote source configuration.");

        var config = ToConfig(item);
        ValidatePortableConfig(config);
        return new ProviderAsnCatalogRemoteSourcePortableBundle
        {
            ExportedAt = now ?? DateTimeOffset.UtcNow,
            CatalogId = registry.CatalogId,
            CatalogVersion = registry.CatalogVersion,
            DisplayName = registry.DisplayName,
            Source = config,
            TrustedPublicKeySha256 = PublicKeyFingerprint(config),
        };
    }

    public async Task SaveAsync(
        ProviderAsnCatalogRemoteSourcePortableBundle bundle,
        string destinationPath,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        ValidateBundle(bundle);

        var path = Path.GetFullPath(destinationPath);
        var directory = Path.GetDirectoryName(path)
            ?? throw new InvalidOperationException("Remote-source bundle destination has no parent directory.");
        Directory.CreateDirectory(directory);

        var payload = JsonUtils.Serialize(bundle, true);
        var bytes = Encoding.UTF8.GetBytes(payload);
        if (bytes.Length > MaximumPortableBundleBytes)
        {
            throw new InvalidOperationException(
                $"Remote-source bundle exceeds {MaximumPortableBundleBytes} bytes.");
        }

        await DurableAtomicFile.WriteAsync(
            path,
            bytes,
            cancellationToken: cancellationToken);
    }

    public async Task<ProviderAsnCatalogRemoteSourcePortableBundle> LoadAsync(
        string sourcePath,
        CancellationToken cancellationToken = default)
    {
        var path = Path.GetFullPath(sourcePath);
        var info = new FileInfo(path);
        if (!info.Exists)
        {
            throw new FileNotFoundException("Remote-source bundle was not found.", path);
        }
        if (info.Length <= 0 || info.Length > MaximumPortableBundleBytes)
        {
            throw new InvalidOperationException(
                $"Remote-source bundle size {info.Length} is outside the allowed range.");
        }

        var json = await File.ReadAllTextAsync(path, cancellationToken);
        var bundle = JsonUtils.Deserialize<ProviderAsnCatalogRemoteSourcePortableBundle>(json)
            ?? throw new InvalidOperationException("Remote-source bundle JSON could not be decoded.");
        ValidateBundle(bundle);
        return bundle;
    }

    public async Task<ProviderAsnCatalogRemoteSourceImportPreview> PrepareImportAsync(
        string targetRegistryId,
        ProviderAsnCatalogRemoteSourcePortableBundle bundle,
        DateTimeOffset? now = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        ValidateBundle(bundle);

        var registry = await catalogs.GetAsync(targetRegistryId, cancellationToken);
        if (!registry.Registered)
        {
            throw new InvalidOperationException("Remote source configuration can be imported only into a registered catalog.");
        }
        if (!string.Equals(bundle.CatalogId.Trim(), registry.CatalogId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Remote-source bundle catalog ID '{bundle.CatalogId}' does not match target catalog ID '{registry.CatalogId}'.");
        }

        var fingerprint = PublicKeyFingerprint(bundle.Source);

        var existing = await sources.GetAsync(targetRegistryId, cancellationToken);
        var warnings = new List<string>();
        if (!bundle.CatalogVersion.IsNullOrEmpty()
            && !string.Equals(bundle.CatalogVersion, registry.CatalogVersion, StringComparison.Ordinal))
        {
            warnings.Add("bundle-catalog-version-differs-from-current");
        }

        return new ProviderAsnCatalogRemoteSourceImportPreview
        {
            TargetRegistryId = targetRegistryId,
            CatalogId = registry.CatalogId,
            CurrentCatalogVersion = registry.CatalogVersion,
            BundleCatalogVersion = bundle.CatalogVersion,
            DisplayName = bundle.DisplayName,
            Source = bundle.Source,
            TrustedPublicKeySha256 = fingerprint,
            ExistingConfigurationFingerprint = ConfigurationFingerprint(existing),
            ImportedConfigurationFingerprint = ConfigurationFingerprint(bundle.Source),
            PreparedAt = now ?? DateTimeOffset.UtcNow,
            Warnings = warnings,
        };
    }

    public async Task<ProviderAsnCatalogRemoteSourceView> ApplyImportAsync(
        ProviderAsnCatalogRemoteSourceImportPreview preview,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(preview);
        var registry = await catalogs.GetAsync(preview.TargetRegistryId, cancellationToken);
        if (!registry.Registered
            || !string.Equals(registry.CatalogId, preview.CatalogId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Target catalog changed after remote-source import preview; prepare a fresh preview.");
        }

        var current = await sources.GetAsync(preview.TargetRegistryId, cancellationToken);
        if (!string.Equals(
                ConfigurationFingerprint(current),
                preview.ExistingConfigurationFingerprint,
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Remote source configuration changed after import preview; prepare a fresh preview before apply.");
        }

        if (!string.Equals(
                ConfigurationFingerprint(preview.Source),
                preview.ImportedConfigurationFingerprint,
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Remote-source import preview content changed after preparation.");
        }

        return await remoteUpdates.ConfigureAsync(
            preview.TargetRegistryId,
            preview.Source,
            cancellationToken: cancellationToken,
            changeContext: new ProviderAsnCatalogRemoteSourceChangeContext
            {
                Reason = "portable-import",
            });
    }

    private static ProviderAsnCatalogRemoteSourceConfig ToConfig(ProviderAsnCatalogRemoteSourceItem item)
    {
        if (!Enum.IsDefined(typeof(ProviderAsnCatalogSignaturePolicy), item.SignaturePolicy))
        {
            throw new InvalidOperationException("Stored provider catalog signature policy is invalid.");
        }

        return new ProviderAsnCatalogRemoteSourceConfig
        {
            Uri = item.Uri,
            SignatureUri = item.SignatureUri,
            SignaturePolicy = (ProviderAsnCatalogSignaturePolicy)item.SignaturePolicy,
            TrustedKeyId = item.TrustedKeyId,
            TrustedPublicKeySpkiBase64 = item.TrustedPublicKeySpkiBase64,
            TlsSpkiPinsSha256 = ProviderAsnCatalogTransportPinning.DeserializePins(item.TlsSpkiPinsSha256Json),
        };
    }

    private static void ValidateBundle(ProviderAsnCatalogRemoteSourcePortableBundle bundle)
    {
        if (bundle.FormatVersion != 1)
        {
            throw new InvalidOperationException(
                $"Unsupported remote-source bundle format version {bundle.FormatVersion}; expected 1.");
        }
        if (bundle.CatalogId.IsNullOrEmpty())
        {
            throw new InvalidOperationException("Remote-source bundle catalog ID is required.");
        }
        ValidatePortableConfig(bundle.Source);

        var fingerprint = PublicKeyFingerprint(bundle.Source);
        if (!bundle.TrustedPublicKeySha256.IsNullOrEmpty()
            && !string.Equals(bundle.TrustedPublicKeySha256, fingerprint, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Remote-source bundle public-key fingerprint does not match its public key.");
        }
    }

    private static void ValidatePortableConfig(ProviderAsnCatalogRemoteSourceConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        ValidateHttpsUri(config.Uri, nameof(config.Uri));
        if (!config.SignatureUri.IsNullOrEmpty())
        {
            ValidateHttpsUri(config.SignatureUri, nameof(config.SignatureUri));
        }
        ProviderAsnCatalogSignatureVerifier.ValidateTrustedKey(config);
        _ = ProviderAsnCatalogTransportPinning.NormalizePins(config.TlsSpkiPinsSha256);

        if (!config.TrustedPublicKeySpkiBase64.IsNullOrEmpty())
        {
            try
            {
                _ = Convert.FromBase64String(config.TrustedPublicKeySpkiBase64);
            }
            catch (FormatException ex)
            {
                throw new InvalidOperationException("Portable remote-source public key is not valid Base64.", ex);
            }
        }
    }

    private static Uri ValidateHttpsUri(string value, string parameter)
    {
        if (!Uri.TryCreate(value?.Trim(), UriKind.Absolute, out var uri)
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || uri.Host.IsNullOrEmpty()
            || !uri.UserInfo.IsNullOrEmpty()
            || !uri.Fragment.IsNullOrEmpty())
        {
            throw new ArgumentException("Remote provider catalog source URI must be an absolute HTTPS URI without credentials or fragments.", parameter);
        }
        return uri;
    }

    private static string PublicKeyFingerprint(ProviderAsnCatalogRemoteSourceConfig config)
    {
        if (config.TrustedPublicKeySpkiBase64.IsNullOrEmpty())
        {
            return string.Empty;
        }
        var bytes = Convert.FromBase64String(config.TrustedPublicKeySpkiBase64);
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    private static string ConfigurationFingerprint(ProviderAsnCatalogRemoteSourceItem? item)
        => item is null ? string.Empty : ConfigurationFingerprint(ToConfig(item));

    private static string ConfigurationFingerprint(ProviderAsnCatalogRemoteSourceConfig config)
    {
        var normalized = new ProviderAsnCatalogRemoteSourceConfig
        {
            Uri = ValidateHttpsUri(config.Uri, nameof(config.Uri)).AbsoluteUri,
            SignatureUri = config.SignatureUri.IsNullOrEmpty()
                ? string.Empty
                : ValidateHttpsUri(config.SignatureUri, nameof(config.SignatureUri)).AbsoluteUri,
            SignaturePolicy = config.SignaturePolicy,
            TrustedKeyId = config.TrustedKeyId.Trim(),
            TrustedPublicKeySpkiBase64 = config.TrustedPublicKeySpkiBase64.Trim(),
            TlsSpkiPinsSha256 = ProviderAsnCatalogTransportPinning.NormalizePins(config.TlsSpkiPinsSha256),
        };
        var bytes = Encoding.UTF8.GetBytes(JsonUtils.Serialize(normalized, false));
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }
}
