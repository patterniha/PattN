using System.Security.Cryptography;
using ServiceLib.Discovery.Models;
using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

public static class ProviderAsnCatalogRemoteConfigurationFingerprint
{
    public static string FromItem(ProviderAsnCatalogRemoteSourceItem? item)
    {
        if (item is null)
        {
            return string.Empty;
        }
        if (!Enum.IsDefined(typeof(ProviderAsnCatalogSignaturePolicy), item.SignaturePolicy))
        {
            throw new InvalidOperationException("Stored provider catalog signature policy is invalid.");
        }

        return Compute(new ProviderAsnCatalogRemoteSourceConfig
        {
            Uri = item.Uri,
            SignatureUri = item.SignatureUri,
            SignaturePolicy = (ProviderAsnCatalogSignaturePolicy)item.SignaturePolicy,
            TrustedKeyId = item.TrustedKeyId,
            TrustedPublicKeySpkiBase64 = item.TrustedPublicKeySpkiBase64,
            TlsSpkiPinsSha256 = ProviderAsnCatalogTransportPinning.DeserializePins(item.TlsSpkiPinsSha256Json),
        });
    }

    public static string Compute(ProviderAsnCatalogRemoteSourceConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        ProviderAsnCatalogSignatureVerifier.ValidateTrustedKey(config);
        var pins = ProviderAsnCatalogTransportPinning.NormalizePins(config.TlsSpkiPinsSha256);

        var normalized = new ProviderAsnCatalogRemoteSourceConfig
        {
            Uri = NormalizeHttps(config.Uri, nameof(config.Uri)),
            SignatureUri = config.SignatureUri.IsNullOrEmpty()
                ? string.Empty
                : NormalizeHttps(config.SignatureUri, nameof(config.SignatureUri)),
            SignaturePolicy = config.SignaturePolicy,
            TrustedKeyId = config.TrustedKeyId.Trim(),
            TrustedPublicKeySpkiBase64 = config.TrustedPublicKeySpkiBase64.Trim(),
            TlsSpkiPinsSha256 = pins,
        };

        var bytes = Encoding.UTF8.GetBytes(JsonUtils.Serialize(normalized, false));
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    private static string NormalizeHttps(string value, string parameter)
    {
        if (!Uri.TryCreate(value?.Trim(), UriKind.Absolute, out var uri)
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || uri.Host.IsNullOrEmpty()
            || !uri.UserInfo.IsNullOrEmpty()
            || !uri.Fragment.IsNullOrEmpty())
        {
            throw new ArgumentException(
                "Remote provider catalog source URI must be an absolute HTTPS URI without credentials or fragments.",
                parameter);
        }
        return uri.AbsoluteUri;
    }
}
