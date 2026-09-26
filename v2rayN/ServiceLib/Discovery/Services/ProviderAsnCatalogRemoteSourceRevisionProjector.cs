using System.Security.Cryptography;
using ServiceLib.Discovery.Models;
using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

public static class ProviderAsnCatalogRemoteSourceRevisionProjector
{
    public static ProviderAsnCatalogRemoteSourceRevisionItem Create(
        string registryId,
        ProviderAsnCatalogRemoteSourceItem? before,
        ProviderAsnCatalogRemoteSourceItem? after,
        ProviderAsnCatalogRemoteSourceChangeContext? context,
        DateTimeOffset changedAt)
    {
        var beforePins = Pins(before);
        var afterPins = Pins(after);
        var added = afterPins.Except(beforePins, StringComparer.Ordinal).OrderBy(x => x, StringComparer.Ordinal).ToArray();
        var removed = beforePins.Except(afterPins, StringComparer.Ordinal).OrderBy(x => x, StringComparer.Ordinal).ToArray();

        return new ProviderAsnCatalogRemoteSourceRevisionItem
        {
            Id = context?.RevisionId.NullIfEmpty() ?? Utils.GetGuid(false),
            RegistryId = registryId,
            ChangeReason = NormalizeReason(context?.Reason),
            BeforeFingerprint = ProviderAsnCatalogRemoteConfigurationFingerprint.FromItem(before),
            AfterFingerprint = ProviderAsnCatalogRemoteConfigurationFingerprint.FromItem(after),
            BeforeUri = before?.Uri ?? string.Empty,
            AfterUri = after?.Uri ?? string.Empty,
            BeforeSignatureUri = before?.SignatureUri ?? string.Empty,
            AfterSignatureUri = after?.SignatureUri ?? string.Empty,
            BeforeSignaturePolicy = before?.SignaturePolicy ?? 0,
            AfterSignaturePolicy = after?.SignaturePolicy ?? 0,
            BeforeTrustedKeyId = before?.TrustedKeyId ?? string.Empty,
            AfterTrustedKeyId = after?.TrustedKeyId ?? string.Empty,
            BeforeTrustedPublicKeySha256 = PublicKeyFingerprint(before?.TrustedPublicKeySpkiBase64),
            AfterTrustedPublicKeySha256 = PublicKeyFingerprint(after?.TrustedPublicKeySpkiBase64),
            BeforeTlsSpkiPinsSha256Json = ProviderAsnCatalogTransportPinning.SerializePins(beforePins),
            AfterTlsSpkiPinsSha256Json = ProviderAsnCatalogTransportPinning.SerializePins(afterPins),
            AddedTlsSpkiPinsSha256Json = ProviderAsnCatalogTransportPinning.SerializePins(added),
            RemovedTlsSpkiPinsSha256Json = ProviderAsnCatalogTransportPinning.SerializePins(removed),
            ChangedAtUnixMs = changedAt.ToUnixTimeMilliseconds(),
        };
    }

    public static ProviderAsnCatalogRemoteSourceRevisionView Project(
        ProviderAsnCatalogRemoteSourceRevisionItem item)
    {
        ArgumentNullException.ThrowIfNull(item);
        return new ProviderAsnCatalogRemoteSourceRevisionView
        {
            Id = item.Id,
            RegistryId = item.RegistryId,
            ChangeReason = item.ChangeReason,
            BeforeFingerprint = item.BeforeFingerprint,
            AfterFingerprint = item.AfterFingerprint,
            BeforeUri = item.BeforeUri,
            AfterUri = item.AfterUri,
            BeforeSignatureUri = item.BeforeSignatureUri,
            AfterSignatureUri = item.AfterSignatureUri,
            BeforeSignaturePolicy = Policy(item.BeforeSignaturePolicy),
            AfterSignaturePolicy = Policy(item.AfterSignaturePolicy),
            BeforeTrustedKeyId = item.BeforeTrustedKeyId,
            AfterTrustedKeyId = item.AfterTrustedKeyId,
            BeforeTrustedPublicKeySha256 = item.BeforeTrustedPublicKeySha256,
            AfterTrustedPublicKeySha256 = item.AfterTrustedPublicKeySha256,
            BeforeTlsSpkiPinsSha256 = Pins(item.BeforeTlsSpkiPinsSha256Json),
            AfterTlsSpkiPinsSha256 = Pins(item.AfterTlsSpkiPinsSha256Json),
            AddedTlsSpkiPinsSha256 = Pins(item.AddedTlsSpkiPinsSha256Json),
            RemovedTlsSpkiPinsSha256 = Pins(item.RemovedTlsSpkiPinsSha256Json),
            ChangedAt = DateTimeOffset.FromUnixTimeMilliseconds(item.ChangedAtUnixMs),
        };
    }

    public static ProviderAsnCatalogRemoteSourceItem Clone(
        ProviderAsnCatalogRemoteSourceItem item)
    {
        ArgumentNullException.ThrowIfNull(item);
        return new ProviderAsnCatalogRemoteSourceItem
        {
            RegistryId = item.RegistryId,
            Uri = item.Uri,
            SignatureUri = item.SignatureUri,
            SignaturePolicy = item.SignaturePolicy,
            TrustedKeyId = item.TrustedKeyId,
            TrustedPublicKeySpkiBase64 = item.TrustedPublicKeySpkiBase64,
            TlsSpkiPinsSha256Json = item.TlsSpkiPinsSha256Json,
            ETag = item.ETag,
            LastModifiedUnixMs = item.LastModifiedUnixMs,
            RemoteContentSha256 = item.RemoteContentSha256,
            ConfigurationUpdatedAtUnixMs = item.ConfigurationUpdatedAtUnixMs,
            CacheUpdatedAtUnixMs = item.CacheUpdatedAtUnixMs,
            LastCheckedAtUnixMs = item.LastCheckedAtUnixMs,
            LastFetchedAtUnixMs = item.LastFetchedAtUnixMs,
            LastSignatureValid = item.LastSignatureValid,
            LastSignatureStatus = item.LastSignatureStatus,
            LastSignatureKeyId = item.LastSignatureKeyId,
            LastSignatureCatalogSha256 = item.LastSignatureCatalogSha256,
            LastSignatureSignedAtUnixMs = item.LastSignatureSignedAtUnixMs,
        };
    }

    private static IReadOnlyList<string> Pins(ProviderAsnCatalogRemoteSourceItem? item)
        => item is null
            ? []
            : ProviderAsnCatalogTransportPinning.DeserializePins(item.TlsSpkiPinsSha256Json);

    private static IReadOnlyList<string> Pins(string json)
        => ProviderAsnCatalogTransportPinning.DeserializePins(json);

    private static ProviderAsnCatalogSignaturePolicy Policy(int value)
    {
        if (!Enum.IsDefined(typeof(ProviderAsnCatalogSignaturePolicy), value))
        {
            throw new InvalidOperationException(
                "Stored provider catalog source-revision signature policy is invalid.");
        }
        return (ProviderAsnCatalogSignaturePolicy)value;
    }

    private static string PublicKeyFingerprint(string? spkiBase64)
    {
        if (spkiBase64.IsNullOrEmpty())
        {
            return string.Empty;
        }
        try
        {
            return Convert.ToHexString(
                    SHA256.HashData(Convert.FromBase64String(spkiBase64!)))
                .ToLowerInvariant();
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                "Stored provider catalog source-revision trusted public key is invalid.",
                ex);
        }
    }

    private static string NormalizeReason(string? value)
    {
        var reason = value?.Trim().ToLowerInvariant() ?? "configure";
        if (reason.IsNullOrEmpty())
        {
            reason = "configure";
        }
        if (reason.Length > 80)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "Remote source revision reason may not exceed 80 characters.");
        }
        return reason;
    }
}
