using ServiceLib.Discovery.Models;
using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

public static class ProviderAsnCatalogRemoteProvenanceProjector
{
    public static ProviderAsnCatalogRemoteApplyProvenanceView Project(
        ProviderAsnCatalogRemoteApplyProvenanceItem item)
    {
        ArgumentNullException.ThrowIfNull(item);
        if (!Enum.IsDefined(typeof(ProviderAsnCatalogSignaturePolicy), item.SignaturePolicy))
        {
            throw new InvalidOperationException(
                "Stored provider catalog provenance signature policy is invalid.");
        }
        var policy = (ProviderAsnCatalogSignaturePolicy)item.SignaturePolicy;

        return new ProviderAsnCatalogRemoteApplyProvenanceView
        {
            RevisionId = item.RevisionId,
            RegistryId = item.RegistryId,
            SourceUri = item.SourceUri,
            SourceFinalUri = item.SourceFinalUri,
            SignatureUri = item.SignatureUri,
            SignatureFinalUri = item.SignatureFinalUri,
            SignaturePolicy = policy,
            TrustedKeyId = item.TrustedKeyId,
            TlsSpkiPinsSha256 = ProviderAsnCatalogTransportPinning.DeserializePins(item.TlsSpkiPinsSha256Json),
            ServerNotModified = item.ServerNotModified,
            ETag = item.ETag,
            LastModified = FromUnixMs(item.LastModifiedUnixMs),
            RemoteContentSha256 = item.RemoteContentSha256,
            SignatureValidation = new ProviderAsnCatalogSignatureValidation
            {
                Policy = policy,
                Attempted = item.SignatureAttempted,
                Valid = item.SignatureValid,
                PolicySatisfied = item.SignaturePolicySatisfied,
                Status = item.SignatureStatus,
                KeyId = item.SignatureKeyId,
                CatalogSha256 = item.SignatureCatalogSha256,
                SignedAt = FromUnixMs(item.SignatureSignedAtUnixMs),
                FinalUri = item.SignatureFinalUri,
            },
            CheckedAt = DateTimeOffset.FromUnixTimeMilliseconds(item.CheckedAtUnixMs),
            AppliedAt = DateTimeOffset.FromUnixTimeMilliseconds(item.AppliedAtUnixMs),
        };
    }

    private static DateTimeOffset? FromUnixMs(long? value)
        => value is null ? null : DateTimeOffset.FromUnixTimeMilliseconds(value.Value);
}
