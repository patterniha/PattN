using ServiceLib.Discovery.Models;
using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Preview/apply workflow for HTTPS SPKI pin rotation. It performs no remote fetch.
/// Safe rotation requires overlap between current and proposed non-empty pin sets, enabling
/// add-new -> validate transport separately -> retire-old as two explicit trust changes.
/// </summary>
public sealed class ProviderAsnCatalogTlsPinRotationService(
    ProviderAsnCatalogRegistryService catalogs,
    IProviderAsnCatalogRemoteSourceStore sources,
    ProviderAsnCatalogRemoteUpdateService remoteUpdates,
    IProviderAsnCatalogRemoteSourceRevisionStore? revisionStore = null)
{
    public async Task<ProviderAsnCatalogTlsPinRotationPreview> PrepareAsync(
        string registryId,
        IEnumerable<string>? proposedPins,
        ProviderAsnCatalogTlsPinRotationOptions? options = null,
        DateTimeOffset? now = null,
        CancellationToken cancellationToken = default)
    {
        options ??= new ProviderAsnCatalogTlsPinRotationOptions();
        var registry = await catalogs.GetAsync(registryId, cancellationToken);
        if (!registry.Registered)
        {
            throw new InvalidOperationException("TLS pin rotation is available only for registered catalogs.");
        }

        var item = await sources.GetAsync(registryId, cancellationToken)
            ?? throw new InvalidOperationException("No remote source is configured for this provider catalog.");
        var current = ToConfig(item);
        var existingPins = ProviderAsnCatalogTransportPinning.NormalizePins(current.TlsSpkiPinsSha256);
        var normalizedProposed = ProviderAsnCatalogTransportPinning.NormalizePins(proposedPins);

        if (existingPins.SequenceEqual(normalizedProposed))
        {
            throw new InvalidOperationException("TLS SPKI pin rotation contains no effective change.");
        }

        ValidateRotation(existingPins, normalizedProposed, options.AllowUnpinning);

        var proposed = current with
        {
            TlsSpkiPinsSha256 = normalizedProposed,
        };
        var warnings = new List<string>();
        if (existingPins.Count == 0 && normalizedProposed.Count > 0)
        {
            warnings.Add("pinning-enabled");
        }
        if (existingPins.Count > 0 && normalizedProposed.Count == 0)
        {
            warnings.Add("pinning-disabled-explicitly");
        }
        if (existingPins.Count > 0
            && normalizedProposed.Count > existingPins.Count
            && existingPins.All(x => normalizedProposed.Contains(x, StringComparer.Ordinal)))
        {
            warnings.Add("overlap-phase-added-new-pin");
        }
        if (normalizedProposed.Count > 0
            && normalizedProposed.Count < existingPins.Count
            && normalizedProposed.Any(x => existingPins.Contains(x, StringComparer.Ordinal)))
        {
            warnings.Add("overlap-phase-retired-old-pin");
        }

        return new ProviderAsnCatalogTlsPinRotationPreview
        {
            RegistryId = registryId,
            CatalogId = registry.CatalogId,
            ExistingPinsSha256 = existingPins,
            ProposedPinsSha256 = normalizedProposed,
            ProposedSource = proposed,
            ExistingConfigurationFingerprint =
                ProviderAsnCatalogRemoteConfigurationFingerprint.FromItem(item),
            ProposedConfigurationFingerprint =
                ProviderAsnCatalogRemoteConfigurationFingerprint.Compute(proposed),
            RemovesAllPins = existingPins.Count > 0 && normalizedProposed.Count == 0,
            PreparedAt = now ?? DateTimeOffset.UtcNow,
            Warnings = warnings,
        };
    }

    public async Task<ProviderAsnCatalogTlsPinRotationReceipt> ApplyAsync(
        ProviderAsnCatalogTlsPinRotationPreview preview,
        ProviderAsnCatalogTlsPinRotationOptions? options = null,
        DateTimeOffset? now = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(preview);
        options ??= new ProviderAsnCatalogTlsPinRotationOptions();

        var registry = await catalogs.GetAsync(preview.RegistryId, cancellationToken);
        if (!registry.Registered
            || !string.Equals(registry.CatalogId, preview.CatalogId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Target catalog changed after TLS pin rotation preview; prepare a fresh preview.");
        }

        var currentItem = await sources.GetAsync(preview.RegistryId, cancellationToken)
            ?? throw new InvalidOperationException("Remote source was removed after TLS pin rotation preview.");
        var currentFingerprint = ProviderAsnCatalogRemoteConfigurationFingerprint.FromItem(currentItem);
        if (!string.Equals(
                currentFingerprint,
                preview.ExistingConfigurationFingerprint,
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Remote source trust/configuration changed after TLS pin rotation preview; prepare a fresh preview.");
        }

        var proposedPins = ProviderAsnCatalogTransportPinning.NormalizePins(
            preview.ProposedSource.TlsSpkiPinsSha256);
        if (!proposedPins.SequenceEqual(preview.ProposedPinsSha256))
        {
            throw new InvalidOperationException("TLS pin rotation preview content changed after preparation.");
        }

        var proposedFingerprint =
            ProviderAsnCatalogRemoteConfigurationFingerprint.Compute(preview.ProposedSource);
        if (!string.Equals(
                proposedFingerprint,
                preview.ProposedConfigurationFingerprint,
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "TLS pin rotation preview fingerprint no longer matches its proposed configuration.");
        }

        var current = ToConfig(currentItem);
        var existingPins = ProviderAsnCatalogTransportPinning.NormalizePins(current.TlsSpkiPinsSha256);
        ValidateRotation(existingPins, proposedPins, options.AllowUnpinning);

        var revisionId = Utils.GetGuid(false);
        var appliedAt = now ?? DateTimeOffset.UtcNow;
        var source = await remoteUpdates.ConfigureAsync(
            preview.RegistryId,
            preview.ProposedSource,
            appliedAt,
            cancellationToken,
            new ProviderAsnCatalogRemoteSourceChangeContext
            {
                RevisionId = revisionId,
                Reason = "tls-pin-rotation",
            });

        var revisionRecorded = false;
        if (revisionStore is not null)
        {
            try
            {
                revisionRecorded = await revisionStore.GetAsync(revisionId, CancellationToken.None) is not null;
            }
            catch (Exception ex)
            {
                Logging.SaveLog($"Provider catalog TLS pin rotation revision lookup failed: {ex}");
            }
        }

        return new ProviderAsnCatalogTlsPinRotationReceipt
        {
            RevisionId = revisionId,
            RegistryId = preview.RegistryId,
            BeforePinsSha256 = existingPins,
            AfterPinsSha256 = proposedPins,
            AppliedAt = appliedAt,
            RevisionRecorded = revisionRecorded,
            Source = source,
        };
    }

    private static void ValidateRotation(
        IReadOnlyList<string> existingPins,
        IReadOnlyList<string> proposedPins,
        bool allowUnpinning)
    {
        if (existingPins.Count > 0 && proposedPins.Count == 0 && !allowUnpinning)
        {
            throw new InvalidOperationException(
                "Removing all TLS SPKI pins requires explicit AllowUnpinning=true.");
        }

        if (existingPins.Count > 0
            && proposedPins.Count > 0
            && !existingPins.Any(x => proposedPins.Contains(x, StringComparer.Ordinal)))
        {
            throw new InvalidOperationException(
                "Safe TLS pin rotation requires at least one overlapping current pin. Add the new pin first, validate transport, then retire the old pin.");
        }
    }

    private static ProviderAsnCatalogRemoteSourceConfig ToConfig(
        ProviderAsnCatalogRemoteSourceItem item)
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
            TlsSpkiPinsSha256 = ProviderAsnCatalogTransportPinning.DeserializePins(
                item.TlsSpkiPinsSha256Json),
        };
    }
}
