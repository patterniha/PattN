using ServiceLib.Discovery.Models;
using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Explicit user-triggered remote catalog orchestration. Fetching may update remote cache metadata, but catalog
/// file mutation still goes exclusively through ProviderAsnCatalogRegistryService Prepare/Apply.
/// </summary>
public sealed class ProviderAsnCatalogRemoteUpdateService(
    ProviderAsnCatalogRegistryService catalogs,
    IProviderAsnCatalogRemoteSourceStore sources,
    IProviderAsnCatalogRemoteTransport? transport = null,
    IProviderAsnCatalogRemoteApplyProvenanceStore? provenanceStore = null,
    IProviderAsnCatalogRemoteSourceRevisionStore? sourceRevisionStore = null)
{
    private const int MaximumSignatureEnvelopeBytes = 64 * 1024;
    private readonly IProviderAsnCatalogRemoteTransport _transport =
        transport ?? new HttpProviderAsnCatalogRemoteTransport();

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, SemaphoreSlim> RegistryOperationLocks =
        new(StringComparer.Ordinal);

    public Task<ProviderAsnCatalogRemoteSourceView> ConfigureAsync(
        string registryId,
        ProviderAsnCatalogRemoteSourceConfig config,
        DateTimeOffset? now = null,
        CancellationToken cancellationToken = default,
        ProviderAsnCatalogRemoteSourceChangeContext? changeContext = null)
        => WithRegistryLockAsync(
            registryId,
            cancellationToken,
            () => ConfigureCoreAsync(registryId, config, now, cancellationToken, changeContext));

    public Task<ProviderAsnCatalogRemoteSourceView?> GetAsync(
        string registryId,
        CancellationToken cancellationToken = default)
        => WithRegistryLockAsync(
            registryId,
            cancellationToken,
            () => GetCoreAsync(registryId, cancellationToken));

    public Task RemoveAsync(
        string registryId,
        CancellationToken cancellationToken = default)
        => WithRegistryLockAsync(
            registryId,
            cancellationToken,
            () => RemoveCoreAsync(registryId, cancellationToken));

    public Task<ProviderAsnCatalogRemoteFetchPreview> FetchPreviewAsync(
        string registryId,
        DateTimeOffset? now = null,
        CancellationToken cancellationToken = default)
        => WithRegistryLockAsync(
            registryId,
            cancellationToken,
            () => FetchPreviewCoreAsync(registryId, now, cancellationToken));

    public Task<ProviderAsnCatalogRevisionView> ApplyAsync(
        ProviderAsnCatalogRemoteFetchPreview preview,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(preview);
        return WithRegistryLockAsync(
            preview.RegistryId,
            cancellationToken,
            () => ApplyCoreAsync(preview, cancellationToken));
    }

    private async Task<ProviderAsnCatalogRemoteSourceView> ConfigureCoreAsync(
        string registryId,
        ProviderAsnCatalogRemoteSourceConfig config,
        DateTimeOffset? now = null,
        CancellationToken cancellationToken = default,
        ProviderAsnCatalogRemoteSourceChangeContext? changeContext = null)
    {
        ArgumentNullException.ThrowIfNull(config);
        var registry = await catalogs.GetAsync(registryId, cancellationToken);
        if (!registry.Registered)
        {
            throw new InvalidOperationException("Remote sources can be configured only for registered catalogs.");
        }
        await using var processLease = await AcquireRemoteOperationLeaseAsync(
            registry.FilePath,
            cancellationToken);

        var catalogUri = ValidateHttpsUri(config.Uri, nameof(config.Uri));
        Uri? signatureUri = null;
        if (!config.SignatureUri.IsNullOrEmpty())
        {
            signatureUri = ValidateHttpsUri(config.SignatureUri, nameof(config.SignatureUri));
        }
        ProviderAsnCatalogSignatureVerifier.ValidateTrustedKey(config);
        var tlsPins = ProviderAsnCatalogTransportPinning.NormalizePins(config.TlsSpkiPinsSha256);
        if (tlsPins.Count > 0
            && signatureUri is not null
            && !SameAuthority(catalogUri, signatureUri))
        {
            throw new InvalidOperationException(
                "A single TLS SPKI pin set cannot be shared across different catalog and signature authorities. " +
                "Use the same HTTPS authority for both pinned resources, or remove transport pins and rely on ordinary TLS plus the detached-signature trust key.");
        }
        var tlsPinsJson = ProviderAsnCatalogTransportPinning.SerializePins(tlsPins);

        var observedAt = now ?? DateTimeOffset.UtcNow;
        var existing = await sources.GetAsync(registryId, cancellationToken);
        var beforeRevision = existing is null
            ? null
            : ProviderAsnCatalogRemoteSourceRevisionProjector.Clone(existing);
        var sameConfiguration = existing is not null
                                && string.Equals(existing.Uri, catalogUri.AbsoluteUri, StringComparison.Ordinal)
                                && string.Equals(existing.SignatureUri, signatureUri?.AbsoluteUri ?? string.Empty, StringComparison.Ordinal)
                                && existing.SignaturePolicy == (int)config.SignaturePolicy
                                && string.Equals(existing.TrustedKeyId, config.TrustedKeyId, StringComparison.Ordinal)
                                && string.Equals(
                                    existing.TrustedPublicKeySpkiBase64,
                                    config.TrustedPublicKeySpkiBase64,
                                    StringComparison.Ordinal)
                                && ProviderAsnCatalogTransportPinning
                                    .DeserializePins(existing.TlsSpkiPinsSha256Json)
                                    .SequenceEqual(tlsPins);

        var item = existing ?? new ProviderAsnCatalogRemoteSourceItem
        {
            RegistryId = registryId,
        };

        item.Uri = catalogUri.AbsoluteUri;
        item.SignatureUri = signatureUri?.AbsoluteUri ?? string.Empty;
        item.SignaturePolicy = (int)config.SignaturePolicy;
        item.TrustedKeyId = config.TrustedKeyId.Trim();
        item.TrustedPublicKeySpkiBase64 = config.TrustedPublicKeySpkiBase64.Trim();
        item.TlsSpkiPinsSha256Json = tlsPinsJson;
        if (!sameConfiguration)
        {
            item.ConfigurationUpdatedAtUnixMs = observedAt.ToUnixTimeMilliseconds();
            item.ETag = string.Empty;
            item.LastModifiedUnixMs = null;
            item.RemoteContentSha256 = string.Empty;
            item.CacheUpdatedAtUnixMs = 0;
            item.LastCheckedAtUnixMs = 0;
            item.LastFetchedAtUnixMs = null;
            item.LastSignatureValid = null;
            item.LastSignatureStatus = string.Empty;
            item.LastSignatureKeyId = string.Empty;
            item.LastSignatureCatalogSha256 = string.Empty;
            item.LastSignatureSignedAtUnixMs = null;
        }

        await sources.UpsertAsync(item, cancellationToken);

        if (!sameConfiguration && sourceRevisionStore is not null)
        {
            try
            {
                await sourceRevisionStore.InsertAsync(
                    ProviderAsnCatalogRemoteSourceRevisionProjector.Create(
                        registryId,
                        beforeRevision,
                        ProviderAsnCatalogRemoteSourceRevisionProjector.Clone(item),
                        changeContext,
                        observedAt),
                    CancellationToken.None);
            }
            catch (Exception revisionError)
            {
                try
                {
                    if (beforeRevision is null)
                    {
                        await sources.RemoveAsync(registryId, CancellationToken.None);
                    }
                    else
                    {
                        await sources.UpsertAsync(beforeRevision, CancellationToken.None);
                    }
                }
                catch (Exception rollbackError)
                {
                    Logging.SaveLog($"Provider catalog remote source revision compensation failed: {rollbackError}");
                    throw new AggregateException(
                        "Remote source trust configuration changed, but its revision history could not be persisted and compensation also failed.",
                        revisionError,
                        rollbackError);
                }

                throw new InvalidOperationException(
                    "Remote source trust configuration was rolled back because its revision history could not be persisted.",
                    revisionError);
            }
        }

        return Project(item);
    }

    private async Task<ProviderAsnCatalogRemoteSourceView?> GetCoreAsync(
        string registryId,
        CancellationToken cancellationToken = default)
    {
        var item = await sources.GetAsync(registryId, cancellationToken);
        return item is null ? null : Project(item);
    }

    private async Task RemoveCoreAsync(
        string registryId,
        CancellationToken cancellationToken = default)
    {
        var registry = await catalogs.GetAsync(registryId, cancellationToken);
        await using var processLease = await AcquireRemoteOperationLeaseAsync(
            registry.FilePath,
            cancellationToken);
        var existing = await sources.GetAsync(registryId, cancellationToken);
        if (existing is null)
        {
            return;
        }

        var beforeRevision = ProviderAsnCatalogRemoteSourceRevisionProjector.Clone(existing);
        await sources.RemoveAsync(registryId, cancellationToken);

        if (sourceRevisionStore is not null)
        {
            try
            {
                await sourceRevisionStore.InsertAsync(
                    ProviderAsnCatalogRemoteSourceRevisionProjector.Create(
                        registryId,
                        beforeRevision,
                        null,
                        new ProviderAsnCatalogRemoteSourceChangeContext
                        {
                            Reason = "remove",
                        },
                        DateTimeOffset.UtcNow),
                    CancellationToken.None);
            }
            catch (Exception revisionError)
            {
                try
                {
                    await sources.UpsertAsync(beforeRevision, CancellationToken.None);
                }
                catch (Exception rollbackError)
                {
                    Logging.SaveLog($"Provider catalog remote source removal compensation failed: {rollbackError}");
                    throw new AggregateException(
                        "Remote source trust configuration was removed, but its revision history could not be persisted and compensation also failed.",
                        revisionError,
                        rollbackError);
                }

                throw new InvalidOperationException(
                    "Remote source removal was rolled back because its revision history could not be persisted.",
                    revisionError);
            }
        }
    }

    private async Task<ProviderAsnCatalogRemoteFetchPreview> FetchPreviewCoreAsync(
        string registryId,
        DateTimeOffset? now = null,
        CancellationToken cancellationToken = default)
    {
        var registry = await catalogs.GetAsync(registryId, cancellationToken);
        if (!registry.Registered)
        {
            throw new InvalidOperationException("Remote catalog fetch is unavailable for retired registry resources.");
        }
        await using var processLease = await AcquireRemoteOperationLeaseAsync(
            registry.FilePath,
            cancellationToken);

        var item = await RequireSourceAsync(registryId, cancellationToken);
        var config = ToConfig(item);
        ProviderAsnCatalogSignatureVerifier.ValidateTrustedKey(config);

        var local = await JsonProviderAsnEndpointCatalog.LoadAsync(registry.FilePath, cancellationToken);
        if (!string.Equals(local.Sha256, registry.Sha256, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Registered catalog file changed on disk; refresh or reconcile the registry before remote fetch.");
        }

        var checkedAt = now ?? DateTimeOffset.UtcNow;
        var conditional = await _transport.FetchAsync(
            new ProviderAsnCatalogRemoteTransportRequest
            {
                Uri = new Uri(item.Uri),
                Conditional = true,
                ETag = item.ETag,
                LastModified = FromUnixMs(item.LastModifiedUnixMs),
                TlsSpkiPinsSha256 = config.TlsSpkiPinsSha256,
            },
            cancellationToken);

        var serverNotModified = conditional.StatusCode == 304;
        ProviderAsnCatalogRemoteTransportResponse contentResponse = conditional;
        JsonProviderAsnEndpointCatalog remote;
        var fetchedBytes = false;

        if (serverNotModified
            && !item.RemoteContentSha256.IsNullOrEmpty()
            && string.Equals(local.Sha256, item.RemoteContentSha256, StringComparison.OrdinalIgnoreCase))
        {
            remote = local;
        }
        else
        {
            if (serverNotModified)
            {
                contentResponse = await _transport.FetchAsync(
                    new ProviderAsnCatalogRemoteTransportRequest
                    {
                        Uri = new Uri(item.Uri),
                        Conditional = false,
                        TlsSpkiPinsSha256 = config.TlsSpkiPinsSha256,
                    },
                    cancellationToken);
            }

            EnsureSuccessContentResponse(contentResponse);
            remote = JsonProviderAsnEndpointCatalog.FromBytes(contentResponse.Bytes);
            fetchedBytes = true;
        }

        if (!string.Equals(remote.Document.Id, registry.CatalogId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Remote catalog ID '{remote.Document.Id}' does not match registered catalog ID '{registry.CatalogId}'.");
        }

        var signatureValidation = await ValidateSignatureAsync(
            remote,
            config,
            cancellationToken);
        if (!signatureValidation.PolicySatisfied)
        {
            throw new InvalidOperationException(
                $"Provider catalog signature policy failed: {signatureValidation.Status}.");
        }

        ProviderAsnCatalogSignatureContinuity.Validate(item, signatureValidation, checkedAt);

        if (fetchedBytes)
        {
            item.ETag = contentResponse.ETag;
            item.LastModifiedUnixMs = contentResponse.LastModified?.ToUnixTimeMilliseconds();
            item.RemoteContentSha256 = remote.Sha256;
            item.LastFetchedAtUnixMs = checkedAt.ToUnixTimeMilliseconds();
        }
        else
        {
            if (!conditional.ETag.IsNullOrEmpty())
            {
                item.ETag = conditional.ETag;
            }
            if (conditional.LastModified is not null)
            {
                item.LastModifiedUnixMs = conditional.LastModified.Value.ToUnixTimeMilliseconds();
            }
        }

        item.LastCheckedAtUnixMs = checkedAt.ToUnixTimeMilliseconds();
        item.CacheUpdatedAtUnixMs = checkedAt.ToUnixTimeMilliseconds();
        item.LastSignatureValid = signatureValidation.Attempted
            ? signatureValidation.Valid
            : null;
        item.LastSignatureStatus = signatureValidation.Status;
        item.LastSignatureKeyId = signatureValidation.KeyId;
        item.LastSignatureCatalogSha256 = signatureValidation.CatalogSha256;
        item.LastSignatureSignedAtUnixMs = signatureValidation.SignedAt?.ToUnixTimeMilliseconds();
        await sources.UpsertAsync(item, cancellationToken);

        ProviderAsnCatalogUpdatePlan? updatePlan = null;
        var localMatchesRemote = string.Equals(local.Sha256, remote.Sha256, StringComparison.OrdinalIgnoreCase);
        if (!localMatchesRemote)
        {
            var bytes = fetchedBytes
                ? contentResponse.Bytes
                : await File.ReadAllBytesAsync(registry.FilePath, cancellationToken);
            updatePlan = await catalogs.PrepareUpdateAsync(
                registryId,
                bytes,
                new ProviderAsnCatalogUpdateOptions
                {
                    RequireSameCatalogId = true,
                },
                checkedAt,
                cancellationToken);
        }

        return new ProviderAsnCatalogRemoteFetchPreview
        {
            RegistryId = registryId,
            Source = Project(item),
            CheckedAt = checkedAt,
            ServerNotModified = serverNotModified,
            LocalAlreadyMatchesRemote = localMatchesRemote,
            ETag = item.ETag,
            LastModified = FromUnixMs(item.LastModifiedUnixMs),
            RemoteContentSha256 = remote.Sha256,
            CatalogFinalUri = contentResponse.FinalUri.AbsoluteUri,
            SignatureValidation = signatureValidation,
            UpdatePlan = updatePlan,
            SourceConfigurationUpdatedAtUnixMs = item.ConfigurationUpdatedAtUnixMs,
            SourceConfigurationFingerprint = ProviderAsnCatalogRemoteConfigurationFingerprint.FromItem(item),
        };
    }

    private async Task<ProviderAsnCatalogRevisionView> ApplyCoreAsync(
        ProviderAsnCatalogRemoteFetchPreview preview,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(preview);
        if (preview.UpdatePlan is null)
        {
            throw new InvalidOperationException("Remote catalog preview contains no update to apply.");
        }

        var registry = await catalogs.GetAsync(preview.RegistryId, cancellationToken);
        await using var processLease = await AcquireRemoteOperationLeaseAsync(
            registry.FilePath,
            cancellationToken);
        var currentSource = await RequireSourceAsync(preview.RegistryId, cancellationToken);
        var currentConfigurationFingerprint =
            ProviderAsnCatalogRemoteConfigurationFingerprint.FromItem(currentSource);
        if (preview.SourceConfigurationFingerprint.IsNullOrEmpty()
            || !string.Equals(
                currentConfigurationFingerprint,
                preview.SourceConfigurationFingerprint,
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Remote source trust/configuration changed after preview; fetch a fresh preview before apply.");
        }
        if (!string.Equals(
                currentSource.RemoteContentSha256,
                preview.RemoteContentSha256,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Remote source cache changed after preview; fetch a fresh preview before apply.");
        }

        var revision = await catalogs.ApplyUpdateAsync(
            preview.RegistryId,
            preview.UpdatePlan,
            cancellationToken);

        if (provenanceStore is not null)
        {
            try
            {
                await provenanceStore.UpsertAsync(
                    CreateProvenanceItem(preview, revision),
                    CancellationToken.None);
            }
            catch (Exception provenanceError)
            {
                try
                {
                    await catalogs.RollbackRevisionAsync(
                        revision.Id,
                        force: false,
                        CancellationToken.None);
                }
                catch (Exception rollbackError)
                {
                    Logging.SaveLog($"Provider catalog remote provenance compensation failed: {rollbackError}");
                    throw new AggregateException(
                        "Remote catalog revision was applied without durable provenance, and compensating rollback also failed.",
                        provenanceError,
                        rollbackError);
                }

                throw new InvalidOperationException(
                    "Remote catalog update was rolled back because revision-linked provenance could not be persisted.",
                    provenanceError);
            }
        }

        return revision;
    }

    private static async Task<FileStream> AcquireRemoteOperationLeaseAsync(
        string catalogPath,
        CancellationToken cancellationToken)
    {
        var path = Path.GetFullPath(catalogPath);
        var directory = Path.GetDirectoryName(path);
        string lockPath;
        if (!directory.IsNullOrEmpty() && Directory.Exists(directory))
        {
            lockPath = Path.Combine(
                directory,
                "." + Path.GetFileName(path) + ".pattn-remote.lock");
        }
        else
        {
            // Registry abstractions and recovery paths can legitimately refer to a
            // catalog whose directory is not currently materialized. Keep
            // cross-process coordination rather than failing before the trust
            // operation reaches its own validation by using a deterministic
            // per-user temp fallback keyed by the canonical catalog path.
            var lockDirectory = Path.Combine(Path.GetTempPath(), "pattn-remote-locks");
            Directory.CreateDirectory(lockDirectory);
            var key = Convert.ToHexString(
                    System.Security.Cryptography.SHA256.HashData(
                        System.Text.Encoding.UTF8.GetBytes(path)))
                .ToLowerInvariant();
            lockPath = Path.Combine(lockDirectory, key + ".lock");
        }
        var deadline = DateTime.UtcNow.AddSeconds(10);
        IOException? lastError = null;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                // Keep the sidecar stable instead of unlinking it after release.
                // FileShare.None coordinates cooperating PattN processes on one inode.
                return new FileStream(
                    lockPath,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    1,
                    FileOptions.Asynchronous | FileOptions.WriteThrough);
            }
            catch (IOException ex) when (DateTime.UtcNow < deadline)
            {
                lastError = ex;
                await Task.Delay(50, cancellationToken);
                continue;
            }

            throw new IOException(
                $"Timed out waiting for the provider catalog remote-operation lease: {lockPath}",
                lastError);
        }
    }

    private static async Task<T> WithRegistryLockAsync<T>(
        string registryId,
        CancellationToken cancellationToken,
        Func<Task<T>> action)
    {
        if (registryId.IsNullOrEmpty())
        {
            throw new ArgumentException("Registry ID is required.", nameof(registryId));
        }

        var gate = RegistryOperationLocks.GetOrAdd(registryId, static _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken);
        try
        {
            return await action();
        }
        finally
        {
            gate.Release();
        }
    }

    private static async Task WithRegistryLockAsync(
        string registryId,
        CancellationToken cancellationToken,
        Func<Task> action)
    {
        if (registryId.IsNullOrEmpty())
        {
            throw new ArgumentException("Registry ID is required.", nameof(registryId));
        }

        var gate = RegistryOperationLocks.GetOrAdd(registryId, static _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken);
        try
        {
            await action();
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task<ProviderAsnCatalogSignatureValidation> ValidateSignatureAsync(
        JsonProviderAsnEndpointCatalog catalog,
        ProviderAsnCatalogRemoteSourceConfig config,
        CancellationToken cancellationToken)
    {
        if (config.SignaturePolicy == ProviderAsnCatalogSignaturePolicy.None
            || (config.SignaturePolicy == ProviderAsnCatalogSignaturePolicy.Optional
                && config.SignatureUri.IsNullOrEmpty()))
        {
            return ProviderAsnCatalogSignatureVerifier.Verify(
                catalog,
                new ProviderAsnCatalogSignatureEnvelope(),
                config);
        }

        var response = await _transport.FetchAsync(
            new ProviderAsnCatalogRemoteTransportRequest
            {
                Uri = new Uri(config.SignatureUri),
                Conditional = false,
                MaximumBytes = MaximumSignatureEnvelopeBytes,
                TlsSpkiPinsSha256 = config.TlsSpkiPinsSha256,
            },
            cancellationToken);
        EnsureSuccessContentResponse(response);

        ProviderAsnCatalogSignatureEnvelope envelope;
        try
        {
            envelope = JsonSerializer.Deserialize<ProviderAsnCatalogSignatureEnvelope>(
                    response.Bytes,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                ?? throw new InvalidOperationException("Provider catalog signature envelope decoded to null.");
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException("Provider catalog signature envelope JSON is invalid.", ex);
        }

        var validation = ProviderAsnCatalogSignatureVerifier.Verify(catalog, envelope, config);
        return validation with { FinalUri = response.FinalUri.AbsoluteUri };
    }

    private async Task<ProviderAsnCatalogRemoteSourceItem> RequireSourceAsync(
        string registryId,
        CancellationToken cancellationToken)
        => await sources.GetAsync(registryId, cancellationToken)
           ?? throw new InvalidOperationException("No remote source is configured for this provider catalog.");

    private static ProviderAsnCatalogRemoteSourceConfig ToConfig(ProviderAsnCatalogRemoteSourceItem item)
    {
        return new ProviderAsnCatalogRemoteSourceConfig
        {
            Uri = item.Uri,
            SignatureUri = item.SignatureUri,
            SignaturePolicy = ReadSignaturePolicy(item.SignaturePolicy),
            TrustedKeyId = item.TrustedKeyId,
            TrustedPublicKeySpkiBase64 = item.TrustedPublicKeySpkiBase64,
            TlsSpkiPinsSha256 = ProviderAsnCatalogTransportPinning.DeserializePins(item.TlsSpkiPinsSha256Json),
        };
    }

    private static ProviderAsnCatalogRemoteSourceView Project(ProviderAsnCatalogRemoteSourceItem item)
        => new()
        {
            RegistryId = item.RegistryId,
            Uri = item.Uri,
            SignatureUri = item.SignatureUri,
            SignaturePolicy = ReadSignaturePolicy(item.SignaturePolicy),
            TrustedKeyId = item.TrustedKeyId,
            TrustedPublicKeySpkiBase64 = item.TrustedPublicKeySpkiBase64,
            TlsSpkiPinsSha256 = ProviderAsnCatalogTransportPinning.DeserializePins(item.TlsSpkiPinsSha256Json),
            ETag = item.ETag,
            LastModified = FromUnixMs(item.LastModifiedUnixMs),
            RemoteContentSha256 = item.RemoteContentSha256,
            ConfigurationUpdatedAt = DateTimeOffset.FromUnixTimeMilliseconds(item.ConfigurationUpdatedAtUnixMs),
            CacheUpdatedAt = FromUnixMs(item.CacheUpdatedAtUnixMs > 0 ? item.CacheUpdatedAtUnixMs : null),
            LastCheckedAt = FromUnixMs(item.LastCheckedAtUnixMs > 0 ? item.LastCheckedAtUnixMs : null),
            LastFetchedAt = FromUnixMs(item.LastFetchedAtUnixMs),
            LastSignatureValid = item.LastSignatureValid,
            LastSignatureStatus = item.LastSignatureStatus,
            LastSignatureKeyId = item.LastSignatureKeyId,
            LastSignatureCatalogSha256 = item.LastSignatureCatalogSha256,
            LastSignatureSignedAt = FromUnixMs(item.LastSignatureSignedAtUnixMs),
        };

    public async Task<ProviderAsnCatalogRemoteApplyProvenanceView?> GetRevisionProvenanceAsync(
        string revisionId,
        CancellationToken cancellationToken = default)
    {
        if (provenanceStore is null)
        {
            return null;
        }

        var item = await provenanceStore.GetAsync(revisionId, cancellationToken);
        return item is null ? null : ProviderAsnCatalogRemoteProvenanceProjector.Project(item);
    }

    private static ProviderAsnCatalogRemoteApplyProvenanceItem CreateProvenanceItem(
        ProviderAsnCatalogRemoteFetchPreview preview,
        ProviderAsnCatalogRevisionView revision)
    {
        var signature = preview.SignatureValidation;
        return new ProviderAsnCatalogRemoteApplyProvenanceItem
        {
            RevisionId = revision.Id,
            RegistryId = preview.RegistryId,
            SourceUri = preview.Source.Uri,
            SourceFinalUri = preview.CatalogFinalUri,
            SignatureUri = preview.Source.SignatureUri,
            SignatureFinalUri = signature?.FinalUri ?? string.Empty,
            SignaturePolicy = (int)preview.Source.SignaturePolicy,
            TrustedKeyId = preview.Source.TrustedKeyId,
            TlsSpkiPinsSha256Json = ProviderAsnCatalogTransportPinning.SerializePins(preview.Source.TlsSpkiPinsSha256),
            ServerNotModified = preview.ServerNotModified,
            ETag = preview.ETag,
            LastModifiedUnixMs = preview.LastModified?.ToUnixTimeMilliseconds(),
            RemoteContentSha256 = preview.RemoteContentSha256,
            SignatureAttempted = signature?.Attempted == true,
            SignatureValid = signature?.Valid == true,
            SignaturePolicySatisfied = signature?.PolicySatisfied == true,
            SignatureStatus = signature?.Status ?? string.Empty,
            SignatureKeyId = signature?.KeyId ?? string.Empty,
            SignatureCatalogSha256 = signature?.CatalogSha256 ?? string.Empty,
            SignatureSignedAtUnixMs = signature?.SignedAt?.ToUnixTimeMilliseconds(),
            CheckedAtUnixMs = preview.CheckedAt.ToUnixTimeMilliseconds(),
            AppliedAtUnixMs = revision.AppliedAt.ToUnixTimeMilliseconds(),
        };
    }

    private static bool SameAuthority(Uri left, Uri right)
        => string.Equals(left.IdnHost, right.IdnHost, StringComparison.OrdinalIgnoreCase)
           && left.Port == right.Port;

    private static Uri ValidateHttpsUri(string value, string parameterName)
    {
        if (!Uri.TryCreate(value?.Trim(), UriKind.Absolute, out var uri)
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !uri.UserInfo.IsNullOrEmpty()
            || !uri.Fragment.IsNullOrEmpty())
        {
            throw new ArgumentException(
                "Provider catalog remote URI must be absolute HTTPS without embedded credentials or fragment.",
                parameterName);
        }
        return uri;
    }

    private static void EnsureSuccessContentResponse(ProviderAsnCatalogRemoteTransportResponse response)
    {
        if (response.StatusCode is < 200 or >= 300 || response.Bytes.Length == 0)
        {
            throw new InvalidOperationException(
                $"Provider catalog remote fetch did not return usable content (HTTP {response.StatusCode}).");
        }
        if (!string.Equals(response.FinalUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Provider catalog remote fetch redirected away from HTTPS.");
        }
    }

    private static ProviderAsnCatalogSignaturePolicy ReadSignaturePolicy(int value)
    {
        if (!Enum.IsDefined(typeof(ProviderAsnCatalogSignaturePolicy), value))
        {
            throw new InvalidOperationException("Stored provider catalog signature policy is invalid.");
        }
        return (ProviderAsnCatalogSignaturePolicy)value;
    }

    private static DateTimeOffset? FromUnixMs(long? value)
        => value is null ? null : DateTimeOffset.FromUnixTimeMilliseconds(value.Value);
}
