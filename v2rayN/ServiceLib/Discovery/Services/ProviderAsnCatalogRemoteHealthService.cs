using ServiceLib.Discovery.Models;
using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Read-only remote source health derived exclusively from persisted registry/source/signature metadata.
/// This service performs no network I/O and never changes catalog/source state.
/// </summary>
public sealed class ProviderAsnCatalogRemoteHealthService(
    ProviderAsnCatalogRegistryService catalogs,
    IProviderAsnCatalogRemoteSourceStore sources)
{
    public async Task<ProviderAsnCatalogRemoteHealthSummary> LoadAsync(
        ProviderAsnCatalogRemoteHealthPolicy? policy = null,
        DateTimeOffset? now = null,
        CancellationToken cancellationToken = default)
    {
        policy ??= new ProviderAsnCatalogRemoteHealthPolicy();
        if (policy.MaximumCheckAge <= TimeSpan.Zero
            || policy.MaximumCheckAge > TimeSpan.FromDays(3650))
        {
            throw new ArgumentOutOfRangeException(nameof(policy.MaximumCheckAge));
        }

        var observedAt = now ?? DateTimeOffset.UtcNow;
        var registries = await catalogs.ListAsync(
            new ProviderAsnCatalogRegistryQuery
            {
                IncludeDisabled = true,
                IncludeUnregistered = false,
                MaxItems = 2000,
            },
            cancellationToken);
        var sourceRows = await sources.ListAsync(2000, cancellationToken);
        var byRegistry = sourceRows.ToDictionary(x => x.RegistryId, StringComparer.Ordinal);

        var rows = registries
            .Select(registry =>
            {
                byRegistry.TryGetValue(registry.Id, out var source);
                return Evaluate(registry, source, policy, observedAt);
            })
            .OrderByDescending(x => x.NeedsReview)
            .ThenByDescending(x => x.Configured)
            .ThenBy(x => x.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.RegistryId, StringComparer.Ordinal)
            .ToArray();

        return new ProviderAsnCatalogRemoteHealthSummary
        {
            RefreshedAt = observedAt,
            Rows = rows,
        };
    }

    public static ProviderAsnCatalogRemoteHealthRow Evaluate(
        ProviderAsnCatalogRegistryView registry,
        ProviderAsnCatalogRemoteSourceItem? source,
        ProviderAsnCatalogRemoteHealthPolicy policy,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(policy);

        var audit = registry.LastAudit;
        if (source is null)
        {
            return new ProviderAsnCatalogRemoteHealthRow
            {
                RegistryId = registry.Id,
                DisplayName = registry.DisplayName,
                CatalogId = registry.CatalogId,
                CatalogVersion = registry.CatalogVersion,
                CatalogEnabled = registry.Enabled,
                Configured = false,
                CatalogAuditValid = audit?.Valid ?? false,
                CatalogFreshnessKnown = audit?.FreshnessKnown ?? false,
                CatalogStale = audit?.Stale ?? false,
                HealthClass = "unconfigured",
                NeedsReview = false,
                Reasons = ["remote-source-optional-not-configured"],
            };
        }

        var checkedAt = FromUnixMs(source.LastCheckedAtUnixMs > 0 ? source.LastCheckedAtUnixMs : null);
        var fetchedAt = FromUnixMs(source.LastFetchedAtUnixMs);
        if (!Enum.IsDefined(typeof(ProviderAsnCatalogSignaturePolicy), source.SignaturePolicy))
        {
            throw new InvalidOperationException(
                "Stored provider catalog remote-source signature policy is invalid.");
        }
        var policyValue = (ProviderAsnCatalogSignaturePolicy)source.SignaturePolicy;

        var reasons = new List<string>();
        string healthClass;

        if (audit is { Valid: false })
        {
            healthClass = "catalog-invalid";
            reasons.Add("local-catalog-audit-invalid");
        }
        else if (audit is { FreshnessKnown: true, Stale: true })
        {
            healthClass = "catalog-stale";
            reasons.Add("local-catalog-metadata-stale");
        }
        else if (policyValue != ProviderAsnCatalogSignaturePolicy.None
                 && source.LastSignatureValid == false)
        {
            healthClass = "signature-failed";
            reasons.Add(source.LastSignatureStatus.NullIfEmpty() ?? "signature-invalid");
        }
        else if (policyValue == ProviderAsnCatalogSignaturePolicy.Required
                 && source.LastSignatureValid != true)
        {
            healthClass = "signature-required";
            reasons.Add(source.LastSignatureStatus.NullIfEmpty() ?? "required-signature-not-verified");
        }
        else if (checkedAt is null)
        {
            healthClass = "unchecked";
            reasons.Add("remote-source-never-checked");
        }
        else if (now - checkedAt.Value > policy.MaximumCheckAge)
        {
            healthClass = "stale-check";
            reasons.Add("remote-source-check-stale");
        }
        else
        {
            healthClass = "healthy";
            if (policyValue == ProviderAsnCatalogSignaturePolicy.Optional
                && source.LastSignatureValid is null)
            {
                reasons.Add("optional-signature-not-configured-or-not-checked");
            }
        }

        return new ProviderAsnCatalogRemoteHealthRow
        {
            RegistryId = registry.Id,
            DisplayName = registry.DisplayName,
            CatalogId = registry.CatalogId,
            CatalogVersion = registry.CatalogVersion,
            CatalogEnabled = registry.Enabled,
            Configured = true,
            SourceUri = source.Uri,
            SignaturePolicy = policyValue,
            LastCheckedAt = checkedAt,
            LastFetchedAt = fetchedAt,
            LastSignatureValid = source.LastSignatureValid,
            LastSignatureStatus = source.LastSignatureStatus,
            RemoteContentSha256 = source.RemoteContentSha256,
            CatalogAuditValid = audit?.Valid ?? false,
            CatalogFreshnessKnown = audit?.FreshnessKnown ?? false,
            CatalogStale = audit?.Stale ?? false,
            HealthClass = healthClass,
            NeedsReview = healthClass != "healthy",
            Reasons = reasons,
        };
    }

    private static DateTimeOffset? FromUnixMs(long? value)
        => value is null ? null : DateTimeOffset.FromUnixTimeMilliseconds(value.Value);
}
