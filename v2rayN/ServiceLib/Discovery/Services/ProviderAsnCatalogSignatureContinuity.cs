using ServiceLib.Discovery.Models;
using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Enforces continuity after a remote catalog signature has already been cryptographically verified.
/// This prevents replaying an older accepted artifact or presenting different content at the same
/// signing instant without changing the locally trusted source configuration.
/// </summary>
public static class ProviderAsnCatalogSignatureContinuity
{
    public static readonly TimeSpan MaximumFutureClockSkew = TimeSpan.FromMinutes(10);
    public static readonly TimeSpan MaximumFirstAcceptanceAge = TimeSpan.FromDays(180);

    public static void Validate(
        ProviderAsnCatalogRemoteSourceItem source,
        ProviderAsnCatalogSignatureValidation validation,
        DateTimeOffset checkedAt)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(validation);

        if (!validation.Attempted || !validation.Valid)
        {
            return;
        }
        if (validation.SignedAt is not DateTimeOffset signedAt)
        {
            throw new InvalidOperationException(
                "A valid provider catalog signature is missing its signing timestamp.");
        }
        if (signedAt > checkedAt + MaximumFutureClockSkew)
        {
            throw new InvalidOperationException(
                "Provider catalog signature timestamp is too far in the future.");
        }

        if (source.LastSignatureSignedAtUnixMs is not long previousUnixMs)
        {
            if (signedAt < checkedAt - MaximumFirstAcceptanceAge)
            {
                throw new InvalidOperationException(
                    $"Provider catalog signature is older than the {MaximumFirstAcceptanceAge.TotalDays:0}-day first-acceptance window; refusing stale trust baseline.");
            }
            return;
        }

        var previousSignedAt = DateTimeOffset.FromUnixTimeMilliseconds(previousUnixMs);
        if (signedAt < previousSignedAt)
        {
            throw new InvalidOperationException(
                "Provider catalog signature is older than the last accepted signed artifact; refusing replay/downgrade.");
        }
        if (signedAt == previousSignedAt
            && !source.LastSignatureCatalogSha256.IsNullOrEmpty()
            && !string.Equals(
                source.LastSignatureCatalogSha256,
                validation.CatalogSha256,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Provider catalog signature reuses an accepted signing timestamp for different content; refusing ambiguous replay/equivocation.");
        }
    }
}
