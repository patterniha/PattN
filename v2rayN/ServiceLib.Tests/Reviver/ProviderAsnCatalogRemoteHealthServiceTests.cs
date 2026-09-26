using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;
using ServiceLib.Models.Entities;

namespace ServiceLib.Tests.Reviver;

public class ProviderAsnCatalogRemoteHealthServiceTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 9, 24, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Evaluate_ShouldTreatUnconfiguredRemoteAsOptionalNotReviewFailure()
    {
        var row = ProviderAsnCatalogRemoteHealthService.Evaluate(
            Registry(),
            null,
            new ProviderAsnCatalogRemoteHealthPolicy(),
            Now);

        await row.HealthClass.Should().BeEqualTo("unconfigured");
        await row.Configured.Should().BeFalse();
        await row.NeedsReview.Should().BeFalse();
    }

    [Test]
    public async Task Evaluate_ShouldRejectInvalidStoredSignaturePolicy()
    {
        var source = Source();
        source.SignaturePolicy = 999;

        var threw = false;
        try
        {
            _ = ProviderAsnCatalogRemoteHealthService.Evaluate(
                Registry(),
                source,
                new ProviderAsnCatalogRemoteHealthPolicy(),
                Now);
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.Message.Contains("signature policy", StringComparison.OrdinalIgnoreCase);
        }

        await threw.Should().BeTrue();
    }

    [Test]
    public async Task Evaluate_ShouldPreferSignatureFailureOverOldCheckAge()
    {
        var source = Source();
        source.SignaturePolicy = (int)ProviderAsnCatalogSignaturePolicy.Required;
        source.LastSignatureValid = false;
        source.LastSignatureStatus = "signature-invalid";
        source.LastCheckedAtUnixMs = Now.AddDays(-120).ToUnixTimeMilliseconds();

        var row = ProviderAsnCatalogRemoteHealthService.Evaluate(
            Registry(),
            source,
            new ProviderAsnCatalogRemoteHealthPolicy { MaximumCheckAge = TimeSpan.FromDays(30) },
            Now);

        await row.HealthClass.Should().BeEqualTo("signature-failed");
        await row.NeedsReview.Should().BeTrue();
        await row.Reasons.Contains("signature-invalid").Should().BeTrue();
    }

    [Test]
    public async Task Evaluate_ShouldMarkRecentValidRequiredSignatureHealthy()
    {
        var source = Source();
        source.SignaturePolicy = (int)ProviderAsnCatalogSignaturePolicy.Required;
        source.LastSignatureValid = true;
        source.LastSignatureStatus = "valid";
        source.LastCheckedAtUnixMs = Now.AddDays(-2).ToUnixTimeMilliseconds();

        var row = ProviderAsnCatalogRemoteHealthService.Evaluate(
            Registry(),
            source,
            new ProviderAsnCatalogRemoteHealthPolicy { MaximumCheckAge = TimeSpan.FromDays(30) },
            Now);

        await row.HealthClass.Should().BeEqualTo("healthy");
        await row.NeedsReview.Should().BeFalse();
    }

    [Test]
    public async Task Evaluate_ShouldMarkOldCheckStaleWhenTrustStateIsOtherwiseAcceptable()
    {
        var source = Source();
        source.SignaturePolicy = (int)ProviderAsnCatalogSignaturePolicy.None;
        source.LastCheckedAtUnixMs = Now.AddDays(-45).ToUnixTimeMilliseconds();

        var row = ProviderAsnCatalogRemoteHealthService.Evaluate(
            Registry(),
            source,
            new ProviderAsnCatalogRemoteHealthPolicy { MaximumCheckAge = TimeSpan.FromDays(30) },
            Now);

        await row.HealthClass.Should().BeEqualTo("stale-check");
        await row.NeedsReview.Should().BeTrue();
    }

    [Test]
    public async Task Evaluate_ShouldSurfaceStaleLocalCatalogBeforeRemoteCheckAge()
    {
        var registry = Registry() with
        {
            LastAudit = new ProviderAsnCatalogAudit
            {
                CatalogId = "catalog-a",
                CatalogVersion = "1",
                AuditedAt = Now,
                FreshnessKnown = true,
                Stale = true,
            },
        };
        var source = Source();
        source.LastCheckedAtUnixMs = Now.ToUnixTimeMilliseconds();

        var row = ProviderAsnCatalogRemoteHealthService.Evaluate(
            registry,
            source,
            new ProviderAsnCatalogRemoteHealthPolicy(),
            Now);

        await row.HealthClass.Should().BeEqualTo("catalog-stale");
        await row.NeedsReview.Should().BeTrue();
    }

    private static ProviderAsnCatalogRegistryView Registry()
        => new()
        {
            Id = "registry-1",
            FilePath = "catalog.json",
            DisplayName = "Catalog A",
            Enabled = true,
            CatalogId = "catalog-a",
            CatalogVersion = "1",
            RegisteredAt = Now.AddDays(-60),
            UpdatedAt = Now.AddDays(-1),
            LastAudit = new ProviderAsnCatalogAudit
            {
                CatalogId = "catalog-a",
                CatalogVersion = "1",
                AuditedAt = Now,
                FreshnessKnown = true,
                Stale = false,
            },
        };

    private static ProviderAsnCatalogRemoteSourceItem Source()
        => new()
        {
            RegistryId = "registry-1",
            Uri = "https://catalog.example/catalog.json",
            SignaturePolicy = (int)ProviderAsnCatalogSignaturePolicy.None,
            ConfigurationUpdatedAtUnixMs = Now.AddDays(-10).ToUnixTimeMilliseconds(),
            LastCheckedAtUnixMs = Now.AddDays(-1).ToUnixTimeMilliseconds(),
        };
}
