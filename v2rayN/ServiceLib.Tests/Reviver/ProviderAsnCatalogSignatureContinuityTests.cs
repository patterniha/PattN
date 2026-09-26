using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;
using ServiceLib.Models.Entities;

namespace ServiceLib.Tests.Reviver;

public class ProviderAsnCatalogSignatureContinuityTests
{
    [Test]
    public async Task Validate_ShouldRejectOlderAcceptedSignature()
    {
        var source = Source("2026-09-24T10:00:00Z", new string('a', 64));
        var validation = Valid("2026-09-24T09:00:00Z", new string('b', 64));

        var threw = false;
        try
        {
            ProviderAsnCatalogSignatureContinuity.Validate(
                source,
                validation,
                DateTimeOffset.Parse("2026-09-24T11:00:00Z"));
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.Message.Contains("older than the last accepted", StringComparison.OrdinalIgnoreCase);
        }

        await threw.Should().BeTrue();
    }

    [Test]
    public async Task Validate_ShouldRejectDifferentContentAtSameAcceptedSignatureTime()
    {
        var source = Source("2026-09-24T10:00:00Z", new string('a', 64));
        var validation = Valid("2026-09-24T10:00:00Z", new string('b', 64));

        var threw = false;
        try
        {
            ProviderAsnCatalogSignatureContinuity.Validate(
                source,
                validation,
                DateTimeOffset.Parse("2026-09-24T11:00:00Z"));
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.Message.Contains("different content", StringComparison.OrdinalIgnoreCase);
        }

        await threw.Should().BeTrue();
    }

    [Test]
    public async Task Validate_ShouldRejectSignatureTooFarInFuture()
    {
        var source = new ProviderAsnCatalogRemoteSourceItem();
        var validation = Valid("2026-09-24T10:11:00Z", new string('a', 64));

        var threw = false;
        try
        {
            ProviderAsnCatalogSignatureContinuity.Validate(
                source,
                validation,
                DateTimeOffset.Parse("2026-09-24T10:00:00Z"));
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.Message.Contains("too far in the future", StringComparison.OrdinalIgnoreCase);
        }

        await threw.Should().BeTrue();
    }

    [Test]
    public async Task Validate_ShouldRejectStaleFirstAcceptedSignature()
    {
        var source = new ProviderAsnCatalogRemoteSourceItem();
        var checkedAt = DateTimeOffset.Parse("2026-09-24T10:00:00Z");
        var validation = Valid(
            checkedAt.Subtract(ProviderAsnCatalogSignatureContinuity.MaximumFirstAcceptanceAge).AddMinutes(-1).ToString("O"),
            new string('a', 64));

        var threw = false;
        try
        {
            ProviderAsnCatalogSignatureContinuity.Validate(source, validation, checkedAt);
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.Message.Contains("first-acceptance window", StringComparison.OrdinalIgnoreCase);
        }

        await threw.Should().BeTrue();
    }

    [Test]
    public async Task Validate_ShouldAllowRecentFirstAcceptedSignature()
    {
        var source = new ProviderAsnCatalogRemoteSourceItem();
        var checkedAt = DateTimeOffset.Parse("2026-09-24T10:00:00Z");
        var validation = Valid(
            checkedAt.Subtract(ProviderAsnCatalogSignatureContinuity.MaximumFirstAcceptanceAge).AddMinutes(1).ToString("O"),
            new string('a', 64));

        ProviderAsnCatalogSignatureContinuity.Validate(source, validation, checkedAt);

        await Task.CompletedTask;
    }

    [Test]
    public async Task Validate_ShouldAllowForwardSignedArtifact()
    {
        var source = Source("2026-09-24T09:00:00Z", new string('a', 64));
        var validation = Valid("2026-09-24T10:00:00Z", new string('b', 64));

        ProviderAsnCatalogSignatureContinuity.Validate(
            source,
            validation,
            DateTimeOffset.Parse("2026-09-24T11:00:00Z"));

        await Task.CompletedTask;
    }

    private static ProviderAsnCatalogRemoteSourceItem Source(string signedAt, string sha256)
        => new()
        {
            LastSignatureSignedAtUnixMs = DateTimeOffset.Parse(signedAt).ToUnixTimeMilliseconds(),
            LastSignatureCatalogSha256 = sha256,
        };

    private static ProviderAsnCatalogSignatureValidation Valid(string signedAt, string sha256)
        => new()
        {
            Attempted = true,
            Valid = true,
            PolicySatisfied = true,
            CatalogSha256 = sha256,
            SignedAt = DateTimeOffset.Parse(signedAt),
        };
}
