using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;
using ServiceLib.Models.Entities;

namespace ServiceLib.Tests.Reviver;

public class ProviderAsnCatalogRemoteProvenanceQueryServiceTests
{
    [Test]
    public async Task FilterAndSummarize_ShouldFilterByHostKeyStatusAndValidity()
    {
        var now = new DateTimeOffset(2026, 9, 24, 10, 0, 0, TimeSpan.Zero);
        var rows = new[]
        {
            Item("r1", "registry-a", "https://catalog.example/a.json", "key-a", "valid", true, true, now.AddHours(-1)),
            Item("r2", "registry-a", "https://catalog.example/b.json", "key-b", "signature-invalid", false, false, now.AddHours(-2)),
            Item("r3", "registry-b", "https://other.example/c.json", "key-a", "valid", true, true, now.AddHours(-3)),
        };

        var result = ProviderAsnCatalogRemoteProvenanceQueryService.FilterAndSummarize(
            rows,
            new ProviderAsnCatalogRemoteProvenanceQuery
            {
                RegistryId = "registry-a",
                SourceHost = "catalog.example",
                TrustedKeyId = "key-a",
                SignatureStatus = "VALID",
                SignatureValid = true,
                SignaturePolicySatisfied = true,
                MaxItems = 20,
            });

        await result.Total.Should().BeEqualTo(1);
        await result.SignatureAttempted.Should().BeEqualTo(1);
        await result.SignatureValid.Should().BeEqualTo(1);
        await result.SignaturePolicySatisfied.Should().BeEqualTo(1);
        await result.Entries[0].RevisionId.Should().BeEqualTo("r1");
    }

    [Test]
    public async Task FilterAndSummarize_ShouldFilterByTransportSpkiPin()
    {
        var now = DateTimeOffset.Parse("2026-09-24T11:00:00Z");
        var pinA = new string('a', 64);
        var pinB = new string('b', 64);
        var rowA = Item("r1", "registry-a", "https://catalog.example/a.json", "key-a", "valid", true, true, now.AddHours(-1));
        var rowB = Item("r2", "registry-a", "https://catalog.example/b.json", "key-a", "valid", true, true, now.AddHours(-2));
        rowA.TlsSpkiPinsSha256Json = ProviderAsnCatalogTransportPinning.SerializePins([pinA, pinB]);
        rowB.TlsSpkiPinsSha256Json = ProviderAsnCatalogTransportPinning.SerializePins([pinB]);

        var result = ProviderAsnCatalogRemoteProvenanceQueryService.FilterAndSummarize(
            [rowA, rowB],
            new ProviderAsnCatalogRemoteProvenanceQuery
            {
                TlsSpkiPinSha256 = pinA.ToUpperInvariant(),
                MaxItems = 20,
            });

        await result.Total.Should().BeEqualTo(1);
        await result.TransportPinned.Should().BeEqualTo(1);
        await result.Entries[0].RevisionId.Should().BeEqualTo("r1");
        await result.Entries[0].TlsSpkiPinsSha256.Contains(pinA).Should().BeTrue();
    }

    [Test]
    public async Task Summarize_ShouldOrderNewestFirstAndCount304Evidence()
    {
        var now = DateTimeOffset.Parse("2026-09-24T11:00:00Z");
        var older = Item("older", "registry-a", "https://catalog.example/a.json", "key-a", "valid", true, true, now.AddDays(-2));
        var newer = Item("newer", "registry-a", "https://catalog.example/a.json", "key-a", "valid", true, true, now.AddHours(-1));
        newer.ServerNotModified = true;

        var result = ProviderAsnCatalogRemoteProvenanceQueryService.Summarize([older, newer]);

        await result.Total.Should().BeEqualTo(2);
        await result.ServerNotModified.Should().BeEqualTo(1);
        await result.TransportPinned.Should().BeEqualTo(0);
        await result.Entries[0].RevisionId.Should().BeEqualTo("newer");
        await result.LatestAppliedAt.Should().BeEqualTo(now.AddHours(-1));
    }

    [Test]
    public async Task Summarize_ShouldRejectInvalidStoredSignaturePolicy()
    {
        var row = Item(
            "r1",
            "registry-a",
            "https://catalog.example/a.json",
            "key-a",
            "valid",
            true,
            true,
            DateTimeOffset.Parse("2026-09-24T11:00:00Z"));
        row.SignaturePolicy = 999;

        var threw = false;
        try
        {
            _ = ProviderAsnCatalogRemoteProvenanceQueryService.Summarize([row]);
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.Message.Contains("signature policy", StringComparison.OrdinalIgnoreCase);
        }

        await threw.Should().BeTrue();
    }

    [Test]
    public async Task FilterAndSummarize_ShouldRejectUrlInHostFilter()
    {
        var threw = false;
        try
        {
            ProviderAsnCatalogRemoteProvenanceQueryService.FilterAndSummarize(
                [],
                new ProviderAsnCatalogRemoteProvenanceQuery
                {
                    SourceHost = "https://catalog.example/",
                });
        }
        catch (ArgumentException)
        {
            threw = true;
        }

        await threw.Should().BeTrue();
    }

    private static ProviderAsnCatalogRemoteApplyProvenanceItem Item(
        string revisionId,
        string registryId,
        string sourceUri,
        string trustedKeyId,
        string signatureStatus,
        bool signatureValid,
        bool policySatisfied,
        DateTimeOffset appliedAt)
        => new()
        {
            RevisionId = revisionId,
            RegistryId = registryId,
            SourceUri = sourceUri,
            SignaturePolicy = (int)ProviderAsnCatalogSignaturePolicy.Required,
            TrustedKeyId = trustedKeyId,
            SignatureAttempted = true,
            SignatureValid = signatureValid,
            SignaturePolicySatisfied = policySatisfied,
            SignatureStatus = signatureStatus,
            SignatureKeyId = trustedKeyId,
            SignatureCatalogSha256 = new string('a', 64),
            CheckedAtUnixMs = appliedAt.AddMinutes(-1).ToUnixTimeMilliseconds(),
            AppliedAtUnixMs = appliedAt.ToUnixTimeMilliseconds(),
        };
}
