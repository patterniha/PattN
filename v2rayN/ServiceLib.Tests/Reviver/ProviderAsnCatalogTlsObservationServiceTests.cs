using System.Security.Cryptography.X509Certificates;
using ServiceLib.Discovery.Services;

namespace ServiceLib.Tests.Reviver;

public class ProviderAsnCatalogTlsObservationServiceTests
{
    [Test]
    public async Task RestrictedHandler_ShouldUseDirectPublicDestinationPolicyWithoutAutomaticRedirects()
    {
        using var handler = ProviderAsnCatalogTlsObservationService.CreateRestrictedHandler(
            _ => { });

        await handler.AllowAutoRedirect.Should().BeFalse();
        await handler.UseProxy.Should().BeFalse();
        await (handler.ConnectCallback is not null).Should().BeTrue();
        await (handler.SslOptions.RemoteCertificateValidationCallback is not null).Should().BeTrue();
    }

    [Test]
    public async Task CreateObservation_ShouldProjectValidatedCertificateWithoutTrustMutation()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=catalog.example", key, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30));
        var observedAt = DateTimeOffset.Parse("2026-09-24T11:30:00Z");

        var observation = ProviderAsnCatalogTlsObservationService.CreateObservation(
            new Uri("https://catalog.example/catalog.json"),
            new Uri("https://cdn.catalog.example/catalog.json"),
            200,
            certificate,
            observedAt);

        await observation.RequestedUri.Should().BeEqualTo("https://catalog.example/catalog.json");
        await observation.FinalUri.Should().BeEqualTo("https://cdn.catalog.example/catalog.json");
        await observation.Host.Should().BeEqualTo("cdn.catalog.example");
        await observation.HttpStatusCode.Should().BeEqualTo(200);
        await observation.SpkiSha256.Should().BeEqualTo(
            ProviderAsnCatalogTransportPinning.ComputeSpkiSha256(certificate));
        await observation.ObservedAt.Should().BeEqualTo(observedAt);
        await observation.Subject.Contains("catalog.example", StringComparison.OrdinalIgnoreCase).Should().BeTrue();
    }

    [Test]
    public async Task CanUseObservedPinForSource_ShouldRequireSameAuthorityAndNoCrossHostRedirect()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=catalog.example", key, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));

        var direct = ProviderAsnCatalogTlsObservationService.CreateObservation(
            new Uri("https://catalog.example/catalog.json"),
            new Uri("https://catalog.example/redirected.json"),
            200,
            certificate,
            DateTimeOffset.UtcNow);

        await ProviderAsnCatalogTlsObservationService.CanUseObservedPinForSource(
                direct,
                "https://catalog.example/other-path.json",
                out var directReason)
            .Should().BeTrue();
        await directReason.Should().BeEqualTo(string.Empty);

        await ProviderAsnCatalogTlsObservationService.CanUseObservedPinForSource(
                direct,
                "https://other.example/catalog.json",
                out var changedReason)
            .Should().BeFalse();
        await changedReason.Contains("changed", StringComparison.OrdinalIgnoreCase).Should().BeTrue();

        var redirected = ProviderAsnCatalogTlsObservationService.CreateObservation(
            new Uri("https://catalog.example/catalog.json"),
            new Uri("https://cdn.example/catalog.json"),
            200,
            certificate,
            DateTimeOffset.UtcNow);

        await ProviderAsnCatalogTlsObservationService.CanUseObservedPinForSource(
                redirected,
                "https://catalog.example/catalog.json",
                out var redirectReason)
            .Should().BeFalse();
        await redirectReason.Contains("cross-host", StringComparison.OrdinalIgnoreCase).Should().BeTrue();
    }

    [Test]
    public async Task CreateObservation_ShouldRejectNonHttpsEvidence()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=catalog.example", key, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));

        var threw = false;
        try
        {
            _ = ProviderAsnCatalogTlsObservationService.CreateObservation(
                new Uri("https://catalog.example/catalog.json"),
                new Uri("http://catalog.example/catalog.json"),
                200,
                certificate,
                DateTimeOffset.UtcNow);
        }
        catch (ArgumentException)
        {
            threw = true;
        }

        await threw.Should().BeTrue();
    }
}
