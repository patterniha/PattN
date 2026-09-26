using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;

namespace ServiceLib.Tests.Reviver;

public class ProviderAsnCatalogRemoteConfigurationFingerprintTests
{
    [Test]
    public async Task Compute_ShouldCanonicalizeEquivalentPinSets()
    {
        var pinA = new string('a', 64);
        var pinB = new string('b', 64);
        var first = new ProviderAsnCatalogRemoteSourceConfig
        {
            Uri = "https://catalog.example/catalog.json",
            TlsSpkiPinsSha256 = [pinB.ToUpperInvariant(), pinA],
        };
        var second = new ProviderAsnCatalogRemoteSourceConfig
        {
            Uri = "https://catalog.example/catalog.json",
            TlsSpkiPinsSha256 = [pinA, pinB],
        };

        await ProviderAsnCatalogRemoteConfigurationFingerprint.Compute(first)
            .Should().BeEqualTo(
                ProviderAsnCatalogRemoteConfigurationFingerprint.Compute(second));
    }

    [Test]
    public async Task Compute_ShouldChangeWhenOnlyPinSetChanges()
    {
        var first = new ProviderAsnCatalogRemoteSourceConfig
        {
            Uri = "https://catalog.example/catalog.json",
            TlsSpkiPinsSha256 = [new string('a', 64)],
        };
        var second = first with
        {
            TlsSpkiPinsSha256 = [new string('b', 64)],
        };

        await ProviderAsnCatalogRemoteConfigurationFingerprint.Compute(first)
            .Should().NotBeEqualTo(
                ProviderAsnCatalogRemoteConfigurationFingerprint.Compute(second));
    }
}
