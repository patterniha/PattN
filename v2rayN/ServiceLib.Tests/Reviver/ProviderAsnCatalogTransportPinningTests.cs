using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using ServiceLib.Discovery.Services;

namespace ServiceLib.Tests.Reviver;

public class ProviderAsnCatalogTransportPinningTests
{
    [Test]
    public async Task NormalizePins_ShouldCanonicalizeDeduplicateAndBound()
    {
        var pin = new string('A', 64);
        var values = ProviderAsnCatalogTransportPinning.NormalizePins(
            [pin, "  " + pin.ToLowerInvariant() + "  ", string.Empty]);

        await values.Count.Should().BeEqualTo(1);
        await values[0].Should().BeEqualTo(pin.ToLowerInvariant());

        var tooMany = Enumerable.Range(0, ProviderAsnCatalogTransportPinning.MaximumPins + 1)
            .Select(i => i.ToString("x64"))
            .ToArray();
        var threw = false;
        try
        {
            ProviderAsnCatalogTransportPinning.NormalizePins(tooMany);
        }
        catch (ArgumentOutOfRangeException)
        {
            threw = true;
        }
        await threw.Should().BeTrue();
    }

    [Test]
    public async Task NormalizePins_ShouldRejectNonSha256Hex()
    {
        var invalid = false;
        try
        {
            ProviderAsnCatalogTransportPinning.NormalizePins(["not-a-pin"]);
        }
        catch (ArgumentException)
        {
            invalid = true;
        }

        await invalid.Should().BeTrue();
    }

    [Test]
    public async Task ComputeAndMatch_ShouldUseCertificateSubjectPublicKeyInfo()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=example.test", key, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));

        var pin = ProviderAsnCatalogTransportPinning.ComputeSpkiSha256(certificate);
        var expected = Convert.ToHexString(
                SHA256.HashData(certificate.PublicKey.ExportSubjectPublicKeyInfo()))
            .ToLowerInvariant();

        await pin.Should().BeEqualTo(expected);
        await ProviderAsnCatalogTransportPinning.Matches(certificate, [pin]).Should().BeTrue();
        await ProviderAsnCatalogTransportPinning.Matches(certificate, [new string('f', 64)]).Should().BeFalse();
    }

    [Test]
    public async Task IsCertificateAccepted_ShouldRequireNormalTlsValidationAndMatchingPin()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=example.test", key, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));
        var pin = ProviderAsnCatalogTransportPinning.ComputeSpkiSha256(certificate);

        await ProviderAsnCatalogTransportPinning.IsCertificateAccepted(
                certificate,
                SslPolicyErrors.None,
                [pin])
            .Should().BeTrue();

        await ProviderAsnCatalogTransportPinning.IsCertificateAccepted(
                certificate,
                SslPolicyErrors.RemoteCertificateChainErrors,
                [pin])
            .Should().BeFalse();

        await ProviderAsnCatalogTransportPinning.IsCertificateAccepted(
                certificate,
                SslPolicyErrors.None,
                [new string('f', 64)])
            .Should().BeFalse();
    }

    [Test]
    public async Task EditorTextAndDiff_ShouldSupportOverlapRotationWithoutImplicitReplacement()
    {
        var pinA = new string('A', 64);
        var pinB = new string('b', 64);
        var pinC = new string('c', 64);

        var parsed = ProviderAsnCatalogTransportPinning.ParseEditorText(
            $"{pinB}\n{pinA}, {pinB};{pinC}");

        await parsed.SequenceEqual([pinA.ToLowerInvariant(), pinB, pinC]).Should().BeTrue();
        await ProviderAsnCatalogTransportPinning.FormatEditorText(parsed)
            .Should().BeEqualTo(string.Join(Environment.NewLine, parsed));

        var diff = ProviderAsnCatalogTransportPinning.Diff([pinA, pinB], [pinB, pinC]);
        await diff.Added.SequenceEqual([pinC]).Should().BeTrue();
        await diff.Removed.SequenceEqual([pinA.ToLowerInvariant()]).Should().BeTrue();
        await diff.Unchanged.SequenceEqual([pinB]).Should().BeTrue();
        await diff.Changed.Should().BeTrue();
    }

    [Test]
    public async Task DeserializePins_ShouldRejectMalformedStoredJson()
    {
        var threw = false;
        try
        {
            _ = ProviderAsnCatalogTransportPinning.DeserializePins("{broken");
        }
        catch (InvalidOperationException)
        {
            threw = true;
        }

        await threw.Should().BeTrue();
    }

    [Test]
    public async Task SerializeDeserialize_ShouldRoundTripCanonicalPins()
    {
        var pins = new[] { new string('a', 64), new string('B', 64) };
        var json = ProviderAsnCatalogTransportPinning.SerializePins(pins);
        var decoded = ProviderAsnCatalogTransportPinning.DeserializePins(json);

        await decoded.SequenceEqual([new string('a', 64), new string('b', 64)]).Should().BeTrue();
    }
}
