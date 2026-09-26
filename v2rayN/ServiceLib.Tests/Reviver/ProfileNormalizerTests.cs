using ServiceLib.Reviver.Normalization;

namespace ServiceLib.Tests.Reviver;

public class ProfileNormalizerTests
{
    [Test]
    public async Task Normalize_ShouldCanonicalizeRepresentationWithoutMutatingSource()
    {
        var source = new ProfileItem
        {
            ConfigType = EConfigType.VLESS,
            Address = " [2001:db8::1] ",
            Port = 443,
            Password = Guid.NewGuid().ToString(),
            Network = " WS ",
            StreamSecurity = " TLS ",
            Sni = " example.com ",
            Fingerprint = " chrome ",
            Alpn = " h2,http/1.1 ",
        };
        source.SetTransportExtra(new TransportExtraItem { Host = " host.example ", Path = " /ws " });

        var normalized = new ProfileNormalizer().Normalize(source);

        await normalized.Address.Should().BeEqualTo("2001:db8::1");
        await normalized.Network.Should().BeEqualTo("ws");
        await normalized.StreamSecurity.Should().BeEqualTo("tls");
        await normalized.Sni.Should().BeEqualTo("example.com");
        await normalized.GetTransportExtra().Host.Should().BeEqualTo("host.example");
        await normalized.GetTransportExtra().Path.Should().BeEqualTo("/ws");

        await source.Address.Should().BeEqualTo(" [2001:db8::1] ");
        await source.GetTransportExtra().Host.Should().BeEqualTo(" host.example ");
    }
}
