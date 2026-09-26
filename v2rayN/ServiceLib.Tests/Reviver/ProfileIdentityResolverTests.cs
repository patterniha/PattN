using ServiceLib.Reviver.Normalization;

namespace ServiceLib.Tests.Reviver;

public class ProfileIdentityResolverTests
{
    [Test]
    public async Task ResolveServerName_ShouldPreferExplicitSni()
    {
        var profile = NewProfile("front.example.com", "origin.example.com", "explicit.example.com");
        await ProfileIdentityResolver.ResolveServerName(profile).Should().BeEqualTo("explicit.example.com");
    }

    [Test]
    public async Task ResolveServerName_ShouldPreferDomainAddressOverTransportHost_WhenSniImplicit()
    {
        var profile = NewProfile("front.example.com", "origin.example.com", string.Empty);
        await ProfileIdentityResolver.ResolveServerName(profile).Should().BeEqualTo("front.example.com");
    }

    [Test]
    public async Task ResolveServerName_ShouldUseTransportHost_WhenAddressIsIp()
    {
        var profile = NewProfile("203.0.113.10", "origin.example.com", string.Empty);
        await ProfileIdentityResolver.ResolveServerName(profile).Should().BeEqualTo("origin.example.com");
    }

    [Test]
    public async Task ResolveHttpHost_ShouldRemainDistinctFromExplicitTlsServerName()
    {
        var profile = NewProfile("front.example.com", "origin.example.com", "tls.example.com");

        await ProfileIdentityResolver.ResolveServerName(profile).Should().BeEqualTo("tls.example.com");
        await ProfileIdentityResolver.ResolveHttpHost(profile).Should().BeEqualTo("origin.example.com");
    }

    private static ProfileItem NewProfile(string address, string host, string sni)
    {
        var profile = new ProfileItem { ConfigType = EConfigType.VLESS, Address = address, Port = 443, Password = Guid.NewGuid().ToString(), Sni = sni };
        profile.SetTransportExtra(new TransportExtraItem { Host = host, Path = "/" });
        return profile;
    }
}
