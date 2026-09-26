using System.Net;
using ServiceLib.Discovery.Services;

namespace ServiceLib.Tests.Reviver;

public class ProviderAsnCatalogRemoteDestinationPolicyTests
{
    [Test]
    public async Task PublicInternetAddresses_ShouldBeAllowed()
    {
        string[] values =
        [
            "1.1.1.1",
            "8.8.8.8",
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
        ];

        foreach (var value in values)
        {
            await ProviderAsnCatalogRemoteDestinationPolicy
                .IsAllowed(IPAddress.Parse(value))
                .Should()
                .BeTrue();
        }
    }

    [Test]
    public async Task SpecialOrNonPublicAddresses_ShouldBeRejected()
    {
        string[] values =
        [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "::",
            "::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001::1",
            "2001:db8::1",
            "2002::1",
        ];

        foreach (var value in values)
        {
            await ProviderAsnCatalogRemoteDestinationPolicy
                .IsAllowed(IPAddress.Parse(value))
                .Should()
                .BeFalse();
        }
    }

    [Test]
    public async Task IPv4MappedPrivateAddress_ShouldBeRejected()
    {
        await ProviderAsnCatalogRemoteDestinationPolicy
            .IsAllowed(IPAddress.Parse("::ffff:127.0.0.1"))
            .Should()
            .BeFalse();
    }

    [Test]
    public async Task ResolveAllowedAsync_ShouldRejectPrivateLiteralWithoutDns()
    {
        var threw = false;
        try
        {
            _ = await ProviderAsnCatalogRemoteDestinationPolicy.ResolveAllowedAsync("127.0.0.1");
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.Message.Contains("disallowed", StringComparison.OrdinalIgnoreCase);
        }

        await threw.Should().BeTrue();
    }

    [Test]
    public async Task ResolveAllowedAsync_ShouldPreservePublicLiteral()
    {
        var values = await ProviderAsnCatalogRemoteDestinationPolicy.ResolveAllowedAsync("1.1.1.1");
        await values.Count.Should().BeEqualTo(1);
        await values[0].ToString().Should().BeEqualTo("1.1.1.1");
    }
}
