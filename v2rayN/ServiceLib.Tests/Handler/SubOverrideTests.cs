using ServiceLib.Handler;

namespace ServiceLib.Tests.Handler;

public class SubOverrideTests
{
    private static ProfileItem CreateProfile() => new()
    {
        ConfigType = EConfigType.VLESS,
        Address = "188.114.97.3",
        Port = 443,
    };

    [Test]
    public async Task ApplySubOverrides_ShouldReplaceAddressAndPort()
    {
        var profile = CreateProfile();

        ConfigHandler.ApplySubOverrides(profile, new SubItem { OverrideAddress = "example.com", OverridePort = 8443 });

        await profile.Address.Should().BeEqualTo("example.com");
        await profile.Port.Should().BeEqualTo(8443);
    }

    [Test]
    public async Task ApplySubOverrides_ShouldReplaceOnlyTheConfiguredValue()
    {
        var addressOnly = CreateProfile();
        ConfigHandler.ApplySubOverrides(addressOnly, new SubItem { OverrideAddress = "example.com" });
        await addressOnly.Address.Should().BeEqualTo("example.com");
        await addressOnly.Port.Should().BeEqualTo(443);

        var portOnly = CreateProfile();
        ConfigHandler.ApplySubOverrides(portOnly, new SubItem { OverridePort = 8443 });
        await portOnly.Address.Should().BeEqualTo("188.114.97.3");
        await portOnly.Port.Should().BeEqualTo(8443);
    }

    [Test]
    public async Task ApplySubOverrides_ShouldKeepProfileWhenNothingIsConfigured()
    {
        SubItem?[] subItems =
        [
            null,
            new SubItem(),
            new SubItem { OverrideAddress = "   ", OverridePort = 0 },
            new SubItem { OverridePort = 70000 },
        ];

        foreach (var subItem in subItems)
        {
            var profile = CreateProfile();

            ConfigHandler.ApplySubOverrides(profile, subItem);

            await profile.Address.Should().BeEqualTo("188.114.97.3");
            await profile.Port.Should().BeEqualTo(443);
        }
    }

    [Test]
    public async Task ApplySubOverrides_ShouldTrimAddress()
    {
        var profile = CreateProfile();

        ConfigHandler.ApplySubOverrides(profile, new SubItem { OverrideAddress = " example.com " });

        await profile.Address.Should().BeEqualTo("example.com");
    }
}
