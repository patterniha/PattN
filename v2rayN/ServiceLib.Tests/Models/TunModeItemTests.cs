namespace ServiceLib.Tests.Models;

public class TunModeItemTests
{
    [Test]
    public async Task EnableIPv6Address_ShouldBeOnByDefault()
    {
        // PattN: a new config, whose TUN settings ConfigTextHandler.LoadConfig creates, has "Enable IPv6 Address" on, and
        // so does a stored one that lacks the value.
        await new TunModeItem().EnableIPv6Address.Should().BeTrue();
        await JsonUtils.Deserialize<TunModeItem>("""{"EnableTun":true}""")!.EnableIPv6Address.Should().BeTrue();
    }

    [Test]
    public async Task EnableIPv6Address_ShouldKeepTheSavedValue()
    {
        // The call ConfigTextHandler.SaveConfig makes, which writes every value: a config saved with the option off still
        // holds it.
        var saved = JsonUtils.Serialize(new Config { TunModeItem = new TunModeItem { EnableIPv6Address = false } }, true, true);

        var loaded = JsonUtils.Deserialize<Config>(saved)!;

        await loaded.TunModeItem.EnableIPv6Address.Should().BeFalse();
    }
}
