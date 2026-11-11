namespace ServiceLib.Tests.CoreConfig.V2ray;

public class CoreConfigV2rayIPNetworkTests
{
    [Test]
    [Arguments("0.0.0.0/0", "::/0")]
    [Arguments("::/0", "0.0.0.0/0")]
    [Arguments("0.0.0.0/1", "128.0.0.0/1,::/0")]
    [Arguments("::/1", "0.0.0.0/0,8000::/1")]
    public async Task GenerateClientConfigContent_TunExclusion_ShouldPreserveRemainingRoutes(
        string excludedNetwork, string expectedRoutes)
    {
        var config = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, true);
        config.TunModeItem.RouteExcludeAddress = [excludedNetwork];
        var generated = await GenerateConfig(config);

        var routes = generated.inbounds.Single(i => i.protocol == "tun").settings.autoSystemRoutingTable;
        await routes.Should().BeEquivalentTo(expectedRoutes.Split(','), StringComparer.Ordinal);
    }

    [Test]
    public async Task GenerateClientConfigContent_TunExclusions_ShouldHandleOverlappingAndDuplicateNetworks()
    {
        var config = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, true);
        config.TunModeItem.RouteExcludeAddress =
        [
            "0.0.0.0/1", "128.0.0.1/2", "128.0.0.1/2", "128.0.0.1/32",
            "::/1", "8000::1/2", "8000::1/128"
        ];
        var generated = await GenerateConfig(config);

        var routes = generated.inbounds.Single(i => i.protocol == "tun").settings.autoSystemRoutingTable;
        await routes.Should().BeEquivalentTo(new[] { "192.0.0.0/2", "c000::/2" }, StringComparer.Ordinal);
    }

    [Test]
    public async Task GenerateClientConfigContent_TunExclusions_ShouldAllowExcludingBothAddressFamilies()
    {
        var config = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, true);
        config.TunModeItem.RouteExcludeAddress = ["0.0.0.0/0", "::/0"];
        var generated = await GenerateConfig(config);

        var routes = generated.inbounds.Single(i => i.protocol == "tun").settings.autoSystemRoutingTable;
        await routes.Should().BeEmpty();
    }

    [Test]
    public async Task GenerateClientConfigContent_TunHostExclusions_ShouldPreserveNeighbouringAddresses()
    {
        var config = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, true);
        config.TunModeItem.RouteExcludeAddress =
        [
            "0.0.0.0/32", "255.255.255.255/32",
            "::/128", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"
        ];
        var generated = await GenerateConfig(config);
        var routes = generated.inbounds.Single(i => i.protocol == "tun").settings.autoSystemRoutingTable
            .Select(IPNetwork.Parse).ToArray();

        foreach (var address in new[]
                 {
                     "0.0.0.0", "255.255.255.255", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
                 })
        {
            await routes.Any(route => route.Contains(IPAddress.Parse(address))).Should().BeFalse();
        }
        foreach (var address in new[]
                 {
                     "0.0.0.1", "255.255.255.254", "::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"
                 })
        {
            await routes.Any(route => route.Contains(IPAddress.Parse(address))).Should().BeTrue();
        }
    }

    // PattN: the IPv4 pool by the IPv6 one's rule, min(addresses - 1, 65535), and an unusable range refused
    [Test]
    [Arguments("198.18.0.0/15", "198.18.0.0/15", 65535L)]
    [Arguments("198.18.0.1/15", "198.18.0.0/15", 65535L)]
    [Arguments("0.0.0.0/0", "0.0.0.0/0", 65535L)]
    [Arguments("198.18.0.0/16", "198.18.0.0/16", 65535L)]
    [Arguments("198.18.0.0/17", "198.18.0.0/17", 32767L)]
    [Arguments("198.18.0.0/24", "198.18.0.0/24", 255L)]
    [Arguments("198.18.0.0/31", "198.18.0.0/31", 1L)]
    public async Task GenerateClientConfigContent_FakeDns_ShouldSizeTheIPv4PoolAsTheIPv6One(
        string range, string expectedRange, long expectedPoolSize)
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        config.SimpleDNSItem.FakeIP = true;
        config.SimpleDNSItem.FakeIPRange = range;
        // PattN: the IPv4 pool alone, as IPv6 FakeIP is on by default
        config.SimpleDNSItem.FakeIPv6 = false;
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray);
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);
        context.RoutingItem!.RuleSet = JsonUtils.Serialize(new List<RulesItem>
        {
            new()
            {
                Enabled = true,
                RuleType = ERuleType.DNS,
                OutboundTag = Global.ProxyTag,
                Domain = ["full:example.com"],
            }
        });
        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();
        await result.Success.Should().BeTrue();
        var generated = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;

        await generated.fakedns.Should().NotBeNull();
        await generated.fakedns!["ipPool"]!.GetValue<string>().Should().BeEqualTo(expectedRange);
        await generated.fakedns["poolSize"]!.GetValue<long>().Should().BeEqualTo(expectedPoolSize);
    }

    [Test]
    [Arguments("198.18.0.1/32")]
    [Arguments("198.18.0.0/33")]
    [Arguments("fd00::/64")]
    [Arguments("invalid-network")]
    public async Task GenerateClientConfigContent_FakeDns_ShouldRefuseAnUnusableIPv4Range(string range)
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        config.SimpleDNSItem.FakeIP = true;
        config.SimpleDNSItem.FakeIPRange = range;
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray);
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);
        context.RoutingItem!.RuleSet = JsonUtils.Serialize(new List<RulesItem>
        {
            new()
            {
                Enabled = true,
                RuleType = ERuleType.DNS,
                OutboundTag = Global.ProxyTag,
                Domain = ["full:example.com"],
            }
        });

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeFalse();
    }

    private static async Task<V2rayConfig> GenerateConfig(Config config)
    {
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray);
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);
        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var generated = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString());
        await generated.Should().NotBeNull();
        return generated!;
    }
}
