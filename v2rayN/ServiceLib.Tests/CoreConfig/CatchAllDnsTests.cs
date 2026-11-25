namespace ServiceLib.Tests.CoreConfig;

/// <summary>
/// PattN: the names no rule lists are resolved where their traffic goes: by the direct DNS when the first rule that takes
/// everything sends it direct, else by the remote DNS. A rule after it that takes everything too is never reached, and
/// decides nothing (upstream counts any such rule for Xray, and only the last rule for sing-box).
/// </summary>
public class CatchAllDnsTests
{
    private const string DirectDns = "1.1.1.1";
    private const string RemoteDns = "9.9.9.9";

    private static RulesItem CatchAll(string outboundTag)
    {
        return new RulesItem { Enabled = true, OutboundTag = outboundTag, Port = "0-65535" };
    }

    private static RoutingItem Routing(params RulesItem[] catchAlls)
    {
        List<RulesItem> rules = [new RulesItem { Enabled = true, OutboundTag = Global.DirectTag, Domain = ["domain:example.ir"] }];
        rules.AddRange(catchAlls);
        return new RoutingItem
        {
            Id = "r-catch-all",
            Remarks = "catch-all",
            RuleSet = JsonUtils.Serialize(rules),
            DomainStrategy = Global.AsIs,
            DomainStrategy4Singbox = string.Empty,
        };
    }

    private static Config CreateConfig(ECoreType coreType)
    {
        var config = CoreConfigTestFactory.CreateConfig(coreType);
        config.SimpleDNSItem.DirectDNS = DirectDns;
        config.SimpleDNSItem.RemoteDNS = RemoteDns;
        config.SimpleDNSItem.FakeIP = false;
        CoreConfigTestFactory.BindAppManagerConfig(config);
        return config;
    }

    /// <summary>The servers Xray asks for a name no rule lists: those without domains, in order.</summary>
    private static async Task<string> XrayFallback(RoutingItem routing)
    {
        var config = CreateConfig(ECoreType.Xray);
        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, "n-main", "main");
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray) with { RoutingItem = routing };

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var servers = JsonNode.Parse(result.Data!.ToString()!)!["dns"]!["servers"]!.AsArray();
        return string.Join(" | ", servers
            .Where(server => server is JsonValue || server?["domains"] == null)
            .Select(server => server is JsonValue value ? value.GetValue<string>() : $"{server!["address"]} tag {server["tag"]}"));
    }

    private static async Task<string?> SingboxFinal(RoutingItem routing)
    {
        var config = CreateConfig(ECoreType.sing_box);
        var node = CoreConfigTestFactory.CreateSocksNode(ECoreType.sing_box, "n-main", "main");
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.sing_box) with { RoutingItem = routing };

        var result = new CoreConfigSingboxService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue().Because($"ret msg: {result.Msg}");
        return JsonUtils.Deserialize<SingboxConfig>(result.Data!.ToString())!.dns!.final;
    }

    [Test]
    public async Task ARuleThatTakesEverythingAfterOneThatProxiesItDecidesNothing()
    {
        var routing = Routing(CatchAll(Global.ProxyTag), CatchAll(Global.DirectTag));

        await (await XrayFallback(routing)).Should().BeEqualTo(RemoteDns);
        await (await SingboxFinal(routing)).Should().BeEqualTo(Global.SingboxRemoteDNSTag);
    }

    [Test]
    public async Task TheFirstRuleThatTakesEverythingDecidesWhereverItIs()
    {
        var routing = Routing(CatchAll(Global.DirectTag), CatchAll(Global.ProxyTag));

        await (await XrayFallback(routing)).Should().BeEqualTo($"{DirectDns} tag {Global.DirectDnsTag}");
        await (await SingboxFinal(routing)).Should().BeEqualTo(Global.SingboxDirectDNSTag);
    }

    [Test]
    public async Task ADisabledRuleThatTakesEverythingDecidesNothing()
    {
        var disabled = CatchAll(Global.DirectTag);
        disabled.Enabled = false;
        var routing = Routing(disabled);

        await (await XrayFallback(routing)).Should().BeEqualTo(RemoteDns);
        await (await SingboxFinal(routing)).Should().BeEqualTo(Global.SingboxRemoteDNSTag);
    }
}
