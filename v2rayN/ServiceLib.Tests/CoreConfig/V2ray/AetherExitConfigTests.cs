using TUnit.Assertions.Enums;

namespace ServiceLib.Tests.CoreConfig.V2ray;

/// <summary>
/// PattN (design 2.6.5, critique 19): the configuration of the short-lived Xray a scan or a key run dials out through,
/// beyond what AetherConfigTests checks: its port, and its DNS under the TUN.
/// </summary>
public class AetherExitConfigTests
{
    private static ProfileItem Dummy()
    {
        return AetherExitHost.ContextProfile();
    }

    private static JsonObject Generate(Config config, AetherExit exit, int port)
    {
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var context = CoreConfigTestFactory.CreateContext(config, Dummy(), ECoreType.Xray);
        var result = new CoreConfigV2rayService(context).GenerateAetherExitConfig(exit, port);
        if (result.Success != true)
        {
            throw new InvalidOperationException(result.Msg);
        }
        return JsonNode.Parse(result.Data!.ToString()!)!.AsObject();
    }

    [Test]
    public async Task TheExitListensOnTheLoopbackPortItIsGivenAndSendsAllOfItOutByTheExitNode()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);

        var node = Generate(config, AetherExit.Plain, 41960);

        var inbound = node["inbounds"]!.AsArray().Single()!;
        await inbound["listen"]!.GetValue<string>().Should().BeEqualTo(Global.Loopback);
        await inbound["port"]!.GetValue<int>().Should().BeEqualTo(41960);
        await inbound["protocol"]!.GetValue<string>().Should().BeEqualTo("mixed");
        await inbound["settings"]!["udp"]!.GetValue<bool>().Should().BeTrue();
        var rule = node["routing"]!["rules"]!.AsArray().Single()!;
        await rule["inboundTag"]!.AsArray().Select(tag => tag!.GetValue<string>()).Should()
            .BeEquivalentTo([Global.AetherSecondarySocksTag], CollectionOrdering.Matching);
        await rule["outboundTag"]!.GetValue<string>().Should().BeEqualTo(Global.AetherExitNodeTag);
        // Without the TUN the freedom exit-node resolves as the system does, and no DNS is set up.
        await (node["outbounds"]![0]!["streamSettings"]?["sockopt"]?["domainStrategy"]).Should().BeNull();
        await (node["dns"] is null).Should().BeTrue();
    }

    [Test]
    public async Task UnderTheTunTheFreedomExitNodeResolvesWithTheDirectDns()
    {
        // Critique 19: the system resolver's queries would enter the TUN, and reach the remote DNS through the very core
        // that is starting.
        var config = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, enableIPv6Address: false);
        config.SimpleDNSItem.DirectDNS = "223.5.5.5, udp://119.29.29.29:53";

        var node = Generate(config, AetherExit.Plain, 41961);

        var exitNode = node["outbounds"]!.AsArray().Single()!;
        await exitNode["protocol"]!.GetValue<string>().Should().BeEqualTo("freedom");
        await exitNode["streamSettings"]!["sockopt"]!["domainStrategy"]!.GetValue<string>().Should().BeEqualTo("ForceIP");
        // It races the addresses it finds, as the session's direct outbound does: a random one of them may not route.
        await (exitNode["streamSettings"]!["sockopt"]!["happyEyeballs"]!["tryDelayMs"]!.GetValue<int>() > 0).Should().BeTrue();
        var servers = node["dns"]!["servers"]!.AsArray().Select(server => server!.AsObject()).ToList();
        await servers.Select(server => server["address"]!.GetValue<string>()).Should()
            .BeEquivalentTo(["223.5.5.5", "119.29.29.29"], CollectionOrdering.Matching);
        await servers[1]["port"]!.GetValue<int>().Should().BeEqualTo(53);
        // Servers with no domains of their own answer every name.
        await servers.All(server => server["domains"] is null && server["skipFallback"] is null).Should().BeTrue();
    }

    [Test]
    public async Task ADirectDnsNamedByItsDomainIsLookedUpWithTheBootstrapDnsFirst()
    {
        var config = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, enableIPv6Address: false);
        config.SimpleDNSItem.DirectDNS = "https://dns.alidns.com/dns-query";
        config.SimpleDNSItem.BootstrapDNS = "223.5.5.5";

        var node = Generate(config, AetherExit.Plain, 41962);

        var servers = node["dns"]!["servers"]!.AsArray().Select(server => server!.AsObject()).ToList();
        await servers.Count.Should().BeEqualTo(2);
        await servers[0]["address"]!.GetValue<string>().Should().BeEqualTo("223.5.5.5");
        await servers[0]["domains"]!.AsArray().Select(domain => domain!.GetValue<string>()).Should()
            .BeEquivalentTo(["full:dns.alidns.com"], CollectionOrdering.Matching);
        await servers[0]["finalQuery"]!.GetValue<bool>().Should().BeTrue();
        await servers[1]["address"]!.GetValue<string>().Should().BeEqualTo("https://dns.alidns.com/dns-query");
    }

    [Test]
    public async Task EveryBootstrapServerIsAskedInTurnAndTheLastEndsTheQuery()
    {
        var config = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, enableIPv6Address: false);
        config.SimpleDNSItem.DirectDNS = "https://dns.alidns.com/dns-query";
        config.SimpleDNSItem.BootstrapDNS = "223.5.5.5, 119.29.29.29";

        var node = Generate(config, AetherExit.Plain, 41965);

        var servers = node["dns"]!["servers"]!.AsArray().Select(server => server!.AsObject()).ToList();
        await servers.Select(server => server["address"]!.GetValue<string>()).Should()
            .BeEquivalentTo(["223.5.5.5", "119.29.29.29", "https://dns.alidns.com/dns-query"], CollectionOrdering.Matching);
        // As in the session's DNS: the first does not end the query, so the second is asked when it gives nothing.
        await servers[0].ContainsKey("finalQuery").Should().BeFalse();
        await servers[1]["finalQuery"]!.GetValue<bool>().Should().BeTrue();
    }

    [Test]
    public async Task UnderTheTunTheExitResolvesByTheFamilyOfTheDirectOutbound()
    {
        var config = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, enableIPv6Address: false);
        config.SimpleDNSItem.Strategy4Freedom = "UseIPv4";

        var node = Generate(config, AetherExit.Plain, 41964);

        await node["outbounds"]![0]!["streamSettings"]!["sockopt"]!["domainStrategy"]!.GetValue<string>().Should().BeEqualTo("ForceIPv4");
    }

    // The freedom exit-node of a scan or a key run carries the core's own connection to its server, as the session's does.
    [Test]
    public async Task TheFreedomExitNodeIsBoundAsAProxysServerConnectionIs()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        config.CoreBasicItem.BindInterface = "Ethernet 2";
        config.CoreBasicItem.SendThrough = "192.0.2.20";

        var exitNode = Generate(config, AetherExit.Plain, 41965)["outbounds"]![0]!;

        await exitNode["sendThrough"]!.GetValue<string>().Should().BeEqualTo("192.0.2.20");
        await exitNode["streamSettings"]!["sockopt"]!["interface"]!.GetValue<string>().Should().BeEqualTo("Ethernet 2");
    }

    [Test]
    public async Task UnderTheTunTheExitTakesTheDefaultDirectDnsWhenNoneIsSet()
    {
        var config = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, enableIPv6Address: false);
        config.SimpleDNSItem.DirectDNS = " ";

        var node = Generate(config, new AetherExit(FinalMask: null, DialMode: "code-1"), 41963);

        var servers = node["dns"]!["servers"]!.AsArray();
        await servers.Count.Should().BeEqualTo(1);
        await servers[0]!["address"]!.GetValue<string>().Should().BeEqualTo(Global.DomainDirectDNSAddress.First());
        await node["outbounds"]![0]!["streamSettings"]!["sockopt"]!["dialMode"]!.GetValue<string>().Should().BeEqualTo("code-1");
    }
}
