using TUnit.Assertions.Enums;

namespace ServiceLib.Tests.CoreConfig.V2ray;

/// <summary>
/// PattN: a group of direct DNS servers (for the direct domains, the direct geosites, the domains of the direct expected
/// IPs, the domains of the proxy servers, and the DNS servers' own domains for the bootstrap DNS) ends the query on its
/// last server alone, as PattNG's does: every server of the group is asked in turn, and nothing after them, so these
/// names never reach the remote DNS.
/// </summary>
public class DnsFinalQueryTests
{
    private const string First = "223.5.5.5";
    private const string Second = "119.29.29.29";

    private static RulesItem Rule(string outboundTag, string domain)
    {
        return new RulesItem { Enabled = true, RuleType = ERuleType.DNS, OutboundTag = outboundTag, Domain = [domain] };
    }

    /// <summary>The DNS servers of the session's configuration, the plain fallback addresses left out.</summary>
    private static async Task<List<DnsServer4Ray>> Servers(Config config, List<RulesItem> rules, HashSet<string>? protectedDomains = null)
    {
        config.SimpleDNSItem.FakeIP = false;
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, "n-main", "main");
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray) with
        {
            RoutingItem = new RoutingItem
            {
                Id = "r-final-query",
                Remarks = "final-query",
                RuleSet = JsonUtils.Serialize(rules),
                DomainStrategy = Global.AsIs,
                DomainStrategy4Singbox = string.Empty,
            },
            ProtectDomainList = protectedDomains ?? [],
        };

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var dns = JsonUtils.Deserialize<Dns4Ray>(JsonUtils.Serialize(cfg.dns))!;
        return dns.servers
            .Select(server => JsonUtils.Deserialize<DnsServer4Ray>(JsonUtils.Serialize(server)))
            .Where(server => server is not null)
            .Cast<DnsServer4Ray>()
            .ToList();
    }

    /// <summary>The servers whose domains hold <paramref name="domain" />, in the order the core asks them.</summary>
    private static List<DnsServer4Ray> Holding(List<DnsServer4Ray> servers, string domain)
    {
        return servers.Where(server => server.domains?.Contains(domain) == true).ToList();
    }

    [Test]
    public async Task EachDirectGroupIsAskedInTurnAndEndsTheQueryOnItsLastServer()
    {
        var config = CoreConfigTestFactory.CreateConfigWithDirectExpectedIPs(ECoreType.Xray, "geoip:cn");
        config.SimpleDNSItem.DirectDNS = $"{First},{Second}";
        config.SimpleDNSItem.RemoteDNS = "9.9.9.9";
        var servers = await Servers(config,
            [
                Rule(Global.DirectTag, "domain:example.ir"),
                Rule(Global.DirectTag, "geosite:private"),
                Rule(Global.DirectTag, "geosite:cn"),
                Rule(Global.ProxyTag, "domain:example.com"),
            ],
            ["proxy.example"]);

        // The direct domains, the direct geosites, the domains of the expected IPs, the proxy server's domain.
        foreach (var domain in new[] { "domain:example.ir", "geosite:private", "geosite:cn", "full:proxy.example" })
        {
            var group = Holding(servers, domain);
            await group.Select(server => server.address).Should().BeEquivalentTo([First, Second], CollectionOrdering.Matching).Because(domain);
            await group[0].finalQuery.Should().BeNull().Because(domain);
            await group[1].finalQuery.Should().BeEqualTo(true).Because(domain);
        }
        await Holding(servers, "geosite:cn").All(server => server.expectedIPs?.SequenceEqual(["geoip:cn"]) == true).Should().BeTrue();
        // The remote server of a proxy rule ends nothing, as upstream's.
        await Holding(servers, "domain:example.com").Single().finalQuery.Should().BeNull();
    }

    [Test]
    public async Task TheBootstrapServersOfTheDnsServersDomainsAreAskedInTurnAndTheLastEndsTheQuery()
    {
        var config = CoreConfigTestFactory.CreateConfigWithBootstrapDNS(ECoreType.Xray, $"{First},{Second}");
        config.SimpleDNSItem.DirectDNS = "https://dns-direct.example/dns-query";
        config.SimpleDNSItem.RemoteDNS = "https://dns-remote.example/dns-query";
        var servers = await Servers(config, []);

        var group = Holding(servers, "full:dns-direct.example");
        await group.Select(server => server.address).Should().BeEquivalentTo([First, Second], CollectionOrdering.Matching);
        await group[0].finalQuery.Should().BeNull();
        await group[1].finalQuery.Should().BeEqualTo(true);
        await Holding(servers, "full:dns-remote.example").Count.Should().BeEqualTo(2);
    }

    [Test]
    public async Task ASingleDirectServerEndsTheQueryAsBefore()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        config.SimpleDNSItem.DirectDNS = First;
        config.SimpleDNSItem.RemoteDNS = "9.9.9.9";
        var servers = await Servers(config, [Rule(Global.DirectTag, "domain:example.ir")]);

        var single = Holding(servers, "domain:example.ir").Single();
        await single.address.Should().BeEqualTo(First);
        await single.finalQuery.Should().BeEqualTo(true);
    }
}
