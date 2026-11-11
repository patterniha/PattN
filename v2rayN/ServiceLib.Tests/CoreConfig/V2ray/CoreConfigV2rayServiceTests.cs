namespace ServiceLib.Tests.CoreConfig.V2ray;

public class CoreConfigV2rayServiceTests
{
    [Test]
    [Arguments(null)]
    [Arguments("")]
    [Arguments("AGH+DQBdAAAgACBAi73MnT3WWXWj4M9MUiTygpjSPUfM/Rj3Iasve4uFQAAkAAEAAQABAAIAAQADAAIAAQACAAIAAgADAAMAAQADAAIAAwADAA5vdXRlci5lY2gudGVzdAAA")]
    [Arguments("https://dns.example.com/dns-query")]
    [Arguments("udp://127.0.0.1:5353")]
    [Arguments("ech.example.com+https://dns.example.com/dns-query")]
    public async Task GenerateClientConfigContent_Tls_ShouldPreserveEchConfigWithoutLegacyQueryOption(string? echConfigList)
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray);
        node.StreamSecurity = Global.StreamSecurity;
        node.Sni = "ech.example.com";
        node.EchConfigList = echConfigList;
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var generatedConfig = JsonNode.Parse(result.Data!.ToString()!)!;
        var proxy = generatedConfig["outbounds"]!.AsArray()
            .First(outbound => outbound!["tag"]!.GetValue<string>() == Global.ProxyTag)!;
        var tls = proxy["streamSettings"]!["tlsSettings"]!.AsObject();

        await tls["serverName"]!.GetValue<string>().Should().BeEqualTo("ech.example.com");
        if (string.IsNullOrEmpty(echConfigList))
        {
            await tls.ContainsKey("echConfigList").Should().BeFalse();
        }
        else
        {
            await tls["echConfigList"]!.GetValue<string>().Should().BeEqualTo(echConfigList);
        }
        await tls.ContainsKey("echForceQuery").Should().BeFalse();
    }

    [Test]
    public async Task GenerateClientConfigContent_ShouldGenerateBasicProxyConfig()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray);
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        await result.Data.Should().NotBeNull();

        var v2rayConfig = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString());
        await v2rayConfig.Should().NotBeNull();
        await v2rayConfig!.outbounds.Should().Contain(o => o.tag == Global.ProxyTag && o.protocol == "vmess");
        await v2rayConfig.inbounds.Should().Contain(i => i.protocol == nameof(EInboundProtocol.mixed));
    }

    [Test]
    public async Task GenerateClientConfigContent_RealityFragment_ShouldUsePacketRangeOnlyForReality()
    {
        static ProfileItem CreateVlessNode(string indexId, string streamSecurity)
        {
            var node = new ProfileItem
            {
                IndexId = indexId,
                ConfigType = EConfigType.VLESS,
                CoreType = ECoreType.Xray,
                Remarks = indexId,
                Address = "example.com",
                Port = 443,
                Password = "01234567-89ab-cdef-0123-456789abcdef",
                Network = nameof(ETransport.raw),
                StreamSecurity = streamSecurity,
                PublicKey = "test-public-key",
                Sni = "example.com",
                Fingerprint = "chrome",
            };
            node.SetProtocolExtra(new ProtocolExtraItem { VlessEncryption = Global.None });
            node.SetTransportExtra(new TransportExtraItem { RawHeaderType = Global.None });
            return node;
        }

        static string GetFragmentPackets(Outbounds4Ray outbound)
        {
            var finalmask = JsonUtils.ParseJson(JsonUtils.Serialize(outbound.streamSettings!.finalmask));
            return finalmask!["tcp"]![0]!["settings"]!["packets"]!.GetValue<string>();
        }

        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        config.CoreBasicItem.EnableFragment = true;
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var tlsNode = CreateVlessNode("tls-node", Global.StreamSecurity);
        var realityNode = CreateVlessNode("reality-node", Global.StreamSecurityReality);
        var group = CoreConfigTestFactory.CreatePolicyGroupNode(ECoreType.Xray, "group", "group",
            [tlsNode.IndexId, realityNode.IndexId]);
        var context = CoreConfigTestFactory.CreateContext(config, group, ECoreType.Xray);
        context.AllProxiesMap[tlsNode.IndexId] = tlsNode;
        context.AllProxiesMap[realityNode.IndexId] = realityNode;
        context.AllProxiesMap[group.IndexId] = group;

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var tlsOutbound = cfg.outbounds.Single(o => o.streamSettings?.security == Global.StreamSecurity);
        var realityOutbound = cfg.outbounds.Single(o => o.streamSettings?.security == Global.StreamSecurityReality);

        await GetFragmentPackets(tlsOutbound).Should().BeEqualTo("tlshello");
        await GetFragmentPackets(realityOutbound).Should().BeEqualTo("1-3");
    }

    [Test]
    public async Task GenerateClientConfigContent_HttpOutbound_ShouldEmitHeadersInSettings()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = CoreConfigTestFactory.CreateHttpNode(ECoreType.Xray);
        node.SetProtocolExtra(node.GetProtocolExtra() with
        {
            HttpHeaders = "{\"User-Agent\":\"v2rayN\",\"Set-Cookie\":[\"a=1\",\"b=2\"]}",
        });
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var outbound = cfg.outbounds.First(o => o.tag == Global.ProxyTag && o.protocol == "http");

        await outbound.settings.address!.ToString().Should().BeEqualTo("proxy.example.com");
        await outbound.settings.port.Should().BeEqualTo(8080);
        await outbound.settings.user.Should().BeEqualTo("user");
        await outbound.settings.pass.Should().BeEqualTo("pass");
        // PattN removes user levels from outbounds; all sessions run at level 0 (policy "0")
        await outbound.settings.level.Should().BeNull();
        await outbound.settings.headers.Should().NotBeNull();
        var headers = JsonUtils.ParseJson(outbound.settings.headers!.ToString());
        await headers["User-Agent"]!.GetValue<string>().Should().BeEqualTo("v2rayN");
        await headers["Set-Cookie"]!.AsArray()
            .Select(item => item!.GetValue<string>())
            .Order(StringComparer.Ordinal).SequenceEqual(["a=1", "b=2"])
            .Should().BeTrue();
    }

    [Test]
    public async Task GenerateClientConfigContent_PolicyGroup_ShouldExpandChildrenAndBuildBalancer()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var n1 = CoreConfigTestFactory.CreateSocksNode(ECoreType.Xray, "n1", "node-1");
        var n2 = CoreConfigTestFactory.CreateSocksNode(ECoreType.Xray, "n2", "node-2");
        var group = CoreConfigTestFactory.CreatePolicyGroupNode(ECoreType.Xray, "g1", "group",
            [n1.IndexId, n2.IndexId]);

        var context = CoreConfigTestFactory.CreateContext(config, group, ECoreType.Xray);
        context.AllProxiesMap[n1.IndexId] = n1;
        context.AllProxiesMap[n2.IndexId] = n2;
        context.AllProxiesMap[group.IndexId] = group;

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;

        await cfg.outbounds.Should().Contain(o => o.tag.StartsWith("proxy-1-", StringComparison.Ordinal));
        await cfg.outbounds.Should().Contain(o => o.tag.StartsWith("proxy-2-", StringComparison.Ordinal));
        await cfg.routing.balancers.Should().NotBeNull();
        await cfg.routing.balancers!.Should().Contain(b => b.tag == Global.ProxyTag + Global.BalancerTagSuffix);
    }

    [Test]
    public async Task GenerateClientConfigContent_ProxyChain_ShouldBuildDialerProxyChain()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var n1 = CoreConfigTestFactory.CreateSocksNode(ECoreType.Xray, "n1", "node-1");
        var n2 = CoreConfigTestFactory.CreateSocksNode(ECoreType.Xray, "n2", "node-2");
        var chain = CoreConfigTestFactory.CreateProxyChainNode(ECoreType.Xray, "c1", "chain", [n1.IndexId, n2.IndexId]);

        var context = CoreConfigTestFactory.CreateContext(config, chain, ECoreType.Xray);
        context.AllProxiesMap[n1.IndexId] = n1;
        context.AllProxiesMap[n2.IndexId] = n2;
        context.AllProxiesMap[chain.IndexId] = chain;

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;

        await cfg.outbounds.Should().Contain(o => o.tag.StartsWith("chain-proxy-1-", StringComparison.Ordinal));
        var hasDialerChain = cfg.outbounds.Any(o =>
            o.tag == Global.ProxyTag
            && o.streamSettings is not null
            && o.streamSettings.sockopt is not null
            && (o.streamSettings.sockopt.dialerProxy ?? string.Empty).StartsWith("chain-proxy-1-",
                StringComparison.Ordinal));
        await hasDialerChain.Should().BeTrue();
    }

    [Test]
    public async Task GenerateClientConfigContent_DialMode_ShouldFillProxySockopt()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray);
        node.DialMode = "code-1";
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var proxy = cfg.outbounds.First(o => o.tag == Global.ProxyTag);
        await proxy.streamSettings!.sockopt!.dialMode.Should().BeEqualTo("code-1");
    }

    [Test]
    public async Task GenerateClientConfigContent_DialModeWireGuard_ShouldFillSockopt()
    {
        // WireGuard has no transport, but Xray dials its endpoint through the system dialer
        // with streamSettings.sockopt, so dialMode must reach that outbound too.
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = CoreConfigTestFactory.CreateWireguardNode(ECoreType.Xray);
        node.DialMode = "code-1";
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var proxy = cfg.outbounds.First(o => o.tag == Global.ProxyTag);
        await proxy.protocol.Should().BeEqualTo("wireguard");
        await proxy.streamSettings!.sockopt!.dialMode.Should().BeEqualTo("code-1");
    }

    [Test]
    public async Task GenerateClientConfigContent_DialModeWithFullConfigTemplate_ShouldKeepProxySockopt()
    {
        // A full config template replaces everything except the generated outbounds, which are copied
        // into it verbatim, so dialMode set on the profile still reaches the final proxy outbound.
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray);
        node.DialMode = "code-1";
        var template = new FullConfigTemplateItem
        {
            Id = "t1",
            Remarks = "template",
            Enabled = true,
            CoreType = ECoreType.Xray,
            AddProxyOnly = true,
            Config = """
                {
                  "log": { "loglevel": "warning" },
                  "inbounds": [ { "tag": "socks-in", "port": 10808, "protocol": "socks" } ],
                  "outbounds": [ { "tag": "direct", "protocol": "freedom" } ],
                  "routing": { "rules": [ { "type": "field", "network": "tcp,udp", "outboundTag": "proxy" } ] }
                }
                """,
        };
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray, fullConfigTemplate: template);

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var proxy = cfg.outbounds.First(o => o.tag == Global.ProxyTag);
        await proxy.protocol.Should().BeEqualTo("vmess");
        await proxy.streamSettings!.sockopt!.dialMode.Should().BeEqualTo("code-1");
        await cfg.outbounds.Should().Contain(o => o.tag == "direct" && o.protocol == "freedom");
        await cfg.inbounds.Should().Contain(i => i.tag == "socks-in");
    }

    [Test]
    public async Task GenerateClientConfigContent_DialModeWithProxyChain_ShouldKeepDialerProxy()
    {
        // dialMode is merged into sockopt rather than replacing it, so the dialerProxy of the chain survives.
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var n1 = CoreConfigTestFactory.CreateSocksNode(ECoreType.Xray, "n1", "node-1");
        var n2 = CoreConfigTestFactory.CreateSocksNode(ECoreType.Xray, "n2", "node-2");
        n1.DialMode = "code-1";
        n2.DialMode = "code-1";
        var chain = CoreConfigTestFactory.CreateProxyChainNode(ECoreType.Xray, "c1", "chain", [n1.IndexId, n2.IndexId]);

        var context = CoreConfigTestFactory.CreateContext(config, chain, ECoreType.Xray);
        context.AllProxiesMap[n1.IndexId] = n1;
        context.AllProxiesMap[n2.IndexId] = n2;
        context.AllProxiesMap[chain.IndexId] = chain;

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var proxy = cfg.outbounds.First(o => o.tag == Global.ProxyTag);
        await proxy.streamSettings!.sockopt!.dialMode.Should().BeEqualTo("code-1");
        await (proxy.streamSettings.sockopt.dialerProxy ?? string.Empty).StartsWith("chain-proxy-1-", StringComparison.Ordinal).Should().BeTrue();
    }

    [Test]
    public async Task GenerateClientConfigContent_PolicyGroupWithProxyChain_ShouldBuildCombinedOutbounds()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var n1 = CoreConfigTestFactory.CreateSocksNode(ECoreType.Xray, "n1", "node-1");
        var n2 = CoreConfigTestFactory.CreateSocksNode(ECoreType.Xray, "n2", "node-2");
        var n3 = CoreConfigTestFactory.CreateSocksNode(ECoreType.Xray, "n3", "node-3");
        var chain = CoreConfigTestFactory.CreateProxyChainNode(ECoreType.Xray, "c1", "chain", [n1.IndexId, n2.IndexId]);
        var group = CoreConfigTestFactory.CreatePolicyGroupNode(ECoreType.Xray, "g1", "group",
            [chain.IndexId, n3.IndexId]);

        var context = CoreConfigTestFactory.CreateContext(config, group, ECoreType.Xray);
        context.AllProxiesMap[n1.IndexId] = n1;
        context.AllProxiesMap[n2.IndexId] = n2;
        context.AllProxiesMap[n3.IndexId] = n3;
        context.AllProxiesMap[chain.IndexId] = chain;
        context.AllProxiesMap[group.IndexId] = group;

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;

        await cfg.outbounds.Should().Contain(o => o.tag.StartsWith("proxy-1-", StringComparison.Ordinal));
        await cfg.outbounds.Should().Contain(o => o.tag.StartsWith("chain-proxy-1-", StringComparison.Ordinal));
        await cfg.outbounds.Should().Contain(o => o.tag.StartsWith("proxy-2-", StringComparison.Ordinal));
        await cfg.routing.balancers.Should().NotBeNull();
        await cfg.routing.balancers!.Should().Contain(b => b.tag == Global.ProxyTag + Global.BalancerTagSuffix);
    }

    [Test]
    public async Task GenerateClientConfigContent_ProxyChainWithPolicyGroup_ShouldBuildClonedChainBranches()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var n1 = CoreConfigTestFactory.CreateSocksNode(ECoreType.Xray, "n1", "node-1");
        var n2 = CoreConfigTestFactory.CreateSocksNode(ECoreType.Xray, "n2", "node-2");
        var n3 = CoreConfigTestFactory.CreateSocksNode(ECoreType.Xray, "n3", "node-3");
        var group = CoreConfigTestFactory.CreatePolicyGroupNode(ECoreType.Xray, "g1", "group",
            [n1.IndexId, n2.IndexId]);
        var chain = CoreConfigTestFactory.CreateProxyChainNode(ECoreType.Xray, "c1", "chain",
            [group.IndexId, n3.IndexId]);

        var context = CoreConfigTestFactory.CreateContext(config, chain, ECoreType.Xray);
        context.AllProxiesMap[n1.IndexId] = n1;
        context.AllProxiesMap[n2.IndexId] = n2;
        context.AllProxiesMap[n3.IndexId] = n3;
        context.AllProxiesMap[group.IndexId] = group;
        context.AllProxiesMap[chain.IndexId] = chain;

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;

        await cfg.outbounds.Should().Contain(o => o.tag.StartsWith("chain-proxy-1-group-1-", StringComparison.Ordinal));
        await cfg.outbounds.Should().Contain(o => o.tag.StartsWith("chain-proxy-1-group-2-", StringComparison.Ordinal));

        var proxyCloneCount = cfg.outbounds.Count(o => o.tag.StartsWith("proxy-clone-", StringComparison.Ordinal));
        await proxyCloneCount.Should().BeEqualTo(2);

        var allCloneDialersPointToGroupBranches = cfg.outbounds
            .Where(o => o.tag.StartsWith("proxy-clone-", StringComparison.Ordinal))
            .All(o => (o.streamSettings?.sockopt?.dialerProxy ?? string.Empty).StartsWith("chain-proxy-1-group-",
                StringComparison.Ordinal));
        await allCloneDialersPointToGroupBranches.Should().BeTrue();

        await cfg.routing.balancers.Should().NotBeNull();
        await cfg.routing.balancers!.Should().Contain(b => b.tag == Global.ProxyTag + Global.BalancerTagSuffix);
    }

    [Test]
    public async Task GenerateClientConfigContent_RoutingSplit_DirectAndBlock_ShouldApplyRules()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, "n-main", "main");
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray) with
        {
            RoutingItem = new RoutingItem
            {
                Id = "r-split-1",
                Remarks = "split-direct-block",
                RuleSet = JsonUtils.Serialize(new List<RulesItem>
                {
                    new()
                    {
                        Enabled = true,
                        RuleType = ERuleType.Routing,
                        OutboundTag = Global.DirectTag,
                        Domain = ["full:direct.example.com"],
                    },
                    new()
                    {
                        Enabled = true,
                        RuleType = ERuleType.Routing,
                        OutboundTag = Global.BlockTag,
                        Domain = ["full:block.example.com"],
                    }
                }),
                DomainStrategy = Global.AsIs,
                DomainStrategy4Singbox = string.Empty,
            }
        };

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;

        var hasDirectRule = cfg.routing.rules.Any(r =>
            r.domain != null
            && r.domain.Contains("full:direct.example.com")
            && r.outboundTag == Global.DirectTag);
        await hasDirectRule.Should().BeTrue();

        var hasBlockRule = cfg.routing.rules.Any(r =>
            r.domain != null
            && r.domain.Contains("full:block.example.com")
            && r.outboundTag == Global.BlockTag);
        await hasBlockRule.Should().BeTrue();
    }

    [Test]
    public async Task GenerateClientConfigContent_RoutingSplit_ByRemark_ShouldGenerateTargetOutbound()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, "n-main", "main");
        var routeNode = CoreConfigTestFactory.CreateSocksNode(ECoreType.Xray, "n-route", "route-node");

        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray) with
        {
            RoutingItem = new RoutingItem
            {
                Id = "r-split-2",
                Remarks = "split-remark",
                RuleSet = JsonUtils.Serialize(new List<RulesItem>
                {
                    new()
                    {
                        Enabled = true,
                        RuleType = ERuleType.Routing,
                        OutboundTag = routeNode.Remarks,
                        Domain = ["full:route.example.com"],
                    }
                }),
                DomainStrategy = Global.AsIs,
                DomainStrategy4Singbox = string.Empty,
            }
        };
        context.AllProxiesMap[$"remark:{routeNode.Remarks}"] = routeNode;

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var expectedPrefix = $"{routeNode.IndexId}-{Global.ProxyTag}-{routeNode.Remarks}";

        await cfg.outbounds.Should().Contain(o => o.tag.StartsWith(expectedPrefix, StringComparison.Ordinal));
        var hasRouteRule = cfg.routing.rules.Any(r =>
            r.domain != null
            && r.domain.Contains("full:route.example.com")
            && (r.outboundTag ?? string.Empty).StartsWith(expectedPrefix, StringComparison.Ordinal));
        await hasRouteRule.Should().BeTrue();
    }

    [Test]
    public async Task GenerateClientConfigContent_DirectExpectedIPs_ShouldApplyExpectedIPsToDirectDnsServer()
    {
        var config = CoreConfigTestFactory.CreateConfigWithDirectExpectedIPs(ECoreType.Xray, "192.168.0.0/16,geoip:cn");
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, "n-main", "main");
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray) with
        {
            RoutingItem = new RoutingItem
            {
                Id = "r-dns-direct-expected",
                Remarks = "dns-direct-expected",
                RuleSet = JsonUtils.Serialize(new List<RulesItem>
                {
                    new()
                    {
                        Enabled = true,
                        RuleType = ERuleType.DNS,
                        OutboundTag = Global.DirectTag,
                        Domain = ["geosite:cn"],
                    }
                }),
                DomainStrategy = Global.AsIs,
                DomainStrategy4Singbox = string.Empty,
            }
        };

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var dns = JsonUtils.Deserialize<Dns4Ray>(JsonUtils.Serialize(cfg.dns))!;

        var dnsServers = dns.servers
            .Select(s => JsonUtils.Deserialize<DnsServer4Ray>(JsonUtils.Serialize(s)))
            .Where(s => s is not null)
            .Cast<DnsServer4Ray>()
            .ToList();

        var hasExpectedServer = dnsServers.Any(s =>
            (s.tag ?? string.Empty).StartsWith(Global.DirectDnsTag, StringComparison.Ordinal)
            && s.domains?.Contains("geosite:cn") == true
            && s.expectedIPs?.Contains("192.168.0.0/16") == true
            && s.expectedIPs?.Contains("geoip:cn") == true);
        await hasExpectedServer.Should().BeTrue();
    }

    [Test]
    public async Task GenerateClientConfigContent_BootstrapDNS_ShouldApplyToDnsServerDomains()
    {
        var bootstrapDns = "8.8.8.8";
        var config = CoreConfigTestFactory.CreateConfigWithBootstrapDNS(ECoreType.Xray, bootstrapDns);
        config.SimpleDNSItem.DirectDNS = "https://dns-direct.example/dns-query";
        config.SimpleDNSItem.RemoteDNS = "https://dns-remote.example/dns-query";
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, "n-main", "main");
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var dns = JsonUtils.Deserialize<Dns4Ray>(JsonUtils.Serialize(cfg.dns))!;

        var dnsServers = dns.servers
            .Select(s => JsonUtils.Deserialize<DnsServer4Ray>(JsonUtils.Serialize(s)))
            .Where(s => s is not null)
            .Cast<DnsServer4Ray>()
            .ToList();

        var hasBootstrapServer = dnsServers.Any(s =>
            s.address == bootstrapDns
            && s.domains?.Contains("full:dns-direct.example") == true
            && s.domains?.Contains("full:dns-remote.example") == true);
        await hasBootstrapServer.Should().BeTrue();
    }

    [Test]
    public async Task GenerateClientConfigContent_DnsFallback_LastRuleDirect_ShouldUseDirectDnsServers()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        config.SimpleDNSItem.DirectDNS = "1.1.1.1";
        config.SimpleDNSItem.RemoteDNS = "9.9.9.9";
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, "n-main", "main");
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray) with
        {
            RoutingItem = new RoutingItem
            {
                Id = "r-direct-final",
                Remarks = "direct-final",
                RuleSet = JsonUtils.Serialize(new List<RulesItem>
                {
                    new()
                    {
                        Enabled = true,
                        RuleType = ERuleType.Routing,
                        OutboundTag = Global.DirectTag,
                        Ip = ["0.0.0.0/0"],
                        Port = "0-65535",
                        Network = "tcp,udp",
                    }
                }),
                DomainStrategy = Global.AsIs,
                DomainStrategy4Singbox = string.Empty,
            }
        };

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var dns = JsonUtils.Deserialize<Dns4Ray>(JsonUtils.Serialize(cfg.dns))!;
        var dnsServers = dns.servers
            .Select(s => JsonUtils.Deserialize<DnsServer4Ray>(JsonUtils.Serialize(s)))
            .Where(s => s is not null)
            .Cast<DnsServer4Ray>()
            .ToList();

        var hasDirectFallback = dnsServers.Any(s =>
            (s.tag ?? string.Empty).StartsWith(Global.DirectDnsTag, StringComparison.Ordinal)
            && s.address == "1.1.1.1");
        await hasDirectFallback.Should().BeTrue();

        var hasRemoteFallback = dnsServers.Any(s => s.address == "9.9.9.9");
        await hasRemoteFallback.Should().BeFalse();
    }

    [Test]
    public async Task GenerateClientConfigContent_DirectExpectedIPs_NonMatchingRegion_ShouldNotApplyExpectedIPs()
    {
        var config = CoreConfigTestFactory.CreateConfigWithDirectExpectedIPs(ECoreType.Xray, "192.168.0.0/16,geoip:cn");
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, "n-main", "main");
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray) with
        {
            RoutingItem = new RoutingItem
            {
                Id = "r-dns-direct-unmatched",
                Remarks = "dns-direct-unmatched",
                RuleSet = JsonUtils.Serialize(new List<RulesItem>
                {
                    new()
                    {
                        Enabled = true,
                        RuleType = ERuleType.DNS,
                        OutboundTag = Global.DirectTag,
                        Domain = ["geosite:us"],
                    }
                }),
                DomainStrategy = Global.AsIs,
                DomainStrategy4Singbox = string.Empty,
            }
        };

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var dns = JsonUtils.Deserialize<Dns4Ray>(JsonUtils.Serialize(cfg.dns))!;
        var dnsServers = dns.servers
            .Select(s => JsonUtils.Deserialize<DnsServer4Ray>(JsonUtils.Serialize(s)))
            .Where(s => s is not null)
            .Cast<DnsServer4Ray>()
            .ToList();

        var hasExpectedIPs = dnsServers.Any(s =>
            s.expectedIPs?.Contains("192.168.0.0/16") == true
            || s.expectedIPs?.Contains("geoip:cn") == true);
        await hasExpectedIPs.Should().BeFalse();
    }

    [Test]
    [Arguments("geosite:cn")]
    [Arguments("geosite:geolocation-cn")]
    [Arguments("geosite:tld-cn")]
    public async Task GenerateClientConfigContent_DirectExpectedIPs_RegionVariant_ShouldApplyExpectedIPs(string domainTag)
    {
        var config = CoreConfigTestFactory.CreateConfigWithDirectExpectedIPs(ECoreType.Xray, "192.168.0.0/16,geoip:cn");
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, "n-main", "main");
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray) with
        {
            RoutingItem = new RoutingItem
            {
                Id = "r-dns-direct-variant",
                Remarks = "dns-direct-variant",
                RuleSet = JsonUtils.Serialize(new List<RulesItem>
                {
                    new()
                    {
                        Enabled = true, RuleType = ERuleType.DNS, OutboundTag = Global.DirectTag, Domain = [domainTag],
                    }
                }),
                DomainStrategy = Global.AsIs,
                DomainStrategy4Singbox = string.Empty,
            }
        };

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var dns = JsonUtils.Deserialize<Dns4Ray>(JsonUtils.Serialize(cfg.dns))!;
        var dnsServers = dns.servers
            .Select(s => JsonUtils.Deserialize<DnsServer4Ray>(JsonUtils.Serialize(s)))
            .Where(s => s is not null)
            .Cast<DnsServer4Ray>()
            .ToList();

        var hasExpectedServer = dnsServers.Any(s =>
            (s.tag ?? string.Empty).StartsWith(Global.DirectDnsTag, StringComparison.Ordinal)
            && s.domains?.Contains(domainTag) == true
            && s.expectedIPs?.Contains("192.168.0.0/16") == true
            && s.expectedIPs?.Contains("geoip:cn") == true);
        await hasExpectedServer.Should().BeTrue();
    }

    [Test]
    public async Task GenerateClientConfigContent_Hosts_ShouldPopulateDnsHosts()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        config.SimpleDNSItem.Hosts = "resolver.example 1.1.1.1";
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, "n-main", "main");
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var dns = JsonUtils.Deserialize<Dns4Ray>(JsonUtils.Serialize(cfg.dns))!;

        await dns.hosts.Should().NotBeNull();
        await dns.hosts!.Should().ContainKey("resolver.example");
        await JsonUtils.Serialize(dns.hosts!["resolver.example"]).Should().Contain("1.1.1.1");
    }

    [Test]
    public async Task GenerateClientConfigContent_FakeIP_ShouldWriteBothPoolsByDefault()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        config.SimpleDNSItem.FakeIP = true;
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, "n-main", "main");
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray) with
        {
            RoutingItem = new RoutingItem
            {
                Id = "r-dns-fakeip",
                Remarks = "dns-fakeip",
                RuleSet = JsonUtils.Serialize(new List<RulesItem>
                {
                    new()
                    {
                        Enabled = true, RuleType = ERuleType.DNS, OutboundTag = Global.ProxyTag, Domain = ["geosite:google"],
                    }
                }),
                DomainStrategy = Global.AsIs,
                DomainStrategy4Singbox = string.Empty,
            }
        };

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        // PattN: by default both pools, Xray-core's ranges (ConfigHandler turns IPv6 FakeIP on)
        var root = JsonUtils.ParseJson(result.Data!.ToString())!.AsObject();
        var pools = root["fakedns"]!.AsArray();
        await pools.Count.Should().BeEqualTo(2);
        await pools[0]!["ipPool"]!.GetValue<string>().Should().BeEqualTo("198.18.0.0/15");
        await pools[0]!["poolSize"]!.GetValue<long>().Should().BeEqualTo(131071L);
        await pools[1]!["ipPool"]!.GetValue<string>().Should().BeEqualTo("2001:2::/48");
        await pools[1]!["poolSize"]!.GetValue<long>().Should().BeEqualTo(65535L);

        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var dns = JsonUtils.Deserialize<Dns4Ray>(JsonUtils.Serialize(cfg.dns))!;
        var dnsServers = dns.servers
            .Select(s => JsonUtils.Deserialize<DnsServer4Ray>(JsonUtils.Serialize(s)))
            .Where(s => s is not null)
            .Cast<DnsServer4Ray>()
            .ToList();

        var hasFakeDnsServer = dnsServers.Any(s =>
            s.address == "fakedns"
            && s.domains?.Contains("geosite:google") == true);
        await hasFakeDnsServer.Should().BeTrue();
    }

    [Test]
    public async Task GenerateClientConfigContent_RawDnsEnabled_ShouldUseCustomDnsConfig()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, "n-main", "main");
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray) with
        {
            RawDnsItem = new DNSItem
            {
                Id = "dns-raw-1",
                Remarks = "raw",
                Enabled = true,
                CoreType = ECoreType.Xray,
                NormalDNS = "{\"servers\":[\"8.8.8.8\"],\"hosts\":{\"raw.example\":\"1.1.1.1\"}}",
                DomainStrategy4Freedom = "UseIPv4",
            }
        };

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var dns = JsonUtils.Deserialize<Dns4Ray>(JsonUtils.Serialize(cfg.dns))!;

        await JsonUtils.Serialize(dns.servers).Should().Contain("8.8.8.8");
        await dns.hosts.Should().NotBeNull();
        await dns.hosts!.Should().ContainKey("raw.example");
        await JsonUtils.Serialize(dns.hosts!["raw.example"]).Should().Contain("1.1.1.1");

        var directOutbound = cfg.outbounds.FirstOrDefault(o => o.tag == Global.DirectTag && o.protocol == "freedom");
        await directOutbound.Should().NotBeNull();
        await directOutbound!.streamSettings.sockopt!.domainStrategy.Should().BeEqualTo("UseIPv4");
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task GenerateClientConfigContent_Tun_ShouldRouteIPv6IntoTunnel(bool enableIPv6Address)
    {
        var config = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, enableIPv6Address);
        config.TunModeItem.StrictRoute = true;
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, "n-main", "main");
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray) with { IsWindows = false };

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var tunInbound = cfg.inbounds.FirstOrDefault(i => i.protocol == "tun");

        await tunInbound.Should().NotBeNull();
        await tunInbound!.settings.autoSystemRoutingTable.Should().Contain("0.0.0.0/0");
        await tunInbound.settings.autoSystemRoutingTable.Should().Contain("::/0");

        // PattN: off Windows, strict route adds no leak block, so nothing stops IPv6 outside the TUN: a host with
        // a global IPv6 address routes ::/0 either way, and EnableIPv6Address governs the interface address alone.
        await tunInbound.settings.gateway.Should().HaveCount(enableIPv6Address ? 2 : 1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task GenerateClientConfigContent_Tun_WindowsStrictRoute_ShouldRouteIPv6OnlyWhenEnabled(bool enableIPv6Address)
    {
        // PattN: on Windows with strict route, misconfigtun blocks an IP version that has no route into the TUN,
        // so with EnableIPv6Address off IPv6 is blocked rather than routed in, even on a host with a global
        // IPv6 address; with it on, IPv6 goes into the TUN.
        var config = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, enableIPv6Address);
        config.TunModeItem.StrictRoute = true;
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, "n-main", "main");
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray, hasGlobalIPv6Address: true) with { IsWindows = true };

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var tunInbound = cfg.inbounds.First(i => i.protocol == "tun");

        await tunInbound.settings.autoSystemWfpBlockLeak.Should().Contain("misconfigtun");
        await tunInbound.settings.autoSystemRoutingTable.Should().Contain("0.0.0.0/0");
        var ipv6Routes = tunInbound.settings.autoSystemRoutingTable!.Where(x => x.Contains(':')).ToList();
        await ipv6Routes.Should().HaveCount(enableIPv6Address ? 1 : 0);
        await tunInbound.settings.gateway.Should().HaveCount(enableIPv6Address ? 2 : 1);
    }

    [Test]
    public async Task GenerateClientConfigContent_Tun_WindowsWithoutStrictRoute_ShouldRouteIPv6WithGlobalIPv6()
    {
        // Without strict route nothing blocks IPv6 outside the TUN, so a host with a global IPv6 address keeps
        // ::/0 even with EnableIPv6Address off, or its IPv6 would bypass the tunnel.
        var config = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, enableIPv6Address: false);
        config.TunModeItem.StrictRoute = false;
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, "n-main", "main");
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray, hasGlobalIPv6Address: true) with { IsWindows = true };

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var tunInbound = cfg.inbounds.First(i => i.protocol == "tun");

        await tunInbound.settings.autoSystemWfpBlockLeak.Should().BeNull();
        await tunInbound.settings.autoSystemRoutingTable.Should().Contain("::/0");
    }

    [Test]
    [Arguments(true, true, true, false)] // Windows strict route: misconfigtun blocks the IPv6 an interface still has
    [Arguments(true, true, true, true)]
    [Arguments(true, false, false, false)] // no global IPv6 address: nothing to bypass the TUN
    [Arguments(false, true, false, true)]
    [Arguments(true, false, true, false)] // a global IPv6 address that nothing would block keeps ::/0
    [Arguments(false, true, true, true)]
    public async Task GenerateClientConfigContent_Tun_IPv6DisabledByOs_ShouldTakeNoIPv6UnlessItWouldBypass(
        bool isWindows, bool strictRoute, bool hasGlobalIPv6Address, bool excludeAddresses)
    {
        // PattN: where the OS keeps IPv6 off on new interfaces, a TUN asked for IPv6 does not start, so it gets no IPv6
        // address even with EnableIPv6Address on, and no IPv6 route unless a global IPv6 address that an existing
        // interface still has would bypass it: outside Windows strict route, ::/0 then stays, and the TUN fails to
        // start rather than let that IPv6 out.
        var config = excludeAddresses
            ? CoreConfigTestFactory.CreateConfigWithTunRouteExcludeAddress(ECoreType.Xray)
            : CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, enableIPv6Address: true);
        config.TunModeItem.EnableIPv6Address = true;
        config.TunModeItem.StrictRoute = strictRoute;
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, "n-main", "main");
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray, hasGlobalIPv6Address)
            with { IsWindows = isWindows, IsIPv6DisabledByOs = true };

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var tunInbound = cfg.inbounds.First(i => i.protocol == "tun");

        var ipv6Routes = tunInbound.settings.autoSystemRoutingTable!.Where(x => x.Contains(':')).ToList();
        await ipv6Routes.Any().Should().BeEqualTo(hasGlobalIPv6Address && !(isWindows && strictRoute));
        await tunInbound.settings.gateway.Should().HaveCount(1);
        var misconfigTun = tunInbound.settings.autoSystemWfpBlockLeak?.Contains("misconfigtun") == true;
        await misconfigTun.Should().BeEqualTo(isWindows && strictRoute);
    }

    [Test]
    public async Task GenerateClientConfigContent_Tun_ShouldSkipIPv6RouteWithoutGlobalIPv6()
    {
        // A host without a global IPv6 address has no IPv6 traffic that could bypass the tunnel,
        // while ::/0 would pull IPv6 attempts into a tunnel they cannot leave.
        var config = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, enableIPv6Address: false);
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, "n-main", "main");
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray, hasGlobalIPv6Address: false);

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var tunInbound = cfg.inbounds.FirstOrDefault(i => i.protocol == "tun");

        await tunInbound.Should().NotBeNull();
        await tunInbound!.settings.autoSystemRoutingTable.Should().Contain("0.0.0.0/0");
        var ipv6Routes = tunInbound.settings.autoSystemRoutingTable!.Where(x => x.Contains(':')).ToList();
        await ipv6Routes.Should().BeEmpty();
    }

    [Test]
    public async Task GenerateClientConfigContent_Tun_ShouldRouteIPv6WhenEnabledWithoutGlobalIPv6()
    {
        // Hosts behind NAT66 hold only ULA addresses, so EnableIPv6Address must still route ::/0.
        var config = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, enableIPv6Address: true);
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, "n-main", "main");
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray, hasGlobalIPv6Address: false);

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var tunInbound = cfg.inbounds.FirstOrDefault(i => i.protocol == "tun");

        await tunInbound.Should().NotBeNull();
        await tunInbound!.settings.autoSystemRoutingTable.Should().Contain("::/0");
    }

    [Test]
    public async Task GenerateClientConfigContent_Tun_ShouldSetAutoSystemDnsToGatewayOnLinux()
    {
        var config = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, false);
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, "n-main", "main");
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray) with { IsLinux = true };

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var tunInbound = cfg.inbounds.FirstOrDefault(i => i.protocol == "tun");

        await tunInbound.Should().NotBeNull();
        await tunInbound!.settings.autoSystemDnsToGateway.Should().BeEqualTo(true);

        // Xray-core hands the system resolver an address derived from the gateway, and does not
        // start unless a query to that address on port 53 is routed to a "dns" outbound.
        await tunInbound.settings.gateway.Should().Contain(x => !x.Contains(':'));
        await cfg.routing.rules.Should().Contain(r =>
            r.port == "53" && r.inboundTag != null && r.inboundTag.Contains("tun") && r.outboundTag == Global.DnsOutboundTag);
        await cfg.outbounds.Should().Contain(o => o.tag == Global.DnsOutboundTag && o.protocol == "dns");

        // The option is Linux-only in Xray-core, so other systems do not get it.
        var otherResult = new CoreConfigV2rayService(context with { IsLinux = false }).GenerateClientConfigContent();
        var otherCfg = JsonUtils.Deserialize<V2rayConfig>(otherResult.Data!.ToString())!;
        await otherCfg.inbounds.First(i => i.protocol == "tun").settings.autoSystemDnsToGateway.Should().BeNull();
    }

    [Test]
    public async Task GenerateClientConfigContent_TunRouteExcludeAddress_ShouldSkipIPv6RangesWithoutGlobalIPv6()
    {
        var config = CoreConfigTestFactory.CreateConfigWithTunRouteExcludeAddress(ECoreType.Xray);
        config.TunModeItem.EnableIPv6Address = false;
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, "n-main", "main");
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray, hasGlobalIPv6Address: false);

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var tunInbound = cfg.inbounds.FirstOrDefault(i => i.protocol == "tun");

        await tunInbound.Should().NotBeNull();
        await tunInbound!.settings.autoSystemRoutingTable.Should().NotBeEmpty();
        var ipv6Routes = tunInbound.settings.autoSystemRoutingTable!.Where(x => x.Contains(':')).ToList();
        await ipv6Routes.Should().BeEmpty();
    }

    [Test]
    public async Task GenerateClientConfigContent_TunRouteExcludeAddress_ShouldIncludeIPv6Ranges()
    {
        var config = CoreConfigTestFactory.CreateConfigWithTunRouteExcludeAddress(ECoreType.Xray);
        config.TunModeItem.EnableIPv6Address = false;
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, "n-main", "main");
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var tunInbound = cfg.inbounds.FirstOrDefault(i => i.protocol == "tun");

        await tunInbound.Should().NotBeNull();
        await tunInbound!.settings.autoSystemRoutingTable.Should().Contain(x => x.Contains(':'));
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task GenerateClientConfigContent_TunRouteExcludeAddress_WindowsStrictRoute_ShouldRouteIPv6OnlyWhenEnabled(bool enableIPv6Address)
    {
        // PattN: RouteExcludeAddress only cuts ranges out of the TUN routes, so on Windows with strict route IPv6
        // still gets no route, and misconfigtun blocks it, unless EnableIPv6Address is on.
        var config = CoreConfigTestFactory.CreateConfigWithTunRouteExcludeAddress(ECoreType.Xray);
        config.TunModeItem.EnableIPv6Address = enableIPv6Address;
        config.TunModeItem.StrictRoute = true;
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, "n-main", "main");
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray, hasGlobalIPv6Address: true) with { IsWindows = true };

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var tunInbound = cfg.inbounds.First(i => i.protocol == "tun");

        await tunInbound.settings.autoSystemWfpBlockLeak.Should().Contain("misconfigtun");
        await tunInbound.settings.autoSystemRoutingTable.Should().Contain("10.0.0.2/31");
        var ipv6Routes = tunInbound.settings.autoSystemRoutingTable!.Where(x => x.Contains(':')).ToList();
        await ipv6Routes.Any().Should().BeEqualTo(enableIPv6Address);
    }

    [Test]
    public async Task GenerateClientConfigContent_TunRouteExcludeAddress()
    {
        var config = CoreConfigTestFactory.CreateConfigWithTunRouteExcludeAddress(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, "n-main", "main");
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();

        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var tunInbound = cfg.inbounds.FirstOrDefault(i => i.protocol == "tun");

        await tunInbound.Should().NotBeNull();

        await tunInbound!.settings.autoSystemRoutingTable.Should().NotContain("0.0.0.0/0");
        await tunInbound!.settings.autoSystemRoutingTable.Should().Contain("10.0.0.0/32");
        await tunInbound!.settings.autoSystemRoutingTable.Should().Contain("10.0.0.2/31");
    }

    [Test]
    public async Task GenerateClientConfigContent_EchOutbound_ShouldBeAppendedLastAndUsedByEchSockopt()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        // tcpKeepAliveIdle is not in the typed sockopt model: the outbound has to reach the config as written.
        var node = CreateEchNode("n1", "node-1", """
            {
              "tag": "ech-out",
              "protocol": "freedom",
              "streamSettings": { "sockopt": { "tcpKeepAliveIdle": 100 } }
            }
            """);
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var outbounds = ParseOutbounds(result);
        await JsonNode.DeepEquals(outbounds[^1], JsonNode.Parse(node.EchOutbound)).Should().BeTrue();
        await EchDialerProxy(outbounds, Global.ProxyTag).Should().BeEqualTo("ech-out");
    }

    [Test]
    public async Task GenerateClientConfigContent_EchOutboundSharedByPolicyGroup_ShouldBeAppendedOnce()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        const string echOutbound = """{"tag": "ech-out", "protocol": "freedom"}""";
        var context = CreateEchGroupContext(config,
            CreateEchNode("n1", "node-1", echOutbound),
            CreateEchNode("n2", "node-2", echOutbound));

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var outbounds = ParseOutbounds(result);
        await outbounds.Count(o => o?["tag"]?.GetValue<string>() == "ech-out").Should().BeEqualTo(1);
        await outbounds[^1]!["tag"]!.GetValue<string>().Should().BeEqualTo("ech-out");
        await EchDialerProxy(outbounds, "proxy-1-node-1").Should().BeEqualTo("ech-out");
        await EchDialerProxy(outbounds, "proxy-2-node-2").Should().BeEqualTo("ech-out");
    }

    [Test]
    public async Task GenerateClientConfigContent_DifferentEchOutboundsWithOneTag_ShouldEachKeepTheirOwn()
    {
        // The tag only links a proxy outbound to its ECH outbound, so the second one is renumbered.
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var context = CreateEchGroupContext(config,
            CreateEchNode("n1", "node-1", """{"tag": "ech-out", "protocol": "freedom"}"""),
            CreateEchNode("n2", "node-2", """{"tag": "ech-out", "protocol": "blackhole"}"""));

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var outbounds = ParseOutbounds(result);
        await EchDialerProxy(outbounds, "proxy-1-node-1").Should().BeEqualTo("ech-out");
        await EchDialerProxy(outbounds, "proxy-2-node-2").Should().BeEqualTo("ech-out-2");
        await outbounds[^2]!["tag"]!.GetValue<string>().Should().BeEqualTo("ech-out");
        await outbounds[^2]!["protocol"]!.GetValue<string>().Should().BeEqualTo("freedom");
        await outbounds[^1]!["tag"]!.GetValue<string>().Should().BeEqualTo("ech-out-2");
        await outbounds[^1]!["protocol"]!.GetValue<string>().Should().BeEqualTo("blackhole");
    }

    [Test]
    public async Task GenerateClientSpeedtestConfig_ProfilesWithEchOutbounds_ShouldEachKeepTheirOwn()
    {
        // A batch speed test puts unrelated profiles in one config, where one tag often names different ECH outbounds.
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var n1 = CreateEchNode("n1", "node-1", """{"tag": "ech", "protocol": "freedom"}""");
        var n2 = CreateEchNode("n2", "node-2", """{"tag": "ech", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}}""");
        var context = CoreConfigTestFactory.CreateContext(config, n1, ECoreType.Xray);
        context.AllProxiesMap[n2.IndexId] = n2;
        List<ServerTestItem> selecteds =
        [
            new() { IndexId = n1.IndexId, ConfigType = n1.ConfigType, Port = n1.Port },
            new() { IndexId = n2.IndexId, ConfigType = n2.ConfigType, Port = n2.Port },
        ];

        var result = new CoreConfigV2rayService(context).GenerateClientSpeedtestConfig(selecteds);

        await result.Success.Should().BeTrue();
        var outbounds = ParseOutbounds(result);
        var dialerProxies = outbounds
            .Where(o => o?["protocol"]?.GetValue<string>() == "vmess")
            .Select(o => o?["streamSettings"]?["tlsSettings"]?["echSockopt"]?["dialerProxy"]?.GetValue<string>())
            .ToList();
        await dialerProxies.Should().HaveCount(2);
        await dialerProxies[0].Should().BeEqualTo("ech");
        await dialerProxies[1].Should().BeEqualTo("ech-2");
        await outbounds[^2]!["tag"]!.GetValue<string>().Should().BeEqualTo("ech");
        await outbounds[^1]!["tag"]!.GetValue<string>().Should().BeEqualTo("ech-2");
    }

    [Test]
    public async Task GenerateClientConfigContent_EchOutboundTagUsedByAnotherOutbound_ShouldFail()
    {
        // In TUN mode the config has a "dns" outbound of its own.
        var config = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, false);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = CreateEchNode("n1", "node-1", """{"tag": "dns", "protocol": "freedom"}""");
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeFalse();
        await result.Msg.Should().BeEqualTo(string.Format(ResUI.MsgEchOutboundTagConflict, Global.DnsOutboundTag));
    }

    [Test]
    public async Task GenerateClientConfigContent_EchOutboundWithoutTls_ShouldBeLeftOut()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = CreateEchNode("n1", "node-1", """{"tag": "ech-out", "protocol": "freedom"}""");
        node.StreamSecurity = string.Empty;
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        await ParseOutbounds(result).Any(o => o?["tag"]?.GetValue<string>() == "ech-out").Should().BeFalse();
    }

    [Test]
    public async Task GenerateClientConfigContent_EchOutboundWithFullConfigTemplate_ShouldComeAfterTheTemplate()
    {
        // The ECH outbound is appended after the template is merged, so it stays last and keeps
        // no proxy detour, which the template would otherwise add to a socks outbound like this one.
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = CreateEchNode("n1", "node-1", """
            {"tag": "ech-out", "protocol": "socks", "settings": {"servers": [{"address": "203.0.113.1", "port": 1080}]}}
            """);
        var template = new FullConfigTemplateItem
        {
            Id = "t1",
            Remarks = "template",
            Enabled = true,
            CoreType = ECoreType.Xray,
            ProxyDetour = "template-out",
            Config = """
                {
                  "outbounds": [ { "tag": "template-out", "protocol": "freedom" } ]
                }
                """,
        };
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray, fullConfigTemplate: template);

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var outbounds = ParseOutbounds(result);
        await outbounds.Any(o => o?["tag"]?.GetValue<string>() == "template-out").Should().BeTrue();
        await outbounds[^1]!["tag"]!.GetValue<string>().Should().BeEqualTo("ech-out");
        await outbounds[^1]!["streamSettings"].Should().BeNull();
    }

    [Test]
    public async Task GenerateClientSpeedtestConfig_EchOutbound_ShouldBeAppendedLast()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = CreateEchNode("n1", "node-1", """{"tag": "ech-out", "protocol": "freedom"}""");
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);

        var result = new CoreConfigV2rayService(context).GenerateClientSpeedtestConfig(10999);

        await result.Success.Should().BeTrue();
        var outbounds = ParseOutbounds(result);
        await outbounds[^1]!["tag"]!.GetValue<string>().Should().BeEqualTo("ech-out");
        await EchDialerProxy(outbounds, Global.ProxyTag).Should().BeEqualTo("ech-out");
    }

    [Test]
    public async Task GenerateClientConfigContent_NumberedEchTagUsedByTheTemplate_ShouldMoveOn()
    {
        // The user never wrote "ech-out-2", so it moves on to a free number instead of failing the config,
        // and only the generated outbound that points at it follows.
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var n1 = CreateEchNode("n1", "node-1", """{"tag": "ech-out", "protocol": "freedom"}""");
        var n2 = CreateEchNode("n2", "node-2", """{"tag": "ech-out", "protocol": "blackhole"}""");
        var group = CoreConfigTestFactory.CreatePolicyGroupNode(ECoreType.Xray, "g1", "group", [n1.IndexId, n2.IndexId]);
        var template = new FullConfigTemplateItem
        {
            Id = "t1",
            Remarks = "template",
            Enabled = true,
            CoreType = ECoreType.Xray,
            Config = """
                {
                  "outbounds": [
                    { "tag": "ech-out-2", "protocol": "freedom" },
                    {
                      "tag": "template-tls",
                      "protocol": "vless",
                      "streamSettings": { "security": "tls", "tlsSettings": { "echSockopt": { "dialerProxy": "ech-out-2" } } }
                    }
                  ]
                }
                """,
        };
        var context = CoreConfigTestFactory.CreateContext(config, group, ECoreType.Xray, fullConfigTemplate: template);
        context.AllProxiesMap[n1.IndexId] = n1;
        context.AllProxiesMap[n2.IndexId] = n2;

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var outbounds = ParseOutbounds(result);
        await EchDialerProxy(outbounds, "proxy-1-node-1").Should().BeEqualTo("ech-out");
        await EchDialerProxy(outbounds, "proxy-2-node-2").Should().BeEqualTo("ech-out-3");
        await EchDialerProxy(outbounds, "template-tls").Should().BeEqualTo("ech-out-2");
        await outbounds[^2]!["tag"]!.GetValue<string>().Should().BeEqualTo("ech-out");
        await outbounds[^1]!["tag"]!.GetValue<string>().Should().BeEqualTo("ech-out-3");
        await outbounds[^1]!["protocol"]!.GetValue<string>().Should().BeEqualTo("blackhole");
    }

    [Test]
    public async Task GenerateClientConfigContent_TemplateOutboundWithRepeatedKey_ShouldStillGetTheEchOutbound()
    {
        // Xray takes the last of repeated keys, and the tag check before the append reads them the same way.
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = CreateEchNode("n1", "node-1", """{"tag": "ech-out", "protocol": "freedom"}""");
        var template = new FullConfigTemplateItem
        {
            Id = "t1",
            Remarks = "template",
            Enabled = true,
            CoreType = ECoreType.Xray,
            Config = """
                {
                  "outbounds": [ { "tag": "template-out", "protocol": "blackhole", "protocol": "freedom" } ]
                }
                """,
        };
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray, fullConfigTemplate: template);

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        await result.Data!.ToString()!.Should().Contain("template-out");
        var outbounds = ParseOutbounds(result);
        await outbounds[^1]!["tag"]!.GetValue<string>().Should().BeEqualTo("ech-out");
        await EchDialerProxy(outbounds, Global.ProxyTag).Should().BeEqualTo("ech-out");
    }

    [Test]
    public async Task GenerateClientConfigContent_EchOutboundWithRepeatedKey_ShouldBeLeftOut()
    {
        // Validation stops such a profile before a real start; the proxy outbound must keep its TLS settings.
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = CreateEchNode("n1", "node-1", """{"tag": "ech-out", "protocol": "freedom", "settings": {"x": 1, "x": 2}}""");
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var outbounds = ParseOutbounds(result);
        var proxy = outbounds.First(o => o?["tag"]?.GetValue<string>() == Global.ProxyTag)!;
        var serverName = proxy["streamSettings"]?["tlsSettings"]?["serverName"]?.GetValue<string>();
        await serverName.Should().BeEqualTo("example.com");
        await EchDialerProxy(outbounds, Global.ProxyTag).Should().BeNull();
        await outbounds.Any(o => o?["tag"]?.GetValue<string>() == "ech-out").Should().BeFalse();
    }

    [Test]
    public async Task GenerateClientConfigContent_Twice_ShouldAppendTheEchOutboundOnce()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = CreateEchNode("n1", "node-1", """{"tag": "ech-out", "protocol": "freedom"}""");
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);

        new CoreConfigV2rayService(context).GenerateClientConfigContent();
        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        await ParseOutbounds(result).Count(o => o?["tag"]?.GetValue<string>() == "ech-out").Should().BeEqualTo(1);
    }

    [Test]
    public async Task GenerateClientConfigContent_CurvePreferencesAndSessionResumption_ShouldFollowCipherSuites()
    {
        // PattN: curvePreferences go out as a list, each name trimmed, and enableSessionResumption only when it is on;
        // both right after cipherSuites, as in the editor and the share links.
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, "n1", "node-1");
        node.StreamSecurity = Global.StreamSecurity;
        node.Sni = "example.com";
        node.Fingerprint = "unsafe";
        node.CipherSuites = "TLS_AES_128_GCM_SHA256";
        node.CurvePreferences = " X25519MLKEM768 ,X25519,";
        node.EnableSessionResumption = true;

        var result = new CoreConfigV2rayService(CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray)).GenerateClientConfigContent();

        await result.Success.Should().BeTrue().Because($"ret msg: {result.Msg}");
        var tls = TlsSettingsOf(result);
        await tls["curvePreferences"]!.AsArray().Select(n => n!.GetValue<string>()).SequenceEqual(["X25519MLKEM768", "X25519"]).Should().BeTrue();
        await tls["enableSessionResumption"]!.GetValue<bool>().Should().BeTrue();
        var keys = tls.Select(p => p.Key).ToList();
        await keys.IndexOf("curvePreferences").Should().BeEqualTo(keys.IndexOf("cipherSuites") + 1);
        await keys.IndexOf("enableSessionResumption").Should().BeEqualTo(keys.IndexOf("cipherSuites") + 2);

        // Unset, neither is written.
        node.CurvePreferences = string.Empty;
        node.EnableSessionResumption = false;
        var plain = new CoreConfigV2rayService(CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray)).GenerateClientConfigContent();

        await plain.Success.Should().BeTrue().Because($"ret msg: {plain.Msg}");
        var plainTls = TlsSettingsOf(plain);
        await plainTls.ContainsKey("curvePreferences").Should().BeFalse();
        await plainTls.ContainsKey("enableSessionResumption").Should().BeFalse();
        await plainTls.ContainsKey("cipherSuites").Should().BeTrue();

        static JsonObject TlsSettingsOf(RetResult result) =>
            ParseOutbounds(result).First(o => o?["tag"]?.GetValue<string>() == Global.ProxyTag)!["streamSettings"]!["tlsSettings"]!.AsObject();
    }

    private static ProfileItem CreateEchNode(string indexId, string remarks, string echOutbound)
    {
        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, indexId, remarks);
        node.StreamSecurity = Global.StreamSecurity;
        node.Sni = "example.com";
        node.EchConfigList = "cloudflare-ech.com+https://1.1.1.1/dns-query";
        node.EchOutbound = echOutbound;
        return node;
    }

    private static CoreConfigContext CreateEchGroupContext(Config config, ProfileItem n1, ProfileItem n2)
    {
        var group = CoreConfigTestFactory.CreatePolicyGroupNode(ECoreType.Xray, "g1", "group", [n1.IndexId, n2.IndexId]);
        var context = CoreConfigTestFactory.CreateContext(config, group, ECoreType.Xray);
        context.AllProxiesMap[n1.IndexId] = n1;
        context.AllProxiesMap[n2.IndexId] = n2;
        context.AllProxiesMap[group.IndexId] = group;
        return context;
    }

    private static JsonArray ParseOutbounds(RetResult result)
    {
        return JsonNode.Parse(result.Data!.ToString()!)!["outbounds"]!.AsArray();
    }

    private static string? EchDialerProxy(JsonArray outbounds, string tag)
    {
        var outbound = outbounds.First(o => o?["tag"]?.GetValue<string>() == tag);
        return outbound?["streamSettings"]?["tlsSettings"]?["echSockopt"]?["dialerProxy"]?.GetValue<string>();
    }

    [Test]
    public async Task GenerateClientConfigContent_CustomOutbound_ShouldReplaceWithUserCustomOutboundJson()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var customNode = CoreConfigTestFactory.CreateCustomOutboundNode(ECoreType.Xray, "n-custom", "custom-xray");
        var customJsonContent = """
        {
          "protocol": "shadowsocks",
          "settings": {
            "servers": [
              {
                "address": "1.2.3.4",
                "port": 8388,
                "method": "aes-128-gcm",
                "password": "custom_password"
              }
            ]
          }
        }
        """;

        var context = CoreConfigTestFactory.CreateContext(config, customNode, ECoreType.Xray);
        context.CustomOutboundContent[customNode.IndexId] = customJsonContent;

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue().Because($"ret msg: {result.Msg}");
        await result.Data.Should().NotBeNull();

        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString());
        await cfg.Should().NotBeNull();
        var proxyOutbound = cfg!.outbounds.FirstOrDefault(o => o.tag == Global.ProxyTag);
        await proxyOutbound.Should().NotBeNull();
        await proxyOutbound!.protocol.Should().BeEqualTo("shadowsocks");
    }

    [Test]
    public async Task GenerateClientConfigContent_XdriveGoogleDrive_ShouldGenerateValidOutbound()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var node = new ProfileItem
        {
            IndexId = "node-xdrive-gdrive",
            ConfigType = EConfigType.VLESS,
            CoreType = ECoreType.Xray,
            Remarks = "xdrive-gdrive",
            Address = "example.com",
            Port = 443,
            Password = Guid.NewGuid().ToString(),
            Network = nameof(ETransport.xdrive),
            MuxEnabled = false,
        };
        node.SetProtocolExtra(new ProtocolExtraItem { VlessEncryption = Global.None });
        node.SetTransportExtra(new TransportExtraItem
        {
            XdriveService = "google-drive",
            XdriveRemoteFolder = "folder-123",
            XdriveSecrets = "id,secret,token",
        });

        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);
        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var generatedConfig = JsonNode.Parse(result.Data!.ToString()!)!;
        var proxy = generatedConfig["outbounds"]!.AsArray()
            .First(outbound => outbound!["tag"]!.GetValue<string>() == Global.ProxyTag)!;

        var streamSettings = proxy["streamSettings"]!;
        await streamSettings["network"]!.GetValue<string>().Should().BeEqualTo("xdrive");

        var xdriveSettings = streamSettings["xdriveSettings"]!;
        await xdriveSettings["service"]!.GetValue<string>().Should().BeEqualTo("google-drive");
        await xdriveSettings["remoteFolder"]!.GetValue<string>().Should().BeEqualTo("folder-123");

        var secrets = xdriveSettings["secrets"]!.AsArray();
        await secrets.Count.Should().BeEqualTo(3);
        await secrets[0]!.GetValue<string>().Should().BeEqualTo("id");
        await secrets[1]!.GetValue<string>().Should().BeEqualTo("secret");
        await secrets[2]!.GetValue<string>().Should().BeEqualTo("token");

        await proxy["mux"]!["enabled"]!.GetValue<bool>().Should().BeTrue();
    }

    [Test]
    public async Task GenerateClientConfigContent_XdriveS3_ShouldGenerateValidOutbound()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var node = new ProfileItem
        {
            IndexId = "node-xdrive-s3",
            ConfigType = EConfigType.VLESS,
            CoreType = ECoreType.Xray,
            Remarks = "xdrive-s3",
            Address = "example.com",
            Port = 443,
            Password = Guid.NewGuid().ToString(),
            Network = nameof(ETransport.xdrive),
        };
        node.SetProtocolExtra(new ProtocolExtraItem { VlessEncryption = Global.None });
        node.SetTransportExtra(new TransportExtraItem
        {
            XdriveService = "s3",
            XdriveS3Endpoint = "https://s3.amazonaws.com",
            XdriveS3Bucket = "mybucket",
            XdriveS3PathStyle = false,
        });

        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);
        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var generatedConfig = JsonNode.Parse(result.Data!.ToString()!)!;
        var proxy = generatedConfig["outbounds"]!.AsArray()
            .First(outbound => outbound!["tag"]!.GetValue<string>() == Global.ProxyTag)!;

        var s3 = proxy["streamSettings"]!["xdriveSettings"]!["s3"]!;
        await s3["endpoint"]!.GetValue<string>().Should().BeEqualTo("https://s3.amazonaws.com");
        await s3["bucket"]!.GetValue<string>().Should().BeEqualTo("mybucket");
        await s3["pathStyle"]!.GetValue<bool>().Should().BeFalse();
    }

    [Test]
    public async Task GenerateClientConfigContent_XdriveExtra_ShouldPopulateParameters()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var node = new ProfileItem
        {
            IndexId = "node-xdrive-extra",
            ConfigType = EConfigType.VLESS,
            CoreType = ECoreType.Xray,
            Remarks = "xdrive-extra",
            Address = "example.com",
            Port = 443,
            Password = Guid.NewGuid().ToString(),
            Network = nameof(ETransport.xdrive),
        };
        node.SetProtocolExtra(new ProtocolExtraItem { VlessEncryption = Global.None });
        node.SetTransportExtra(new TransportExtraItem
        {
            XdriveService = "onedrive",
            XdriveExtra = """{"segmentBytes":1048576,"flushIntervalMs":500,"pollIntervalMs":200,"maxPollIntervalMs":2000,"eagerWindowMs":1000,"concurrency":4}""",
        });

        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);
        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var generatedConfig = JsonNode.Parse(result.Data!.ToString()!)!;
        var proxy = generatedConfig["outbounds"]!.AsArray()
            .First(outbound => outbound!["tag"]!.GetValue<string>() == Global.ProxyTag)!;

        var xdriveSettings = proxy["streamSettings"]!["xdriveSettings"]!;
        await xdriveSettings["segmentBytes"]!.GetValue<int>().Should().BeEqualTo(1048576);
        await xdriveSettings["flushIntervalMs"]!.GetValue<int>().Should().BeEqualTo(500);
        await xdriveSettings["pollIntervalMs"]!.GetValue<int>().Should().BeEqualTo(200);
        await xdriveSettings["maxPollIntervalMs"]!.GetValue<int>().Should().BeEqualTo(2000);
        await xdriveSettings["eagerWindowMs"]!.GetValue<int>().Should().BeEqualTo(1000);
        await xdriveSettings["concurrency"]!.GetValue<int>().Should().BeEqualTo(4);
    }
}
