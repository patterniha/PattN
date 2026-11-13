namespace ServiceLib.Tests.CoreConfig.V2ray;

/// <summary>
/// PattN (PattNG CoreOutboundBuilderTest): the tcpUserTimeout of a profile reaches the sockopt of its outbound, merged in
/// as the dialMode is, only where the outbound connects over TCP (TcpUserTimeoutRule); that of an Aether profile
/// reaches the freedom exit-node where its core connects out over TCP, and never another profile's outbound.
/// </summary>
public class TcpUserTimeoutTests
{
    private static V2rayConfig Generate(ProfileItem node)
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);
        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();
        if (!result.Success)
        {
            throw new InvalidOperationException("config generation failed: " + result.Msg);
        }
        return JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
    }

    private static Outbounds4Ray Proxy(ProfileItem node)
    {
        return Generate(node).outbounds.First(outbound => outbound.tag == Global.ProxyTag);
    }

    private static ProfileItem Masque(string alpn)
    {
        return new ProfileItem
        {
            IndexId = "node-masque-1",
            ConfigType = EConfigType.MASQUE,
            CoreType = ECoreType.Xray,
            Remarks = "masque",
            Address = "example.com",
            Port = 443,
            Username = "user",
            Password = "pass",
            StreamSecurity = Global.StreamSecurity,
            Alpn = alpn,
            Subid = string.Empty,
            TcpUserTimeout = 10000,
        };
    }

    [Test]
    public async Task ATcpOutboundTakesItBesideItsDialMode()
    {
        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray);
        node.DialMode = "oob.0";
        node.TcpUserTimeout = 10000;
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var result = new CoreConfigV2rayService(CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray)).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var proxy = JsonNode.Parse(result.Data!.ToString()!)!["outbounds"]!.AsArray()
            .First(outbound => outbound!["tag"]!.GetValue<string>() == Global.ProxyTag)!;
        var sockopt = proxy["streamSettings"]!["sockopt"]!.AsObject();
        // A number, under the name Xray reads (sockopt.tcpUserTimeout, in milliseconds).
        await sockopt["tcpUserTimeout"]!.GetValue<int>().Should().BeEqualTo(10000);
        await sockopt["dialMode"]!.GetValue<string>().Should().BeEqualTo("oob.0");
    }

    [Test]
    public async Task NoneSetLeavesItOut()
    {
        var proxy = Proxy(CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray));

        await (proxy.streamSettings?.sockopt?.tcpUserTimeout).Should().BeNull();
    }

    [Test]
    public async Task SocksAndHttpTakeIt()
    {
        var socks = CoreConfigTestFactory.CreateSocksNode(ECoreType.Xray);
        socks.TcpUserTimeout = 3000;
        var http = CoreConfigTestFactory.CreateHttpNode(ECoreType.Xray);
        http.TcpUserTimeout = 4000;

        await Proxy(socks).streamSettings!.sockopt!.tcpUserTimeout.Should().BeEqualTo(3000);
        await Proxy(http).streamSettings!.sockopt!.tcpUserTimeout.Should().BeEqualTo(4000);
    }

    [Test]
    public async Task MasqueTakesItOverHttp2Alone()
    {
        await Proxy(Masque("h2")).streamSettings!.sockopt!.tcpUserTimeout.Should().BeEqualTo(10000);
        await (Proxy(Masque("h3")).streamSettings?.sockopt?.tcpUserTimeout).Should().BeNull();
        await (Proxy(Masque(string.Empty)).streamSettings?.sockopt?.tcpUserTimeout).Should().BeNull();
    }

    [Test]
    public async Task AUdpOutboundLeavesItOutAndKeepsItsDialMode()
    {
        // WireGuard dials its endpoint over UDP; the dialMode still goes to its sockopt.
        var wireguard = CoreConfigTestFactory.CreateWireguardNode(ECoreType.Xray);
        wireguard.DialMode = "oob.0";
        wireguard.TcpUserTimeout = 10000;
        var wg = Proxy(wireguard);
        await wg.streamSettings!.sockopt!.dialMode.Should().BeEqualTo("oob.0");
        await wg.streamSettings.sockopt.tcpUserTimeout.Should().BeNull();

        // mKCP, and XHTTP over HTTP/3, run over UDP too.
        var kcp = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray);
        kcp.Network = nameof(ETransport.kcp);
        kcp.TcpUserTimeout = 10000;
        await (Proxy(kcp).streamSettings?.sockopt?.tcpUserTimeout).Should().BeNull();

        var xhttp = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray);
        xhttp.Network = nameof(ETransport.xhttp);
        xhttp.StreamSecurity = Global.StreamSecurity;
        xhttp.Sni = "example.com";
        xhttp.Alpn = "h3";
        xhttp.TcpUserTimeout = 10000;
        await (Proxy(xhttp).streamSettings?.sockopt?.tcpUserTimeout).Should().BeNull();
        // Over HTTP/2 it is TCP again.
        xhttp.Alpn = "h2";
        await Proxy(xhttp).streamSettings!.sockopt!.tcpUserTimeout.Should().BeEqualTo(10000);
    }

    [Test]
    public async Task AProxyChainKeepsItsDialerProxyBesideIt()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var n1 = CoreConfigTestFactory.CreateSocksNode(ECoreType.Xray, "n1", "node-1");
        var n2 = CoreConfigTestFactory.CreateSocksNode(ECoreType.Xray, "n2", "node-2");
        n1.TcpUserTimeout = 5000;
        n2.TcpUserTimeout = 6000;
        var chain = CoreConfigTestFactory.CreateProxyChainNode(ECoreType.Xray, "c1", "chain", [n1.IndexId, n2.IndexId]);
        var context = CoreConfigTestFactory.CreateContext(config, chain, ECoreType.Xray);
        context.AllProxiesMap[n1.IndexId] = n1;
        context.AllProxiesMap[n2.IndexId] = n2;
        context.AllProxiesMap[chain.IndexId] = chain;

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var proxy = cfg.outbounds.First(outbound => outbound.tag == Global.ProxyTag);
        await (proxy.streamSettings!.sockopt!.dialerProxy ?? string.Empty).StartsWith("chain-proxy-1-", StringComparison.Ordinal).Should().BeTrue();
        // Each hop takes its own.
        var dialer = cfg.outbounds.First(outbound => outbound.tag == proxy.streamSettings.sockopt.dialerProxy);
        var timeouts = new[] { proxy.streamSettings.sockopt.tcpUserTimeout, dialer.streamSettings?.sockopt?.tcpUserTimeout };
        await timeouts.OrderBy(timeout => timeout).SequenceEqual(new int?[] { 5000, 6000 }).Should().BeTrue();
    }

    [Test]
    public async Task TheFreedomExitNodeOfAnAetherCoreOverTcpTakesItAndTheOutboundToTheCoreDoesNot()
    {
        var warp = AetherConfigTests.Warp(extra: extra => extra with { AetherTransport = AetherTransport.Http2.Type });
        warp.DialMode = "oob.0";
        warp.TcpUserTimeout = 10000;

        var g = await AetherConfigTests.Succeeds(AetherConfigTests.AetherContext(AetherConfigTests.NewConfig(), warp));

        var sockopt = g.OutboundNode(Global.AetherExitNodeTag)["streamSettings"]!["sockopt"]!;
        await sockopt["tcpUserTimeout"]!.GetValue<int>().Should().BeEqualTo(10000);
        await sockopt["dialMode"]!.GetValue<string>().Should().BeEqualTo("oob.0");
        // The outbound to the core is on the loopback address, where it would do nothing.
        await g.Outbound(Global.ProxyTag).streamSettings.Should().BeNull();
        await g.Core.Exit.Should().BeEqualTo(new AetherExit(DialMode: "oob.0", TcpUserTimeout: 10000));

        // Alone it makes the stream settings of its own.
        var alone = AetherConfigTests.Warp(extra: extra => extra with { AetherTor = AetherTor.Only.Type });
        alone.TcpUserTimeout = 7000;
        var only = await AetherConfigTests.Succeeds(AetherConfigTests.AetherContext(AetherConfigTests.NewConfig(), alone));
        var onlySockopt = only.OutboundNode(Global.AetherExitNodeTag)["streamSettings"]!["sockopt"]!.AsObject();
        await onlySockopt["tcpUserTimeout"]!.GetValue<int>().Should().BeEqualTo(7000);
        await onlySockopt.ContainsKey("dialMode").Should().BeFalse();
    }

    [Test]
    public async Task AnAetherCoreOverUdpLeavesItOutOfTheExitNode()
    {
        // MASQUE over HTTP/3 (the default transport) and WireGuard reach WARP over UDP.
        foreach (var warp in new[] { AetherConfigTests.Warp(), AetherConfigTests.Wg() })
        {
            warp.TcpUserTimeout = 10000;

            var g = await AetherConfigTests.Succeeds(AetherConfigTests.AetherContext(AetherConfigTests.NewConfig(), warp));

            await (g.OutboundNode(Global.AetherExitNodeTag)["streamSettings"]?["sockopt"]?["tcpUserTimeout"]).Should().BeNull();
            await g.Core.Exit.TcpUserTimeout.Should().BeNull();
        }
    }

    [Test]
    public async Task AProfileChosenAsTheExitNodeKeepsItsOwnAndTheAetherProfilesDoesNotCount()
    {
        var germany = AetherConfigTests.Vless("germany-id", "germany", "198.51.100.9");
        germany.TcpUserTimeout = 5000;
        var warp = AetherConfigTests.Warp(extra: extra => extra with
        {
            AetherTransport = AetherTransport.Http2.Type,
            AetherExitNode = "germany",
        });
        warp.TcpUserTimeout = 10000;
        var context = AetherConfigTests.AetherContext(AetherConfigTests.NewConfig(), warp);
        context.Aether.ExitNodes["germany"] = ExitNodeLookup.Of(new ByName<ProfileItem>.One(germany));

        var g = await AetherConfigTests.Succeeds(context);

        var exitNode = g.Outbound(Global.AetherExitNodeTag);
        await exitNode.protocol.Should().BeEqualTo("vless");
        await exitNode.streamSettings!.sockopt!.tcpUserTimeout.Should().BeEqualTo(5000);
        await g.Core.Exit.TcpUserTimeout.Should().BeNull();
    }

    [Test]
    public async Task TheExitOfAScanTakesItAsTheSessionsDoes()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var context = CoreConfigTestFactory.CreateContext(config, AetherExitHost.ContextProfile(), ECoreType.Xray);

        var result = new CoreConfigV2rayService(context).GenerateAetherExitConfig(new AetherExit(TcpUserTimeout: 9000), 41970);

        await result.Success.Should().BeTrue();
        var exitNode = JsonNode.Parse(result.Data!.ToString()!)!["outbounds"]!.AsArray().Single()!;
        await exitNode["protocol"]!.GetValue<string>().Should().BeEqualTo("freedom");
        await exitNode["streamSettings"]!["sockopt"]!["tcpUserTimeout"]!.GetValue<int>().Should().BeEqualTo(9000);
    }

    [Test]
    public async Task TheKeyOfAnExitNodeTellsItsTcpUserTimeoutAndStaysWhatItWasWithout()
    {
        var plain = new AetherExit(FinalMask: "{}", DialMode: "oob.0");
        var timed = plain with { TcpUserTimeout = 10000 };

        await timed.Key.Should().NotBeEqualTo(plain.Key);
        await (timed with { TcpUserTimeout = 9000 }).Key.Should().NotBeEqualTo(timed.Key);
        // The key of an exit-node without one is the one it had before tcpUserTimeout came: the three digests joined.
        var before = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes("{}\u0000oob.0\u0000")));
        await plain.Key.Should().BeEqualTo(before);
    }
}
