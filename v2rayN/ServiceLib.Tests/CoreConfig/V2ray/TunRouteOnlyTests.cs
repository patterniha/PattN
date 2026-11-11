namespace ServiceLib.Tests.CoreConfig.V2ray;

/// <summary>
/// PattN: the TUN inbound follows the Route Only setting, as the local inbound does; upstream forces it on for the TUN.
/// </summary>
public class TunRouteOnlyTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task TheTunInboundFollowsTheRouteOnlySetting(bool routeOnly)
    {
        var config = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, true);
        config.Inbound.First().RouteOnly = routeOnly;
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray);
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();

        await result.Success.Should().BeTrue().Because(result.Msg ?? string.Empty);
        var generated = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        var tun = generated.inbounds.Single(inbound => inbound.protocol == "tun");
        var local = generated.inbounds.First(inbound => inbound.tag == nameof(EInboundProtocol.socks));
        await tun.sniffing.routeOnly.Should().BeEqualTo(routeOnly);
        await local.sniffing.routeOnly.Should().BeEqualTo(routeOnly);
    }
}
