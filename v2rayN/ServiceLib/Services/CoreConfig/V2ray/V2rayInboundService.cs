namespace ServiceLib.Services.CoreConfig;

public partial class CoreConfigV2rayService
{
    private void GenInbounds()
    {
        try
        {
            var listen = "0.0.0.0";
            var listenPort = AppManager.Instance.GetLocalPort(EInboundProtocol.socks);
            _coreConfig.inbounds = [];
            var inboundConf = _config.Inbound.First();
            var inbound = BuildInbound(inboundConf, EInboundProtocol.socks, true);
            var isUsingLocalMixedPort = _node.Address == Global.Loopback && _node.Port == listenPort;

            if (!context.IsTunEnabled || !isUsingLocalMixedPort)
            {
                _coreConfig.inbounds.Add(inbound);

                if (inboundConf.SecondLocalPortEnabled)
                {
                    var inbound2 = BuildInbound(inboundConf, EInboundProtocol.socks2, true);
                    _coreConfig.inbounds.Add(inbound2);
                }

                if (inboundConf.AllowLANConn)
                {
                    if (inboundConf.NewPort4LAN)
                    {
                        var inbound3 = BuildInbound(inboundConf, EInboundProtocol.socks3, true);
                        inbound3.listen = listen;
                        _coreConfig.inbounds.Add(inbound3);

                        // auth
                        if (inboundConf.User.IsNotEmpty() && inboundConf.Pass.IsNotEmpty())
                        {
                            inbound3.settings.auth = "password";
                            inbound3.settings.accounts =
                            [
                                new()
                                {
                                    user = inboundConf.User,
                                    pass = inboundConf.Pass,
                                },

                            ];
                        }
                    }
                    else
                    {
                        inbound.listen = listen;
                    }
                }
            }

            if (context.IsTunEnabled)
            {
                if (_config.TunModeItem.Mtu <= 0)
                {
                    _config.TunModeItem.Mtu = Global.TunMtus.First();
                }
                var tunInbound =
                    JsonUtils.Deserialize<Inbounds4Ray>(EmbedUtils.GetEmbedText(Global.V2raySampleTunInbound)) ??
                    new Inbounds4Ray();
                tunInbound.settings.name = context.IsMacOS ? $"utun{new Random().Next(99)}" : "xray_tun";
                tunInbound.settings.MTU = _config.TunModeItem.Mtu;

                var address = _config.TunModeItem.IPv4Address.NullIfEmpty() ?? Global.TunIPv4Address.First();
                tunInbound.settings.gateway = [address];
                // PattN: on Windows with strict route, misconfigtun blocks an IP version that has no route into
                // the TUN, so IPv6 goes into the TUN only when EnableIPv6Address is on and is blocked otherwise.
                // Elsewhere nothing blocks it: without ::/0, IPv6 bypasses the tunnel, so ::/0 is skipped only
                // when the host has no global IPv6 address and EnableIPv6Address is off; NAT66 hosts have only
                // ULA addresses. Where the OS keeps IPv6 off on new interfaces, a TUN asked for IPv6 does not
                // start (Xray-core leaves IPv6 out only when the config asks for none, XTLS/Xray-core#6874), so
                // EnableIPv6Address counts for nothing there; a global IPv6 address that an existing interface
                // still has keeps ::/0 outside Windows strict route, and the TUN then fails to start rather than
                // let that IPv6 bypass it.
                var wfpBlocksLeaks = context.IsWindows && _config.TunModeItem.StrictRoute == true;
                var tunIPv6 = _config.TunModeItem.EnableIPv6Address && !context.IsIPv6DisabledByOs;
                var routeIPv6 = tunIPv6 || (!wfpBlocksLeaks && context.HasGlobalIPv6Address);
                tunInbound.settings.autoSystemRoutingTable = routeIPv6
                    ? ["0.0.0.0/0", "::/0"]
                    : ["0.0.0.0/0"];
                if (tunIPv6)
                {
                    var address6 = _config.TunModeItem.IPv6Address.NullIfEmpty() ?? Global.TunIPv6Address.First();
                    tunInbound.settings.gateway.Add(address6);
                }

                var bindInterface = NetworkUtils.GetRealBindInterfaceName(_config.CoreBasicItem.BindInterface);
                if (!bindInterface.IsNullOrEmpty())
                {
                    tunInbound.settings.autoOutboundsInterface = bindInterface;
                }
                tunInbound.sniffing = JsonUtils.DeepCopy(inbound.sniffing);
                // PattN: respect the user's Route Only setting in TUN mode (upstream forces true)
                // tunInbound.sniffing.routeOnly = true;

                if (wfpBlocksLeaks)
                {
                    tunInbound.settings.autoSystemWfpBlockLeak = ["dns", "misconfigtun"];
                }
                if (context.IsLinux)
                {
                    tunInbound.settings.autoSystemDnsToGateway = true;
                }

                if (_config.TunModeItem.RouteExcludeAddress is { Count: > 0 })
                {
                    var wholeInternet = IPNetwork2.Parse("0.0.0.0/0");
                    var wholeInternetV6 = IPNetwork2.Parse("::/0");

                    var excludeList = _config.TunModeItem.RouteExcludeAddress.Select(IPNetwork2.Parse)
                        .Where(x => x != null).ToList();

                    var includeList = new List<IPNetwork2> { wholeInternet };
                    var includeListV6 = routeIPv6
                        ? new List<IPNetwork2> { wholeInternetV6 }
                        : new List<IPNetwork2>();

                    foreach (var exclude in excludeList)
                    {
                        var temp = new List<IPNetwork2>();
                        if (exclude.AddressFamily == AddressFamily.InterNetwork)
                        {
                            foreach (var net in includeList)
                            {
                                temp.AddRange(net.Subtract(exclude));
                            }
                            includeList = temp;
                        }
                        else if (exclude.AddressFamily == AddressFamily.InterNetworkV6)
                        {
                            foreach (var net in includeListV6)
                            {
                                temp.AddRange(net.Subtract(exclude));
                            }
                            includeListV6 = temp;
                        }
                    }

                    includeList = IPNetwork2.Supernet(includeList.ToArray()).ToList();
                    includeListV6 = IPNetwork2.Supernet(includeListV6.ToArray()).ToList();

                    tunInbound.settings.autoSystemRoutingTable = includeList.Select(x => x.ToString())
                        .Concat(includeListV6.Select(x => x.ToString())).ToList();
                }

                _coreConfig.inbounds.Add(tunInbound);
            }
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
        }
    }

    private Inbounds4Ray BuildInbound(InItem inItem, EInboundProtocol protocol, bool bSocks)
    {
        var result = EmbedUtils.GetEmbedText(Global.V2raySampleInbound);
        if (result.IsNullOrEmpty())
        {
            return new();
        }

        var inbound = JsonUtils.Deserialize<Inbounds4Ray>(result);
        if (inbound == null)
        {
            return new();
        }
        inbound.tag = protocol.ToString();
        inbound.port = inItem.LocalPort + (int)protocol;
        inbound.protocol = nameof(EInboundProtocol.mixed);
        inbound.settings.udp = inItem.UdpEnabled;
        inbound.sniffing.enabled = inItem.SniffingEnabled;
        // PattN: copy the list; adding "fakedns" below must not leak into the saved settings
        inbound.sniffing.destOverride = inItem.DestOverride?.ToList();
        inbound.sniffing.routeOnly = inItem.RouteOnly;

        if (_config.SimpleDNSItem.FakeIP == true)
        {
            // Ensure destOverride contains "fakedns" if FakeIP is enabled
            inbound.sniffing.destOverride ??= [];
            if (!inbound.sniffing.destOverride.Contains("fakedns"))
            {
                inbound.sniffing.destOverride.Add("fakedns");
            }
        }
        else
        {
            // PattN: drop "fakedns" that older builds persisted into the settings while FakeIP was on
            inbound.sniffing.destOverride?.Remove("fakedns");
        }

        return inbound;
    }
}
