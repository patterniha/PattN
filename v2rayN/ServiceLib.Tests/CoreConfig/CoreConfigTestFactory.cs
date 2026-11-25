namespace ServiceLib.Tests.CoreConfig;

internal static class CoreConfigTestFactory
{
    public static void BindAppManagerConfig(Config config)
    {
        var field = typeof(ConfigState).GetField("_current", BindingFlags.Instance | BindingFlags.NonPublic);
        field?.SetValue(ConfigState.Instance, config);
    }

    public static Config CreateConfig(ECoreType vmessCoreType = ECoreType.Xray)
    {
        return new Config
        {
            CoreBasicItem = new CoreBasicItem { Loglevel = "warning" },
            TunModeItem = new TunModeItem { EnableTun = false, IcmpRouting = "default" },
            KcpItem = new KcpItem(),
            GrpcItem = new GrpcItem(),
            RoutingBasicItem =
                new RoutingBasicItem
                {
                    DomainStrategy = Global.AsIs,
                    DomainStrategy4Singbox = string.Empty,
                    RoutingIndexId = string.Empty,
                },
            GuiItem = new GUIItem { EnableStatistics = false, DisplayRealTimeSpeed = false, EnableLog = false },
            MsgUIItem = new MsgUIItem(),
            UiItem =
                new UIItem
                {
                    CurrentLanguage = "en",
                    CurrentFontFamily = "sans",
                    MainColumnItem = [],
                    WindowSizeItem = []
                },
            ConstItem = new ConstItem(),
            SpeedTestItem = new SpeedTestItem
            {
                SpeedPingTestUrl = Global.SpeedPingTestUrls.First(),
                SpeedTestUrl = Global.SpeedTestUrls.First(),
                SpeedTestTimeout = 10,
                MixedConcurrencyCount = 1,
                IPAPIUrl = string.Empty,
            },
            Mux4RayItem = new Mux4RayItem { Concurrency = 8, XudpConcurrency = 16, XudpProxyUDP443 = "reject" },
            Mux4SboxItem = new Mux4SboxItem { Protocol = Global.SingboxMuxs.First(), MaxConnections = 8 },
            HysteriaItem = new HysteriaItem { UpMbps = 100, DownMbps = 100 },
            ClashUIItem = new ClashUIItem { ConnectionsColumnItem = [] },
            SystemProxyItem =
                new SystemProxyItem
                {
                    SystemProxyExceptions = string.Empty,
                    SystemProxyAdvancedProtocol = string.Empty
                },
            WebDavItem = new WebDavItem(),
            CheckUpdateItem = new CheckUpdateItem(),
            Fragment4RayItem = new Fragment4RayItem { Packets = "tlshello", Lengths = ["100-200"], Delays = ["10-20"] },
            Inbound =
            [
                new InItem
                {
                    Protocol = nameof(EInboundProtocol.socks),
                    LocalPort = 10808,
                    UdpEnabled = true,
                    SniffingEnabled = true,
                    RouteOnly = false,
                    DestOverride = ["http", "tls"],
                }
            ],
            GlobalHotkeys = [],
            CoreTypeItem =
            [
                new CoreTypeItem { ConfigType = EConfigType.VMess, CoreType = vmessCoreType }
            ],
            SimpleDNSItem = new SimpleDNSItem
            {
                BootstrapDNS = Global.DomainPureIPDNSAddress.FirstOrDefault(),
                ServeStale = false,
                ParallelQuery = false,
                Strategy4Freedom = Global.AsIs,
                Strategy4Proxy = Global.AsIs,
                Strategy4ProxyDial = Global.AsIs,
            },
            IndexId = string.Empty,
            SubIndexId = string.Empty,
        };
    }

    public static ProfileItem CreateVmessNode(ECoreType coreType, string indexId = "node-1", string remarks = "demo")
    {
        var node = new ProfileItem
        {
            IndexId = indexId,
            ConfigType = EConfigType.VMess,
            CoreType = coreType,
            Remarks = remarks,
            Address = "example.com",
            Port = 443,
            Password = Guid.NewGuid().ToString(),
            Network = nameof(ETransport.raw),
            StreamSecurity = string.Empty,
            Subid = string.Empty,
        };

        node.SetProtocolExtra(node.GetProtocolExtra() with { AlterId = "0", VmessSecurity = Global.DefaultSecurity, });

        return node;
    }

    public static ProfileItem CreateSocksNode(ECoreType coreType, string indexId = "node-socks-1",
        string remarks = "demo-socks")
    {
        return new ProfileItem
        {
            IndexId = indexId,
            ConfigType = EConfigType.SOCKS,
            CoreType = coreType,
            Remarks = remarks,
            Address = "127.0.0.1",
            Port = 1080,
            Password = "pass",
            Username = "user",
            Network = nameof(ETransport.raw),
            StreamSecurity = string.Empty,
            Subid = string.Empty,
        };
    }

    public static ProfileItem CreateHttpNode(ECoreType coreType, string indexId = "node-http-1",
        string remarks = "demo-http")
    {
        return new ProfileItem
        {
            IndexId = indexId,
            ConfigType = EConfigType.HTTP,
            CoreType = coreType,
            Remarks = remarks,
            Address = "proxy.example.com",
            Port = 8080,
            Password = "pass",
            Username = "user",
            Network = nameof(ETransport.raw),
            StreamSecurity = string.Empty,
            Subid = string.Empty,
        };
    }

    public static ProfileItem CreateWireguardNode(ECoreType coreType, string indexId = "node-wg-1",
        string remarks = "demo-wg")
    {
        var node = new ProfileItem
        {
            IndexId = indexId,
            ConfigType = EConfigType.WireGuard,
            CoreType = coreType,
            Remarks = remarks,
            Address = "wg.example.com",
            Port = 51820,
            Password = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            Network = nameof(ETransport.raw),
            StreamSecurity = string.Empty,
            Subid = string.Empty,
        };

        node.SetProtocolExtra(node.GetProtocolExtra() with
        {
            WgPublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            WgReserved = "0,0,0",
            WgInterfaceAddress = "172.16.0.2/32",
            WgMtu = 1420,
        });

        return node;
    }

    public static ProfileItem CreateCustomOutboundNode(ECoreType coreType, string indexId = "node-custom-1",
        string remarks = "demo-custom-outbound", string address = "custom_outbound.json")
    {
        return new ProfileItem
        {
            IndexId = indexId,
            ConfigType = EConfigType.Outbound,
            CoreType = coreType,
            Remarks = remarks,
            Address = address,
            Port = 0,
            Network = nameof(ETransport.raw),
            StreamSecurity = string.Empty,
            Subid = string.Empty,
        };
    }

    // PattN: an Aether profile as the editor stores it: no endpoint unless given (its core scans), Xray to run it, and
    // the Aether settings of ProtocolExtraItem; protocol is the stored type (masque, wg, gool, mim, wg-over-masque).
    public static ProfileItem CreateAetherNode(string indexId, string remarks, string protocol = "masque",
        Func<ProtocolExtraItem, ProtocolExtraItem>? extra = null, string address = "", int port = 0)
    {
        var node = new ProfileItem
        {
            IndexId = indexId,
            ConfigType = EConfigType.Aether,
            CoreType = ECoreType.Xray,
            Remarks = remarks,
            Address = address,
            Port = port,
            Network = Global.DefaultNetwork,
            StreamSecurity = string.Empty,
            Subid = string.Empty,
        };
        var protocolExtra = new ProtocolExtraItem { AetherProtocol = protocol };
        node.SetProtocolExtra(extra == null ? protocolExtra : extra(protocolExtra));
        return node;
    }

    public static ProfileItem CreatePolicyGroupNode(ECoreType coreType, string indexId, string remarks,
        IEnumerable<string> childIndexIds)
    {
        var node = new ProfileItem
        {
            IndexId = indexId,
            ConfigType = EConfigType.PolicyGroup,
            CoreType = coreType,
            Remarks = remarks,
        };
        node.SetProtocolExtra(node.GetProtocolExtra() with
        {
            GroupType = nameof(EConfigType.PolicyGroup),
            ChildItems = string.Join(",", childIndexIds),
        });

        return node;
    }

    public static ProfileItem CreateProxyChainNode(ECoreType coreType, string indexId, string remarks,
        IEnumerable<string> childIndexIds)
    {
        var node = new ProfileItem
        {
            IndexId = indexId,
            ConfigType = EConfigType.ProxyChain,
            CoreType = coreType,
            Remarks = remarks,
        };
        node.SetProtocolExtra(node.GetProtocolExtra() with
        {
            GroupType = nameof(EConfigType.ProxyChain),
            ChildItems = string.Join(",", childIndexIds),
        });

        return node;
    }

    public static CoreConfigContext CreateContext(Config config, ProfileItem node, ECoreType runCoreType,
        bool hasGlobalIPv6Address = true, FullConfigTemplateItem? fullConfigTemplate = null)
    {
        return new CoreConfigContext
        {
            Node = node,
            RunCoreType = runCoreType,
            AppConfig = config,
            RoutingItem = new RoutingItem
            {
                Id = "r1",
                Remarks = "default",
                RuleSet = "[]",
                DomainStrategy = Global.AsIs,
                DomainStrategy4Singbox = string.Empty,
            },
            RawDnsItem = null,
            SimpleDnsItem = config.SimpleDNSItem,
            AllProxiesMap = new Dictionary<string, ProfileItem> { [node.IndexId] = node },
            FullConfigTemplate = fullConfigTemplate,
            IsTunEnabled = config.TunModeItem.EnableTun,
            ProtectDomainList = [],
            HasGlobalIPv6Address = hasGlobalIPv6Address,
        };
    }

    public static Config CreateConfigWithDirectExpectedIPs(ECoreType coreType,
        string directExpectedIPs = "192.168.0.0/16,geoip:cn")
    {
        var config = CreateConfig(coreType);
        config.SimpleDNSItem.DirectExpectedIPs = directExpectedIPs;
        return config;
    }

    public static Config CreateConfigWithBootstrapDNS(ECoreType coreType, string bootstrapDns = "8.8.8.8")
    {
        var config = CreateConfig(coreType);
        config.SimpleDNSItem.BootstrapDNS = bootstrapDns;
        return config;
    }

    public static Config CreateConfigWithTunRouteExcludeAddress(ECoreType coreType)
    {
        var config = CreateConfig(coreType);
        config.TunModeItem.EnableTun = true;
        config.TunModeItem.RouteExcludeAddress = ["10.0.0.1/32", "192.168.1.0/24", "fc00::/7"];
        return config;
    }

    public static Config CreateConfigWithTun(ECoreType coreType, bool enableIPv6Address)
    {
        var config = CreateConfig(coreType);
        config.TunModeItem.EnableTun = true;
        config.TunModeItem.EnableIPv6Address = enableIPv6Address;
        return config;
    }
}
