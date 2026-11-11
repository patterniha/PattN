namespace ServiceLib.Services.CoreConfig;

public partial class CoreConfigV2rayService(CoreConfigContext context)
{
    private static readonly string _tag = "CoreConfigV2rayService";
    private readonly Config _config = context.AppConfig;
    private readonly ProfileItem _node = context.Node;

    private V2rayConfig _coreConfig = new();

    #region public gen function

    public RetResult GenerateClientConfigContent()
    {
        var ret = new RetResult();
        try
        {
            if (_node == null
                || !_node.IsValid())
            {
                ret.Msg = ResUI.CheckServerSettings;
                return ret;
            }

            if (_node.GetNetwork() is nameof(ETransport.quic))
            {
                ret.Msg = ResUI.Incorrectconfiguration + $" - {_node.GetNetwork()}";
                return ret;
            }

            ret.Msg = ResUI.InitialConfiguration;

            var result = EmbedUtils.GetEmbedText(Global.V2raySampleClient);
            if (result.IsNullOrEmpty())
            {
                ret.Msg = ResUI.FailedGetDefaultConfiguration;
                return ret;
            }

            _coreConfig = JsonUtils.Deserialize<V2rayConfig>(result);
            if (_coreConfig == null)
            {
                ret.Msg = ResUI.FailedGenDefaultConfiguration;
                return ret;
            }

            // PattN: the ECH outbounds of this config are collected while its outbounds are built
            context.EchOutbounds.Clear();
            // PattN: and so are its Aether outbounds
            context.Aether.Reset();
            GenLog();

            GenInbounds();

            GenOutbounds();

            GenRouting();

            GenDns();

            if (context.IsTunEnabled)
            {
                // PattN: with the TUN inbound, freedom must resolve domain targets via the built-in
                // DNS instead of the OS resolver, whose queries would detour back through the tun
                var directOutbound = _coreConfig.outbounds.FirstOrDefault(t => t is { protocol: "freedom", tag: Global.DirectTag });
                if (directOutbound != null)
                {
                    directOutbound.streamSettings ??= new();
                    directOutbound.streamSettings.sockopt ??= new();
                    directOutbound.streamSettings.sockopt.domainStrategy ??= "ForceIP";
                }
            }

            // PattN: what the Aether core sends out leaves through Xray; after GenDns, whose proxy strategies the
            // exit-node must not get
            var aetherError = GenAether(AetherPorts.SecondarySocksPortOf(AetherListenPort), forTest: false);
            if (aetherError != null)
            {
                ret.Msg = aetherError;
                return ret;
            }

            GenStatistic();

            if (_config.CoreBasicItem.EnableFragment)
            {
                ApplyOutboundFragment();
            }
            if (_config.CoreBasicItem.EnableFinalFragment)
            {
                ApplyFinalFragment();
            }

            var finalRule = BuildFinalRule();
            if (!string.IsNullOrEmpty(finalRule?.balancerTag))
            {
                _coreConfig.routing.rules.Add(finalRule);
            }

            var coreConfigContent = ApplyFinalConfigModifiers();
            // PattN: the ECH outbounds go after every other outbound
            var echOutboundError = AppendEchOutbounds(ref coreConfigContent);
            if (echOutboundError != null)
            {
                ret.Msg = echOutboundError;
                return ret;
            }
            // PattN: an inbound on a port of the Aether core, a full configuration template's among them
            var aetherConfigError = CheckAetherConfig(coreConfigContent);
            if (aetherConfigError != null)
            {
                ret.Msg = aetherConfigError;
                return ret;
            }

            ret.Msg = string.Format(ResUI.SuccessfulConfiguration, "");
            ret.Success = true;
            ret.Data = coreConfigContent;
            return ret;
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
            ret.Msg = ResUI.FailedGenDefaultConfiguration;
            return ret;
        }
    }

    public RetResult GenerateClientSpeedtestConfig(List<ServerTestItem> selecteds)
    {
        var ret = new RetResult();
        try
        {
            ret.Msg = ResUI.InitialConfiguration;

            var result = EmbedUtils.GetEmbedText(Global.V2raySampleClient);
            var txtOutbound = EmbedUtils.GetEmbedText(Global.V2raySampleOutbound);
            if (result.IsNullOrEmpty() || txtOutbound.IsNullOrEmpty())
            {
                ret.Msg = ResUI.FailedGetDefaultConfiguration;
                return ret;
            }

            _coreConfig = JsonUtils.Deserialize<V2rayConfig>(result);
            if (_coreConfig == null)
            {
                ret.Msg = ResUI.FailedGenDefaultConfiguration;
                return ret;
            }

            var (lstIpEndPoints, lstTcpConns) = Utils.GetActiveNetworkInfo();

            // PattN: the ECH outbounds of this config are collected while its outbounds are built
            context.EchOutbounds.Clear();
            // PattN: and so are its Aether outbounds
            context.Aether.Reset();
            GenLog();
            _coreConfig.inbounds.Clear();
            _coreConfig.outbounds.Clear();
            _coreConfig.routing.rules.Clear();

            var initPort = AppManager.Instance.GetLocalPort(EInboundProtocol.speedtest);

            foreach (var it in selecteds)
            {
                if (!(Global.XraySupportConfigType.Contains(it.ConfigType) || it.ConfigType.IsGroupType() || it.ConfigType is EConfigType.Outbound))
                {
                    continue;
                }
                // PattN: an Aether profile needs a core of its own on the Aether listen port, so its test runs alone
                if (it.ConfigType == EConfigType.Aether)
                {
                    continue;
                }
                if (!it.ConfigType.IsComplexType() && it.Port <= 0)
                {
                    continue;
                }
                var actIndexId = context.ServerTestItemMap.GetValueOrDefault(it.IndexId, it.IndexId);
                var item = context.AllProxiesMap.GetValueOrDefault(actIndexId);
                if (item is null || item.ConfigType is EConfigType.Custom || !item.IsValid())
                {
                    continue;
                }

                //find unused port
                var port = initPort;
                for (var k = initPort; k < Global.MaxPort; k++)
                {
                    if (lstIpEndPoints?.FindIndex(_it => _it.Port == k) >= 0)
                    {
                        continue;
                    }
                    if (lstTcpConns?.FindIndex(_it => _it.LocalEndPoint.Port == k) >= 0)
                    {
                        continue;
                    }
                    // PattN: never a port the Aether core may take: the session's or a latency test's core may need it
                    if (AetherPorts.IsReserved(k, AetherListenPort))
                    {
                        continue;
                    }
                    //found
                    port = k;
                    initPort = port + 1;
                    break;
                }

                //Port In Used
                if (lstIpEndPoints?.FindIndex(_it => _it.Port == port) >= 0)
                {
                    continue;
                }
                it.Port = port;
                it.AllowTest = true;

                //inbound
                Inbounds4Ray inbound = new()
                {
                    listen = Global.Loopback,
                    port = port,
                    protocol = nameof(EInboundProtocol.mixed),
                    settings = new Inboundsettings4Ray()
                    {
                        udp = true,
                        auth = "noauth"
                    },
                };
                inbound.tag = inbound.protocol + inbound.port.ToString();
                _coreConfig.inbounds.Add(inbound);

                var tag = Global.ProxyTag + inbound.port.ToString();
                var isBalancer = false;
                //outbound
                var service = new CoreConfigV2rayService(context with { Node = item });
                var proxyOutbounds = service.BuildAllProxyOutbounds(tag);
                // PattN: a group or a chain that dials an Aether core is tested on its own, with its core (design
                // 2.12.1); one left in the batch is not tested rather than dial a core that is not there
                if (proxyOutbounds.Any(context.Aether.IsAetherOutbound))
                {
                    _coreConfig.inbounds.Remove(inbound);
                    it.AllowTest = false;
                    continue;
                }
                _coreConfig.outbounds.AddRange(proxyOutbounds);
                if (proxyOutbounds.Count(n => n.tag.StartsWith(tag)) > 1)
                {
                    isBalancer = true;
                    var multipleLoad = service.FindFirstPolicyGroupMultipleLoad() ?? EMultipleLoad.LeastPing;
                    GenObservatory(multipleLoad, tag);
                    GenBalancer(multipleLoad, tag);
                }

                //rule
                RulesItem4Ray rule = new()
                {
                    inboundTag = [inbound.tag],
                    outboundTag = tag,
                    type = "field"
                };
                if (isBalancer)
                {
                    rule.balancerTag = tag + Global.BalancerTagSuffix;
                    rule.outboundTag = null;
                }
                _coreConfig.routing.rules.Add(rule);
            }
            // PattN: a test has no DNS, so the Aether outbounds pass every name on
            TrimAetherOutboundsForTest();

            if (_config.CoreBasicItem.EnableFragment)
            {
                ApplyOutboundFragment();
            }
            if (_config.CoreBasicItem.EnableFinalFragment)
            {
                ApplyFinalFragment();
            }
            ApplyOutboundBindInterface();
            ApplyOutboundSendThrough();
            var coreConfigContent = ApplyCustomOutboundReplace();
            // PattN: the ECH outbounds go after every other outbound
            var echOutboundError = AppendEchOutbounds(ref coreConfigContent);
            if (echOutboundError != null)
            {
                ret.Msg = echOutboundError;
                return ret;
            }

            //ret.Msg =string.Format(ResUI.SuccessfulConfiguration"), node.getSummary());
            ret.Success = true;
            ret.Data = coreConfigContent;
            return ret;
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
            ret.Msg = ResUI.FailedGenDefaultConfiguration;
            return ret;
        }
    }

    public RetResult GenerateClientSpeedtestConfig(int port)
    {
        var ret = new RetResult();
        try
        {
            if (_node == null
                || !_node.IsValid())
            {
                ret.Msg = ResUI.CheckServerSettings;
                return ret;
            }

            if (_node.GetNetwork() is nameof(ETransport.quic))
            {
                ret.Msg = ResUI.Incorrectconfiguration + $" - {_node.GetNetwork()}";
                return ret;
            }

            var result = EmbedUtils.GetEmbedText(Global.V2raySampleClient);
            if (result.IsNullOrEmpty())
            {
                ret.Msg = ResUI.FailedGetDefaultConfiguration;
                return ret;
            }

            _coreConfig = JsonUtils.Deserialize<V2rayConfig>(result);
            if (_coreConfig == null)
            {
                ret.Msg = ResUI.FailedGenDefaultConfiguration;
                return ret;
            }

            // PattN: the ECH outbounds of this config are collected while its outbounds are built
            context.EchOutbounds.Clear();
            // PattN: and so are its Aether outbounds
            context.Aether.Reset();
            GenLog();
            GenOutbounds();

            _coreConfig.routing.domainStrategy = Global.AsIs;
            _coreConfig.routing.rules.Clear();
            _coreConfig.inbounds.Clear();
            _coreConfig.inbounds.Add(new()
            {
                tag = $"{EInboundProtocol.socks}{port}",
                listen = Global.Loopback,
                port = port,
                protocol = nameof(EInboundProtocol.mixed),
                settings = new Inboundsettings4Ray()
                {
                    udp = true,
                    auth = "noauth"
                },
            });

            _coreConfig.routing.rules.Add(BuildFinalRule());

            // PattN: a test has no DNS (one bound to the uplink has its own, D2-3), so the Aether outbounds pass every
            // name on. A test whose own core the tester starts (it picks the secondary port) routes that core through
            // this Xray, after the inbounds and rules of the session were cleared; one that measures through the live
            // session's core leaves its routing to the session's Xray, and is refused for what one core cannot serve all
            // the same.
            TrimAetherOutboundsForTest();
            var aetherError = context.Aether.SecondaryPort is { } secondaryPort
                ? GenAether(secondaryPort, forTest: true)
                : CheckAether();
            if (aetherError != null)
            {
                ret.Msg = aetherError;
                return ret;
            }

            if (_config.CoreBasicItem.EnableFragment)
            {
                ApplyOutboundFragment();
            }
            if (_config.CoreBasicItem.EnableFinalFragment)
            {
                ApplyFinalFragment();
            }
            // PattN: the Xray of an Aether latency test bound to the uplink under a TUN looks names up by its own DNS (D2-3)
            LookUpNamesByUplink();
            ApplyOutboundBindInterface();
            ApplyOutboundSendThrough();

            var coreConfigContent = ApplyCustomOutboundReplace();
            // PattN: the ECH outbounds go after every other outbound
            var echOutboundError = AppendEchOutbounds(ref coreConfigContent);
            if (echOutboundError != null)
            {
                ret.Msg = echOutboundError;
                return ret;
            }
            // PattN: the test inbound on a port of the Aether core
            var aetherPortError = CheckAetherConfig(coreConfigContent);
            if (aetherPortError != null)
            {
                ret.Msg = aetherPortError;
                return ret;
            }

            ret.Msg = string.Format(ResUI.SuccessfulConfiguration, "");
            ret.Success = true;
            ret.Data = coreConfigContent;
            return ret;
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
            ret.Msg = ResUI.FailedGenDefaultConfiguration;
            return ret;
        }
    }

    #endregion public gen function
}
