namespace ServiceLib.Services.CoreConfig;

public partial class CoreConfigV2rayService
{
    private void GenDns()
    {
        // PattN: an unusable FakeIP range fails the configuration, as it fails sing-box's, before the try below: there,
        // where errors are only logged, it left the configuration without its DNS
        if (context.RawDnsItem is not { Enabled: true })
        {
            CheckFakeIPRanges();
        }
        try
        {
            var item = context.RawDnsItem;
            if (item is { Enabled: true })
            {
                GenDnsCustom();

                if (_coreConfig.routing.domainStrategy != Global.IPIfNonMatch)
                {
                    return;
                }

                // DNS routing
                var dnsNode = JsonUtils.SerializeToNode(_coreConfig.dns);
                if (dnsNode is not JsonObject dnsObj)
                {
                    return;
                }

                dnsObj["tag"] = Global.DnsTag;
                _coreConfig.dns = dnsObj;
                _coreConfig.routing.rules.Insert(0, new RulesItem4Ray
                {
                    type = "field",
                    inboundTag = [Global.DnsTag],
                    outboundTag = Global.ProxyTag,
                });
                return;
            }
            var simpleDnsItem = context.SimpleDnsItem;
            var dnsItem = new Dns4Ray();

            var strategy4Freedom = simpleDnsItem?.Strategy4Freedom ?? Global.AsIs;
            //Outbound Freedom domainStrategy
            if (strategy4Freedom.IsNotEmpty() && strategy4Freedom != Global.AsIs)
            {
                var outbound = _coreConfig.outbounds.FirstOrDefault(t => t is { protocol: "freedom", tag: Global.DirectTag });
                if (outbound != null)
                {
                    FillSockoptDomainStrategy(outbound, strategy4Freedom);
                }
            }

            var strategy4Proxy = simpleDnsItem?.Strategy4Proxy ?? Global.AsIs;
            //Outbound Proxy domainStrategy
            if (strategy4Proxy.IsNotEmpty() && strategy4Proxy != Global.AsIs)
            {
                var xraySupportConfigTypeNames = Global.XraySupportConfigType
                        .Select(x => x == EConfigType.Hysteria2 ? "hysteria" : Global.ProtocolTypes[x])
                        .ToHashSet();
                _coreConfig.outbounds
                    .Where(t => xraySupportConfigTypeNames.Contains(t.protocol))
                    // PattN: an Aether outbound keeps the default of where its traffic leaves, and the exit-node none
                    .Where(t => !KeepsAetherTargetStrategy(t))
                    .ToList()
                    .ForEach(outbound =>
                    {
                        // PattN: a targetStrategy chosen on the profile wins over this global default
                        if (outbound.targetStrategy.IsNullOrEmpty())
                        {
                            outbound.targetStrategy = strategy4Proxy;
                        }
                    });
            }

            var strategy4DialProxy = simpleDnsItem?.Strategy4ProxyDial ?? Global.AsIs;
            //Outbound DialProxy domainStrategy
            if (strategy4DialProxy.IsNotEmpty() && strategy4DialProxy != Global.AsIs)
            {
                var xraySupportConfigTypeNames = Global.XraySupportConfigType
                        .Select(x => x == EConfigType.Hysteria2 ? "hysteria" : Global.ProtocolTypes[x])
                        .ToHashSet();
                _coreConfig.outbounds
                    .Where(t => xraySupportConfigTypeNames.Contains(t.protocol))
                    // PattN: an Aether outbound dials its core on the loopback address
                    .Where(t => !context.Aether.IsAetherOutbound(t))
                    .ToList()
                    .ForEach(outbound =>
                    {
                        FillSockoptDomainStrategy(outbound, strategy4DialProxy);
                    });
            }

            FillDnsServers(dnsItem);
            FillDnsHosts(dnsItem);

            dnsItem.serveStale = simpleDnsItem?.ServeStale is true ? true : null;
            dnsItem.enableParallelQuery = simpleDnsItem?.ParallelQuery is true ? true : null;

            if (simpleDnsItem.BlockAAAAQuery == true)
            {
                dnsItem.queryStrategy = "UseIPv4";
            }

            // DNS routing, inserted at the top so user rules cannot hijack DNS module queries
            var dnsRouteRules = new List<RulesItem4Ray>();
            var directDnsTags = dnsItem.servers
                .Select(server =>
                {
                    var tagNode = (server as JsonObject)?["tag"];
                    return tagNode is JsonValue value && value.TryGetValue<string>(out var tag) ? tag : null;
                })
                .Where(tag => tag is not null && tag.StartsWith(Global.DirectDnsTag, StringComparison.Ordinal))
                .Select(tag => tag!)
                .ToList();
            if (directDnsTags.Count > 0)
            {
                dnsRouteRules.Add(new()
                {
                    type = "field",
                    inboundTag = directDnsTags,
                    outboundTag = Global.DirectTag,
                });
            }

            var finalRule = BuildFinalRule();
            dnsItem.tag = Global.DnsTag;
            dnsRouteRules.Add(new()
            {
                type = "field",
                inboundTag = [Global.DnsTag],
                outboundTag = finalRule.outboundTag,
                balancerTag = finalRule.balancerTag,
            });
            _coreConfig.routing.rules.InsertRange(0, dnsRouteRules);

            _coreConfig.dns = (JsonObject)JsonUtils.SerializeToNode(dnsItem);
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
        }
    }

    private void CheckFakeIPRanges()
    {
        var simpleDnsItem = _config.SimpleDNSItem;
        if (simpleDnsItem?.FakeIP != true)
        {
            return;
        }
        if (!FakeIPUtils.TryParseIPv4Range(simpleDnsItem.FakeIPRange, out _, out _))
        {
            throw new ArgumentException("Invalid IPv4 FakeIP range.");
        }
        if (simpleDnsItem.FakeIPv6 != false && simpleDnsItem.BlockAAAAQuery != true
            && !FakeIPUtils.TryParseIPv6Range(simpleDnsItem.FakeIPv6Range, out _, out _))
        {
            throw new ArgumentException("Invalid IPv6 FakeIP range.");
        }
    }

    private void GenFakeDns()
    {
        // PattN: the IPv4 pool is checked and sized by the same rule as the IPv6 one, min(addresses - 1, 65535)
        if (!FakeIPUtils.TryParseIPv4Range(_config.SimpleDNSItem.FakeIPRange, out var fakeipRange, out var poolSize))
        {
            throw new ArgumentException("Invalid IPv4 FakeIP range.");
        }
        var fakeDns = new FakeDns4Ray
        {
            ipPool = fakeipRange,
            poolSize = poolSize,
        };
        _coreConfig.fakedns = JsonUtils.SerializeToNode(fakeDns);
        // PattN: the IPv6 pool is on unless turned off (ConfigHandler sets it on)
        if (_config.SimpleDNSItem.FakeIPv6 != false && _config.SimpleDNSItem.BlockAAAAQuery != true)
        {
            if (!FakeIPUtils.TryParseIPv6Range(_config.SimpleDNSItem.FakeIPv6Range, out var range6, out var poolSize6))
            {
                throw new ArgumentException("Invalid IPv6 FakeIP range.");
            }
            _coreConfig.fakedns = new JsonArray(
                _coreConfig.fakedns,
                JsonUtils.SerializeToNode(new FakeDns4Ray { ipPool = range6, poolSize = poolSize6 }));
        }
    }

    private void FillDnsServers(Dns4Ray dnsItem)
    {
        var simpleDNSItem = context.SimpleDnsItem;

        var directDNSAddress = ParseDnsAddresses(simpleDNSItem?.DirectDNS, Global.DomainDirectDNSAddress.First());
        var remoteDNSAddress = ParseDnsAddresses(simpleDNSItem?.RemoteDNS, Global.DomainRemoteDNSAddress.First());

        var directDomainList = new HashSet<string>();
        var directGeositeList = new HashSet<string>();
        var proxyDomainList = new HashSet<string>();
        var proxyGeositeList = new HashSet<string>();
        var expectedDomainList = new HashSet<string>();
        var expectedIPs = new HashSet<string>();
        var regionName = string.Empty;

        var bootstrapDNSAddress = ParseDnsAddresses(simpleDNSItem?.BootstrapDNS, Global.DomainPureIPDNSAddress.First());
        var dnsServerDomains = new HashSet<string>();

        foreach (var dns in directDNSAddress)
        {
            var (domain, _, _, _) = Utils.ParseUrl(dns);
            if (domain == "localhost")
            {
                continue;
            }
            if (Utils.IsDomain(domain))
            {
                dnsServerDomains.Add($"full:{domain}");
            }
        }
        foreach (var dns in remoteDNSAddress)
        {
            var (domain, _, _, _) = Utils.ParseUrl(dns);
            if (domain == "localhost")
            {
                continue;
            }
            if (Utils.IsDomain(domain))
            {
                dnsServerDomains.Add($"full:{domain}");
            }
        }

        if (!string.IsNullOrEmpty(simpleDNSItem?.DirectExpectedIPs))
        {
            expectedIPs = (Utils.String2List(simpleDNSItem.DirectExpectedIPs) ?? [])
                .Select(s => s.Trim())
                .Where(s => !string.IsNullOrEmpty(s))
                .ToHashSet();

            foreach (var region in from ip in expectedIPs
                                   where ip.StartsWith(Global.GeoIPPrefix, StringComparison.OrdinalIgnoreCase)
                                   select ip[Global.GeoIPPrefix.Length..]
                                   into region
                                   where !string.IsNullOrEmpty(region)
                                   select region)
            {
                regionName = region;
            }
        }

        var routing = context.RoutingItem;
        List<RulesItem>? rules = null;
        rules = JsonUtils.Deserialize<List<RulesItem>>(routing?.RuleSet) ?? [];
        foreach (var item in rules)
        {
            if (!item.Enabled || item.Domain is null || item.Domain.Count == 0)
            {
                continue;
            }

            if (item.RuleType == ERuleType.Routing)
            {
                continue;
            }

            foreach (var domain in item.Domain)
            {
                if (domain.StartsWith('#'))
                {
                    continue;
                }

                var normalizedDomain = domain.Replace(Global.RoutingRuleComma, ",");

                if (item.OutboundTag == Global.DirectTag)
                {
                    if (normalizedDomain.StartsWith(Global.GeoSitePrefix) || normalizedDomain.StartsWith("ext:"))
                    {
                        var isExpectedDomain = !regionName.IsNullOrEmpty()
                            && (normalizedDomain.EndsWith($"-{regionName}")
                            || normalizedDomain.EndsWith($"@{regionName}")
                            || normalizedDomain == Global.GeoSitePrefix + regionName);
                        var targetList = isExpectedDomain ? expectedDomainList : directGeositeList;
                        targetList.Add(normalizedDomain);
                    }
                    else
                    {
                        directDomainList.Add(normalizedDomain);
                    }
                }
                else if (item.OutboundTag != Global.BlockTag)
                {
                    if (normalizedDomain.StartsWith(Global.GeoSitePrefix) || normalizedDomain.StartsWith("ext:"))
                    {
                        proxyGeositeList.Add(normalizedDomain);
                    }
                    else
                    {
                        proxyDomainList.Add(normalizedDomain);
                    }
                }
            }
        }

        dnsItem.servers ??= [];

        var directDnsTagIndex = 1;

        if (dnsServerDomains.Count > 0)
        {
            AddDnsServers(bootstrapDNSAddress, dnsServerDomains, finalQuery: true);
        }
        if (context.ProtectDomainList.Count > 0)
        {
            // finalQuery: the protected (proxy server) domains must be answered by the direct
            // servers alone, never falling through to resolvers that dial through the proxy itself
            // full: so only the proxy host itself matches, a plain entry is a substring match in Xray DNS
            AddDnsServers(directDNSAddress, context.ProtectDomainList.Select(d => $"full:{d}").ToHashSet(), true, finalQuery: true);
        }

        if (simpleDNSItem.FakeIP == true)
        {
            var fakeIPMatchDomain = new HashSet<string>(proxyDomainList);
            fakeIPMatchDomain.UnionWith(proxyGeositeList);
            if (simpleDNSItem.GlobalFakeIp != false)
            {
                fakeIPMatchDomain.UnionWith(directDomainList);
                fakeIPMatchDomain.UnionWith(directGeositeList);
                fakeIPMatchDomain.UnionWith(expectedDomainList);
            }
            if (fakeIPMatchDomain.Count > 0)
            {
                GenFakeDns();
                AddDnsServers(["fakedns"], fakeIPMatchDomain, skipFallback: false);
            }
        }

        AddDnsServers(remoteDNSAddress, proxyDomainList);
        AddDnsServers(directDNSAddress, directDomainList, true, finalQuery: true);
        AddDnsServers(remoteDNSAddress, proxyGeositeList);
        AddDnsServers(directDNSAddress, directGeositeList, true, finalQuery: true);
        AddDnsServers(directDNSAddress, expectedDomainList, true, expectedIPs, finalQuery: true);

        var useDirectDns = false;

        if (rules?.LastOrDefault() is { OutboundTag: Global.DirectTag } lastRule)
        {
            var noDomain = lastRule.Domain == null || lastRule.Domain.Count == 0;
            var noProcess = lastRule.Process == null || lastRule.Process.Count == 0;
            var isAnyIp = lastRule.Ip == null || lastRule.Ip.Count == 0 || lastRule.Ip.Contains("0.0.0.0/0");
            var isAnyPort = string.IsNullOrEmpty(lastRule.Port) || lastRule.Port == "0-65535";
            var isAnyNetwork = string.IsNullOrEmpty(lastRule.Network) || lastRule.Network == "tcp,udp";
            useDirectDns = noDomain && noProcess && isAnyIp && isAnyPort && isAnyNetwork;
        }

        if (!useDirectDns)
        {
            dnsItem.servers.AddRange(JsonUtils.SerializeToArray(remoteDNSAddress));
        }
        else
        {
            foreach (var dns in directDNSAddress)
            {
                var dnsServer = CreateDnsServer(dns, []);
                dnsServer.tag = $"{Global.DirectDnsTag}-{directDnsTagIndex++}";
                dnsServer.skipFallback = false;
                dnsItem.servers.Add(JsonUtils.SerializeToNode(dnsServer));
            }
        }
        return;

        static List<string> ParseDnsAddresses(string? dnsInput, string defaultAddress)
        {
            var addresses = (Utils.String2List(dnsInput) ?? [])
                .Select(addr => addr.Trim())
                .Where(addr => !string.IsNullOrEmpty(addr))
                .Select(addr => addr.StartsWith("dhcp", StringComparison.OrdinalIgnoreCase) ? "localhost" : addr)
                .Distinct()
                .ToList() ?? [defaultAddress];
            return addresses.Count > 0 ? addresses : new List<string> { defaultAddress };
        }

        static DnsServer4Ray CreateDnsServer(string dnsAddress, HashSet<string> domains, HashSet<string>? expectedIPs = null)
        {
            var (domain, scheme, port, path) = Utils.ParseUrl(dnsAddress);
            var domainFinal = dnsAddress;
            int? portFinal = null;
            if (scheme.IsNullOrEmpty() || scheme.StartsWith("udp", StringComparison.OrdinalIgnoreCase))
            {
                domainFinal = domain;
                portFinal = port > 0 ? port : null;
            }
            else if (scheme.StartsWith("tcp", StringComparison.OrdinalIgnoreCase))
            {
                domainFinal = scheme + "://" + domain;
                portFinal = port > 0 ? port : null;
            }
            var dnsServer = new DnsServer4Ray
            {
                address = domainFinal,
                port = portFinal,
                skipFallback = true,
                domains = domains.Count > 0 ? domains.ToList() : null,
                expectedIPs = expectedIPs?.Count > 0 ? expectedIPs.ToList() : null
            };
            return dnsServer;
        }

        void AddDnsServers(List<string> dnsAddresses, HashSet<string> domains, bool isDirectDns = false, HashSet<string>? expectedIPs = null, bool finalQuery = false, bool skipFallback = true)
        {
            if (domains.Count <= 0)
            {
                return;
            }
            for (var i = 0; i < dnsAddresses.Count; i++)
            {
                var dnsAddress = dnsAddresses[i];
                var dnsServer = CreateDnsServer(dnsAddress, domains, expectedIPs);
                if (isDirectDns)
                {
                    dnsServer.tag = $"{Global.DirectDnsTag}-{directDnsTagIndex++}";
                }
                // PattN: the group's last server ends the query, so that every server of the group is asked in turn
                // and none after them
                if (finalQuery && i == dnsAddresses.Count - 1)
                {
                    dnsServer.finalQuery = true;
                }
                if (!skipFallback)
                {
                    dnsServer.skipFallback = null;
                }
                var dnsServerNode = JsonUtils.SerializeToNode(dnsServer);
                dnsItem.servers.Add(dnsServerNode);
            }
        }
    }

    private void FillDnsHosts(Dns4Ray dnsItem)
    {
        var simpleDNSItem = context.SimpleDnsItem;
        if (simpleDNSItem.AddCommonHosts == false && simpleDNSItem.UseSystemHosts == false && simpleDNSItem.Hosts.IsNullOrEmpty())
        {
            return;
        }
        dnsItem.hosts ??= new Dictionary<string, JsonNode>();
        if (simpleDNSItem.AddCommonHosts == true)
        {
            dnsItem.hosts = Global.PredefinedHosts.ToDictionary(
                kvp => kvp.Key,
                kvp => (JsonNode)JsonUtils.SerializeToArray(kvp.Value)
            );
        }

        if (simpleDNSItem.UseSystemHosts == true)
        {
            var systemHosts = Utils.GetSystemHosts();
            var normalHost = dnsItem.hosts;

            if (normalHost != null && systemHosts?.Count > 0)
            {
                foreach (var host in systemHosts)
                {
                    normalHost.TryAdd(host.Key, JsonUtils.SerializeToArray(new List<string> { host.Value }));
                }
            }
        }

        foreach (var kvp in Utils.ParseHostsToDictionary(simpleDNSItem.Hosts))
        {
            dnsItem.hosts[kvp.Key] = JsonUtils.SerializeToArray(kvp.Value);
        }
    }

    private void GenDnsCustom()
    {
        try
        {
            var item = context.RawDnsItem;
            var customDNS = context.IsTunEnabled ? item?.TunDNS : item?.NormalDNS;
            var domainStrategy4Freedom = item?.DomainStrategy4Freedom;
            if (customDNS.IsNullOrEmpty())
            {
                customDNS = EmbedUtils.GetEmbedText(Global.DNSV2rayNormalFileName);
            }

            //Outbound Freedom domainStrategy
            if (domainStrategy4Freedom.IsNotEmpty())
            {
                var outbound = _coreConfig.outbounds.FirstOrDefault(t => t is { protocol: "freedom", tag: Global.DirectTag });
                if (outbound != null)
                {
                    outbound.streamSettings ??= new();
                    outbound.streamSettings.sockopt ??= new();
                    outbound.streamSettings.sockopt.domainStrategy = domainStrategy4Freedom;
                }
            }

            var node = JsonUtils.ParseJson(customDNS);
            if (node is not JsonObject obj)
            {
                List<string> servers = [];
                var arrDNS = customDNS.Split(',');
                foreach (var str in arrDNS)
                {
                    servers.Add(str);
                }
                obj = new JsonObject { ["servers"] = JsonUtils.SerializeToNode(servers) };
            }

            // Append to dns settings
            if (item.UseSystemHosts)
            {
                var systemHosts = Utils.GetSystemHosts();
                if (systemHosts.Count > 0)
                {
                    var normalHost1 = obj["hosts"];
                    if (normalHost1 != null)
                    {
                        foreach (var host in systemHosts)
                        {
                            if (normalHost1[host.Key] != null)
                            {
                                continue;
                            }

                            normalHost1[host.Key] = host.Value;
                        }
                    }
                }
            }
            var normalHost = obj["hosts"];
            if (normalHost != null)
            {
                foreach (var hostProp in normalHost.AsObject().ToList())
                {
                    if (hostProp.Value is JsonValue value && value.TryGetValue<string>(out var ip))
                    {
                        normalHost[hostProp.Key] = new JsonArray(ip);
                    }
                }
            }

            FillDnsDomainsCustom(obj);

            _coreConfig.dns = obj;
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
        }
    }

    private void FillDnsDomainsCustom(JsonNode dns)
    {
        var servers = dns["servers"];
        if (servers == null)
        {
            return;
        }

        var domainList = context.ProtectDomainList;
        if (domainList.Count <= 0)
        {
            return;
        }

        var dnsItem = context.RawDnsItem;
        var dnsServer = new DnsServer4Ray()
        {
            address = string.IsNullOrEmpty(dnsItem?.DomainDNSAddress) ? Global.DomainPureIPDNSAddress.FirstOrDefault() : dnsItem?.DomainDNSAddress,
            skipFallback = true,
            domains = domainList.Select(d => $"full:{d}").ToList(),
        };
        servers.AsArray().Add(JsonUtils.SerializeToNode(dnsServer));
    }

    private void FillSockoptDomainStrategy(Outbounds4Ray outbound, string? domainStrategy, bool skipHappyEyeballs = false)
    {
        if (domainStrategy.IsNullOrEmpty())
        {
            return;
        }
        outbound.streamSettings ??= new();
        outbound.streamSettings.sockopt ??= new();
        var sockopt = outbound.streamSettings.sockopt;
        sockopt.domainStrategy = domainStrategy;

        if (skipHappyEyeballs || _config.SimpleDNSItem.EnableHappyEyeballs != true)
        {
            return;
        }
        var happyEyeballsItem = _config.HappyEyeballs4RayItem;
        sockopt.happyEyeballs ??= new();
        var happyEyeballs = sockopt.happyEyeballs;
        happyEyeballs.tryDelayMs = happyEyeballsItem.TryDelayMs;
        happyEyeballs.prioritizeIPv6 = happyEyeballsItem.PrioritizeIPv6;
        happyEyeballs.interleave = happyEyeballsItem.Interleave;
        happyEyeballs.maxConcurrentTry = happyEyeballsItem.MaxConcurrentTry;
    }
}
