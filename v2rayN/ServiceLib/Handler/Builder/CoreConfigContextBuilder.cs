namespace ServiceLib.Handler.Builder;

public record CoreConfigContextBuilderResult(CoreConfigContext Context, NodeValidatorResult ValidatorResult)
{
    public bool Success => ValidatorResult.Success;
}

/// <summary>
///     Holds the results of a full context build, including the main context and an optional
///     pre-socks context (e.g. for TUN protection or pre-socks chaining).
/// </summary>
public record CoreConfigContextBuilderAllResult(
    CoreConfigContextBuilderResult MainResult,
    CoreConfigContextBuilderResult? PreSocksResult)
{
    /// <summary>True only when both the main result and (if present) the pre-socks result succeeded.</summary>
    public bool Success => MainResult.Success && (PreSocksResult?.Success ?? true);

    /// <summary>
    ///     Merges all errors and warnings from the main result and the optional pre-socks result
    ///     into a single <see cref="NodeValidatorResult" /> for unified notification.
    /// </summary>
    public NodeValidatorResult CombinedValidatorResult => new(
        [.. MainResult.ValidatorResult.Errors, .. PreSocksResult?.ValidatorResult.Errors ?? []],
        [.. MainResult.ValidatorResult.Warnings, .. PreSocksResult?.ValidatorResult.Warnings ?? []]);
}

// PattN: partial; the Aether part is in CoreConfigContextBuilder.Aether.cs
public partial class CoreConfigContextBuilder
{
    /// <summary>
    ///     Builds a <see cref="CoreConfigContext" /> for the given node, resolves its proxy map,
    ///     and processes outbound nodes referenced by routing rules.
    ///     PattN: <paramref name="rulesCarriedBehind" /> when the context is the pre-socks one, in front of a core whose
    ///     routing has the same rules and builds their chains itself (RuleChainShortfallAsync).
    ///     PattN: a routing rule whose target names no profile, a name several have, or a profile that cannot be built
    ///     refuses the context, as the session's, unless <paramref name="refuseRuleTargets" /> is false, as for a latency
    ///     test, which measures the profile alone without the rules: such a rule then goes to the proxy (E2,
    ///     RefusesRuleTarget).
    /// </summary>
    public static async Task<CoreConfigContextBuilderResult> Build(Config config, ProfileItem node, bool rulesCarriedBehind = false,
        bool refuseRuleTargets = true)
    {
        var runCoreType = AppManager.Instance.GetCoreType(node, node.ConfigType);
        var coreType = runCoreType == ECoreType.sing_box ? ECoreType.sing_box : ECoreType.Xray;
        var context = new CoreConfigContext
        {
            Node = node,
            RunCoreType = runCoreType,
            AllProxiesMap = [],
            AppConfig = config,
            FullConfigTemplate = await AppManager.Instance.GetFullConfigTemplateItem(coreType),
            IsTunEnabled = config.TunModeItem.EnableTun,
            SimpleDnsItem = config.SimpleDNSItem,
            ProtectDomainList = [],
            RawDnsItem = await AppManager.Instance.GetDNSItem(coreType),
            RoutingItem = await ConfigHandler.GetDefaultRouting(config),
            IsWindows = Utils.IsWindows(),
            IsMacOS = Utils.IsMacOS(),
            IsLinux = Utils.IsLinux(),
            HasGlobalIPv6Address = Utils.HasGlobalIPv6Address(),
            IsIPv6DisabledByOs = Utils.IsIPv6DisabledByOs(),
            ProtectCoreTypeList = config.TunModeItem.EnableTun ? [ECoreType.Xray, ECoreType.sing_box] : []
        };
        // PattN: what the Aether core and its helpers dial out themselves goes direct under the TUN as well
        if (context.IsTunEnabled)
        {
            context.ProtectCoreTypeList.Add(ECoreType.aether);
        }
        var validatorResult = NodeValidatorResult.Empty();
        var (actNode, nodeValidatorResult) = await ResolveNodeAsync(context, node);
        if (!nodeValidatorResult.Success)
        {
            return new CoreConfigContextBuilderResult(context, nodeValidatorResult);
        }
        context = context with { Node = actNode };
        validatorResult.Warnings.AddRange(nodeValidatorResult.Warnings);
        if (!(context.RoutingItem?.RuleSet.IsNullOrEmpty() ?? true))
        {
            var rules = JsonUtils.Deserialize<List<RulesItem>>(context.RoutingItem?.RuleSet) ?? [];
            // PattN: the targets the context is refused for, each told once (E2)
            var refusedTargets = new HashSet<string>(StringComparer.Ordinal);
            foreach (var ruleItem in rules.Where(ruleItem =>
                         ruleItem.Enabled && !Global.OutboundTags.Contains(ruleItem.OutboundTag)))
            {
                if (ruleItem.OutboundTag.IsNullOrEmpty())
                {
                    validatorResult.Warnings.Add(string.Format(ResUI.MsgRoutingRuleEmptyOutboundTag, ruleItem.Remarks));
                    ruleItem.OutboundTag = Global.ProxyTag;
                    continue;
                }
                // PattN: whether this rule's target refuses the context rather than give way to the proxy (E2)
                var refusesRule = RefusesRuleTarget(node, ruleItem, rulesCarriedBehind, refuseRuleTargets);
                // PattN: found by its name among the profiles a rule can send to, never the first of several (E2); this
                // replaces upstream's GetProfileItemViaRemarks lookup, which takes the first profile of the name
                var ruleTarget = await FindRuleTargetAsync(ruleItem.OutboundTag);
                var ruleOutboundNode = (ruleTarget as ByName<ProfileItem>.One)?.Value;
                if (ruleOutboundNode == null)
                {
                    // PattN: a name no profile has, or several have, refuses the context (E2); where it does not, a name
                    // several have finds none of them, and says so
                    if (refusesRule)
                    {
                        RefuseRuleTarget(validatorResult, refusedTargets, RuleTargetNotFound(ruleTarget, ruleItem.OutboundTag));
                        continue;
                    }
                    if (ruleTarget is ByName<ProfileItem>.Several)
                    {
                        validatorResult.Warnings.Add(string.Format(ResUI.MsgRoutingRuleOutboundNodeError, ruleItem.Remarks,
                            ruleItem.OutboundTag, RuleTargetNotFound(ruleTarget, ruleItem.OutboundTag).Message));
                        ruleItem.OutboundTag = Global.ProxyTag;
                        continue;
                    }
                    validatorResult.Warnings.Add(string.Format(ResUI.MsgRoutingRuleOutboundNodeNotFound,
                        ruleItem.Remarks, ruleItem.OutboundTag));
                    ruleItem.OutboundTag = Global.ProxyTag;
                    continue;
                }

                // PattN: the profile a rule sends to runs inside its subscription's previous/next chain, as the main
                // profile does (PattNG CoreConfigContextBuilder.kt resolveOutbound), where upstream resolves it alone
                // (includeSubChain false). A chain whose subscription names a hop no profile has, or several have (N1), or
                // holding an Aether profile that lacks a hop, is refused for the rule as for the main profile, as any
                // target that cannot be built: the context is refused for it (E2), or, where rule targets do not refuse
                // it, the rule goes to the proxy with the error as a warning.
                // PattN: what resolving it adds to the context is taken back when the rule cannot use it (D1-R4)
                var stateBeforeRule = RuleTargetState.Of(context);
                var (actRuleNode, ruleNodeValidatorResult) = await ResolveNodeAsync(context, ruleOutboundNode, true);
                // PattN: a chain that lost the profile itself, or in front of the core that carries the rule a hop, cannot
                // carry the rule (D1-R1, D1-R2)
                if (ruleNodeValidatorResult.Success
                    && await RuleChainShortfallAsync(ruleOutboundNode, actRuleNode, ruleNodeValidatorResult,
                        rulesCarriedBehind) is { } shortfall)
                {
                    ruleNodeValidatorResult = shortfall;
                }
                validatorResult.Warnings.AddRange(ruleNodeValidatorResult.Warnings.Select(w =>
                    string.Format(ResUI.MsgRoutingRuleOutboundNodeWarning, ruleItem.Remarks, ruleItem.OutboundTag, w)));
                if (!ruleNodeValidatorResult.Success)
                {
                    // PattN: a target that cannot be built refuses the context, with why after it (E2); nothing of it stays
                    if (refusesRule)
                    {
                        RefuseRuleTarget(validatorResult, refusedTargets,
                            RuleTargetUnbuilt(ruleItem.OutboundTag, ruleNodeValidatorResult.Errors));
                        stateBeforeRule.Restore(context);
                        continue;
                    }
                    validatorResult.Warnings.AddRange(ruleNodeValidatorResult.Errors.Select(e =>
                        string.Format(ResUI.MsgRoutingRuleOutboundNodeError, ruleItem.Remarks, ruleItem.OutboundTag,
                            e)));
                    // PattN: (D1-R4)
                    stateBeforeRule.Restore(context);
                    ruleItem.OutboundTag = Global.ProxyTag;
                    continue;
                }
                // PattN: a policy group keeps its strategy inside its subscription's chain (D1-R3)
                KeepRuleGroupStrategy(ruleOutboundNode, actRuleNode);

                context.AllProxiesMap[$"remark:{ruleItem.OutboundTag}"] = actRuleNode;
            }
        }

        if (context.IsTunEnabled && context.AppConfig.TunModeItem.RouteExcludeAddress is { Count: > 0 })
        {
            var appConfig = JsonUtils.DeepCopy(config);
            var routeExcludeAddressList = new List<string>();
            foreach (var addr in context.AppConfig.TunModeItem.RouteExcludeAddress)
            {
                try
                {
                    IPNetwork2.Parse(addr);
                    routeExcludeAddressList.Add(addr);
                }
                catch
                {
                    validatorResult.Warnings.Add(string.Format(ResUI.MsgTunRouteExcludeInvalidAddress, addr));
                }
            }
            appConfig.TunModeItem.RouteExcludeAddress = routeExcludeAddressList;
            context = context with { AppConfig = appConfig };
        }
        if (!context.AppConfig.CoreBasicItem.SendThrough.IsNullOrEmpty()
            && !Utils.IsLocalIP(context.AppConfig.CoreBasicItem.SendThrough))
        {
            validatorResult.Warnings.Add(string.Format(ResUI.MsgInvalidProperty, ResUI.TbSettingsSendThrough));
            var appConfig = JsonUtils.DeepCopy(context.AppConfig);
            appConfig.CoreBasicItem.SendThrough = string.Empty;
            context = context with { AppConfig = appConfig };
        }
        var bindInterface = context.AppConfig.CoreBasicItem.BindInterface?.TrimEx();
        if (bindInterface.IsNotEmpty())
        {
            if (NetworkUtils.IsAutoBindInterface(bindInterface))
            {
                bindInterface = NetworkUtils.GetDefaultPhysicalInterfaceName()?.TrimEx();
            }

            if (bindInterface.IsNullOrEmpty()
                || !Utils.ContainsInterfaceName(bindInterface)
                || !(context.IsTunEnabled || context.IsWindows))
            {
                validatorResult.Warnings.Add(string.Format(ResUI.MsgInvalidProperty, ResUI.TbSettingsBindInterface));
                bindInterface = string.Empty;
            }

            var appConfig = JsonUtils.DeepCopy(context.AppConfig);
            appConfig.CoreBasicItem.BindInterface = bindInterface;
            context = context with { AppConfig = appConfig };
        }

        return new CoreConfigContextBuilderResult(context, validatorResult);
    }

    /// <summary>
    ///     Builds the main <see cref="CoreConfigContext" /> for <paramref name="node" /> and, when
    ///     the main build succeeds, also builds the optional pre-socks context required for TUN
    ///     protection or pre-socks proxy chaining.
    /// </summary>
    public static async Task<CoreConfigContextBuilderAllResult> BuildAll(Config config, ProfileItem node)
    {
        var mainResult = await Build(config, node);
        if (!mainResult.Success)
        {
            return new CoreConfigContextBuilderAllResult(mainResult, null);
        }

        var preResult = await BuildPreSocksIfNeeded(mainResult.Context);
        if (preResult is null)
        {
            return new CoreConfigContextBuilderAllResult(mainResult, null);
        }

        var resolvedMainResult = mainResult with
        {
            Context = mainResult.Context with
            {
                IsTunEnabled = false,
                // main core doesn't handle tun directly when pre-socks is used
                ProtectDomainList = [.. mainResult.Context.ProtectDomainList, .. preResult.Context.ProtectDomainList],
            },
        };
        if (mainResult.Context.IsTunEnabled
            && mainResult.Context.AppConfig.TunModeItem.StrictRoute)
        {
            var appConfig = JsonUtils.DeepCopy(mainResult.Context.AppConfig);
            appConfig.CoreBasicItem.BindInterface = string.Empty;
            appConfig.CoreBasicItem.SendThrough = string.Empty;
            resolvedMainResult = resolvedMainResult with
            {
                Context = resolvedMainResult.Context with
                {
                    AppConfig = appConfig,
                },
            };
        }
        return new CoreConfigContextBuilderAllResult(resolvedMainResult, preResult);
    }

    /// <summary>
    ///     Determines whether a pre-socks context is required for <paramref name="nodeContext" />
    ///     and, if so, builds and returns it. Returns <c>null</c> when no pre-socks core is needed.
    /// </summary>
    private static async Task<CoreConfigContextBuilderResult?> BuildPreSocksIfNeeded(CoreConfigContext nodeContext)
    {
        var config = nodeContext.AppConfig;
        var node = nodeContext.Node;
        var coreType = AppManager.Instance.GetCoreType(node, node.ConfigType);

        var preSocksItem = ConfigHandler.GetPreSocksItem(config, node, coreType);
        if (preSocksItem != null)
        {
            // PattN: in front of a core of PattN's own configuration, which routes the same rules with their whole chains;
            // a custom configuration knows none of them
            var preSocksResult = await Build(nodeContext.AppConfig, preSocksItem, rulesCarriedBehind: node.ConfigType != EConfigType.Custom);

            var protectCoreTypeList = new HashSet<ECoreType>(nodeContext.ProtectCoreTypeList) { nodeContext.RunCoreType };

            return preSocksResult with
            {
                Context = preSocksResult.Context with
                {
                    ProtectDomainList =
                    [.. nodeContext.ProtectDomainList, .. preSocksResult.Context.ProtectDomainList],
                    ProtectCoreTypeList = protectCoreTypeList,
                },
            };
        }

        return null;
    }

    /// <summary>
    ///     Resolves a node into the context, optionally wrapping it in a subscription-level proxy chain.
    ///     Returns the effective (possibly replaced) node and the validation result.
    /// </summary>
    public static async Task<(ProfileItem, NodeValidatorResult)> ResolveNodeAsync(CoreConfigContext context,
        ProfileItem node,
        bool includeSubChain = true)
    {
        if (node.IndexId.IsNullOrEmpty())
        {
            return (node, NodeValidatorResult.Empty());
        }

        if (includeSubChain)
        {
            var (virtualChainNode, chainValidatorResult) = await BuildSubscriptionChainNodeAsync(node);
            // PattN: a subscription chain that names a hop no profile has, or several have, is refused rather than
            // shortened (N1)
            if (!chainValidatorResult.Success)
            {
                return (node, chainValidatorResult);
            }
            if (virtualChainNode != null)
            {
                context.AllProxiesMap[virtualChainNode.IndexId] = virtualChainNode;
                var (resolvedNode, resolvedResult) = await ResolveNodeAsync(context, virtualChainNode, false);
                resolvedResult.Warnings.InsertRange(0, chainValidatorResult.Warnings);
                return (resolvedNode, resolvedResult);
            }
            // Chain not built but warnings may still exist (e.g. missing profiles)
            if (chainValidatorResult.Warnings.Count > 0)
            {
                var fillResult = await RegisterNodeAsync(context, node);
                fillResult.Warnings.InsertRange(0, chainValidatorResult.Warnings);
                return (node, fillResult);
            }
        }

        var registerResult = await RegisterNodeAsync(context, node);
        return (node, registerResult);
    }

    /// <summary>
    ///     If the node's subscription defines prev/next profiles, creates a virtual
    ///     <see cref="EConfigType.ProxyChain" /> node that wraps them together.
    ///     Returns <c>null</c> as the chain item when no chain is needed.
    ///     Any warnings (e.g. missing prev/next profile) are returned in the validator result.
    ///     PattN: a previous or next profile name that no profile has, or several have, is an error that refuses the chain
    ///     (N1), with no chain item.
    /// </summary>
    private static async Task<(ProfileItem? ChainNode, NodeValidatorResult ValidatorResult)>
        BuildSubscriptionChainNodeAsync(ProfileItem node)
    {
        var result = NodeValidatorResult.Empty();

        if (node.Subid.IsNullOrEmpty() || node.ConfigType == EConfigType.Custom)
        {
            return (null, result);
        }

        var subItem = await AppManager.Instance.GetSubItem(node.Subid);
        if (subItem == null)
        {
            return (null, result);
        }

        ProfileItem? prevNode = null;
        ProfileItem? nextNode = null;

        // PattN: found by their names, the spaces around them aside, where upstream takes the first profile of the name and
        // leaves out with a warning one it does not find; a name no profile has, or several have, refuses the chain,
        // whatever the type of the profile it wraps, rather than build it without that hop or through a profile it may
        // not mean (N1, PattNG resolveProxyChainProfilesFromGroup); a custom configuration is no hop, and a blank name
        // names none (CoreConfigContextBuilder.Names.cs)
        prevNode = await FindSubscriptionNeighbourAsync(subItem.PrevProfile, result);
        nextNode = await FindSubscriptionNeighbourAsync(subItem.NextProfile, result);
        if (!result.Success)
        {
            Logging.SaveLog($"Subscription '{subItem.Remarks}': the chain around '{node.Remarks}' is refused: {string.Join("; ", result.Errors)}");
            return (null, result);
        }

        if (prevNode is null && nextNode is null)
        {
            return (null, result);
        }

        // Build new proxy chain node
        var chainNode = new ProfileItem
        {
            IndexId = $"inner-{Utils.GetGuid(false)}",
            ConfigType = EConfigType.ProxyChain,
            CoreType = AppManager.Instance.GetCoreType(node, node.ConfigType),
            Remarks = node.Remarks,
        };
        List<string?> childItems = [prevNode?.IndexId, node.IndexId, nextNode?.IndexId];
        var chainExtraItem = chainNode.GetProtocolExtra() with
        {
            GroupType = chainNode.ConfigType.ToString(),
            ChildItems = string.Join(",", childItems.Where(x => !x.IsNullOrEmpty())),
        };
        chainNode.SetProtocolExtra(chainExtraItem);
        return (chainNode, result);
    }

    /// <summary>
    ///     Dispatches registration to either <see cref="RegisterGroupNodeAsync" /> or
    ///     <see cref="RegisterSingleNodeAsync" /> based on the node's config type.
    /// </summary>
    private static async Task<NodeValidatorResult> RegisterNodeAsync(CoreConfigContext context, ProfileItem node)
    {
        if (node.ConfigType.IsGroupType())
        {
            return await RegisterGroupNodeAsync(context, node);
        }
        return await RegisterSingleNodeAsync(context, node);
    }

    /// <summary>
    ///     Validates a single (non-group) node and, on success, adds it to the proxy map
    ///     and records any domain addresses that should bypass the proxy.
    /// </summary>
    private static async Task<NodeValidatorResult> RegisterSingleNodeAsync(CoreConfigContext context, ProfileItem node)
    {
        if (node.ConfigType.IsGroupType())
        {
            return NodeValidatorResult.Empty();
        }

        var nodeValidatorResult = NodeValidator.Validate(node, context.RunCoreType);

        if (node.ConfigType == EConfigType.Outbound)
        {
            var addressFileName = node.Address;
            if (!File.Exists(addressFileName))
            {
                addressFileName = Utils.GetConfigPath(addressFileName);
            }
            if (!File.Exists(addressFileName))
            {
                nodeValidatorResult.Errors.Add(string.Format(ResUI.MsgCustomOutboundFileNotFound, node.Remarks, addressFileName));
            }
            try
            {
                var fileContent = await File.ReadAllTextAsync(addressFileName);
                context.CustomOutboundContent[node.IndexId] = fileContent;
            }
            catch
            {
                nodeValidatorResult.Errors.Add(string.Format(ResUI.MsgCustomOutboundFileNotFound, node.Remarks, addressFileName));
            }
        }

        var msgs = new List<string>([.. nodeValidatorResult.Errors, .. nodeValidatorResult.Warnings]);
        if (msgs.Count > 0)
        {
            Logging.SaveLog($"{node.Remarks}: {string.Join("; ", msgs)}");
        }
        if (!nodeValidatorResult.Success)
        {
            return nodeValidatorResult;
        }

        context.AllProxiesMap[node.IndexId] = node;

        // PattN: an Aether profile's Address is the WARP endpoint its core dials, no server Xray resolves; the names its
        // core asks Xray for are protected instead, and its exit-node is looked up
        if (node.ConfigType == EConfigType.Aether)
        {
            await RegisterAetherNodeAsync(context, node);
            return nodeValidatorResult;
        }

        var address = node.Address;
        if (Utils.IsDomain(address))
        {
            context.ProtectDomainList.Add(address);
        }

        // ech query server name protect
        if (!node.EchConfigList.IsNullOrEmpty())
        {
            var echQuerySni = node.Sni;
            if (node.StreamSecurity == Global.StreamSecurity
                && node.EchConfigList.Contains("://"))
            {
                var idx = node.EchConfigList.IndexOf('+');
                echQuerySni = idx > 0 ? node.EchConfigList[..idx] : node.Sni;
            }

            if (Utils.IsDomain(echQuerySni))
            {
                context.ProtectDomainList.Add(echQuerySni);
            }
        }

        // PattN: Xray sends the ECH config query to the DNS server after the "+" (the whole value when there
        // is none) and resolves that server's domain itself; in TUN mode it would otherwise resolve through
        // the proxy, whose handshake waits for this query. sing-box never uses that server: it queries the
        // name protected above through its own DNS.
        if (context.RunCoreType != ECoreType.sing_box
            && node.StreamSecurity == Global.StreamSecurity
            && !node.EchConfigList.IsNullOrEmpty()
            && node.EchConfigList.Contains("://"))
        {
            var idx = node.EchConfigList.IndexOf('+');
            var echDnsServer = idx > 0 ? node.EchConfigList[(idx + 1)..] : node.EchConfigList;
            if (Uri.TryCreate(echDnsServer, UriKind.Absolute, out var echDnsUri) && Utils.IsDomain(echDnsUri.IdnHost))
            {
                context.ProtectDomainList.Add(echDnsUri.IdnHost);
            }
        }

        // xhttp downloadSettings address protect
        var xhttpExtra = node.GetTransportExtra().XhttpExtra;
        if (!string.IsNullOrEmpty(xhttpExtra)
            && JsonUtils.ParseJson(xhttpExtra) is JsonObject extra
            && extra.TryGetPropertyValue("downloadSettings", out var dsNode)
            && dsNode is JsonObject downloadSettings
            && downloadSettings.TryGetPropertyValue("address", out var dAddrNode)
            && dAddrNode is JsonValue dAddrValue
            && dAddrValue.TryGetValue(out string? dAddr)
            && !string.IsNullOrEmpty(dAddr)
            && Utils.IsDomain(dAddr))
        {
            context.ProtectDomainList.Add(dAddr);
        }

        // PattN: the servers of the ECH outbound, which the ECH config query is sent through
        if (NodeValidator.ValidateEchOutbound(node, out var echOutbound) == null && echOutbound != null)
        {
            foreach (var echServer in GetOutboundServerAddresses(echOutbound).Where(Utils.IsDomain))
            {
                context.ProtectDomainList.Add(echServer);
            }
        }

        return nodeValidatorResult;
    }

    /// <summary>
    ///     PattN: the servers an outbound written as JSON connects to: the address of each vnext and
    ///     servers entry, the address of the flat settings that newer configs use, and the host of each
    ///     WireGuard peer endpoint.
    /// </summary>
    private static IEnumerable<string> GetOutboundServerAddresses(JsonObject outbound)
    {
        if (outbound["settings"] is not JsonObject settings)
        {
            yield break;
        }
        var servers = new List<JsonObject> { settings };
        foreach (var key in new[] { "vnext", "servers" })
        {
            if (settings[key] is JsonArray entries)
            {
                servers.AddRange(entries.OfType<JsonObject>());
            }
        }
        foreach (var server in servers)
        {
            if (server["address"] is JsonValue address && address.TryGetValue<string>(out var value))
            {
                yield return value;
            }
        }
        if (settings["peers"] is JsonArray peers)
        {
            foreach (var peer in peers.OfType<JsonObject>())
            {
                // host:port, where an IPv6 host is in brackets and so never taken for a domain
                if (peer["endpoint"] is JsonValue endpoint && endpoint.TryGetValue<string>(out var value))
                {
                    var portColon = value.LastIndexOf(':');
                    yield return portColon > 0 ? value[..portColon] : value;
                }
            }
        }
    }

    /// <summary>
    ///     Entry point for registering a group node. Initialises the visited/ancestor sets
    ///     and delegates to <see cref="TraverseGroupNodeAsync" />.
    /// </summary>
    private static async Task<NodeValidatorResult> RegisterGroupNodeAsync(CoreConfigContext context,
        ProfileItem node)
    {
        if (!node.ConfigType.IsGroupType())
        {
            return NodeValidatorResult.Empty();
        }

        HashSet<string> ancestors = [node.IndexId];
        HashSet<string> globalVisited = [node.IndexId];
        return await TraverseGroupNodeAsync(context, node, globalVisited, ancestors);
    }

    /// <summary>
    ///     Recursively walks the children of a group node, registering valid leaf nodes
    ///     and nested groups. Detects cycles via <paramref name="ancestorsGroup" /> and
    ///     deduplicates shared nodes via <paramref name="globalVisitedGroup" />.
    /// </summary>
    private static async Task<NodeValidatorResult> TraverseGroupNodeAsync(
        CoreConfigContext context,
        ProfileItem node,
        HashSet<string> globalVisitedGroup,
        HashSet<string> ancestorsGroup)
    {
        var (groupChildList, _) = await GroupProfileManager.GetChildProfileItems(node);
        List<string> childIndexIdList = [];
        var childNodeValidatorResult = NodeValidatorResult.Empty();
        foreach (var childNode in groupChildList)
        {
            if (ancestorsGroup.Contains(childNode.IndexId))
            {
                childNodeValidatorResult.Errors.Add(
                    string.Format(ResUI.MsgGroupCycleDependency, node.Remarks, childNode.Remarks));
                continue;
            }

            if (globalVisitedGroup.Contains(childNode.IndexId))
            {
                childIndexIdList.Add(childNode.IndexId);
                continue;
            }

            if (!childNode.ConfigType.IsGroupType())
            {
                var childNodeResult = await RegisterSingleNodeAsync(context, childNode);
                childNodeValidatorResult.Warnings.AddRange(childNodeResult.Warnings.Select(w =>
                    string.Format(ResUI.MsgGroupChildNodeWarning, node.Remarks, childNode.Remarks, w)));
                childNodeValidatorResult.Errors.AddRange(childNodeResult.Errors.Select(e =>
                    string.Format(ResUI.MsgGroupChildNodeError, node.Remarks, childNode.Remarks, e)));
                if (!childNodeResult.Success)
                {
                    continue;
                }

                globalVisitedGroup.Add(childNode.IndexId);
                childIndexIdList.Add(childNode.IndexId);
                continue;
            }

            var newAncestorsGroup = new HashSet<string>(ancestorsGroup) { childNode.IndexId };
            var childGroupResult =
                await TraverseGroupNodeAsync(context, childNode, globalVisitedGroup, newAncestorsGroup);
            childNodeValidatorResult.Warnings.AddRange(childGroupResult.Warnings.Select(w =>
                string.Format(ResUI.MsgGroupChildGroupNodeWarning, node.Remarks, childNode.Remarks, w)));
            childNodeValidatorResult.Errors.AddRange(childGroupResult.Errors.Select(e =>
                string.Format(ResUI.MsgGroupChildGroupNodeError, node.Remarks, childNode.Remarks, e)));
            if (!childGroupResult.Success)
            {
                continue;
            }

            globalVisitedGroup.Add(childNode.IndexId);
            childIndexIdList.Add(childNode.IndexId);
        }

        // PattN: one Aether core serves one profile, and a chain holding one is built whole
        if (SettleAetherChildren(context, node, groupChildList, childIndexIdList, childNodeValidatorResult) is { } aetherRefusal)
        {
            childNodeValidatorResult.Errors.Add(aetherRefusal);
            return childNodeValidatorResult;
        }

        if (childIndexIdList.Count == 0)
        {
            childNodeValidatorResult.Errors.Add(string.Format(ResUI.MsgGroupNoValidChildNode, node.Remarks));
            return childNodeValidatorResult;
        }
        childNodeValidatorResult.Warnings.AddRange(childNodeValidatorResult.Errors);
        childNodeValidatorResult.Errors.Clear();

        node.SetProtocolExtra(node.GetProtocolExtra() with { ChildItems = Utils.List2String(childIndexIdList) });
        context.AllProxiesMap[node.IndexId] = node;
        return childNodeValidatorResult;
    }
}
