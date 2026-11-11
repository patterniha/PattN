namespace ServiceLib.Services.CoreConfig;

public partial class CoreConfigV2rayService
{
    private string ApplyFinalConfigModifiers()
    {
        ApplyOutboundBindInterface();
        ApplyOutboundSendThrough();

        var coreConfigContent = ApplyCustomOutboundReplace();

        return ApplyFullConfigTemplate(coreConfigContent);
    }

    /// <summary>
    ///     PattN: registers the ECH outbound of the profile being built and returns the tag that its
    ///     echSockopt points at. Profiles with the same ECH outbound share it. A different ECH outbound
    ///     under a tag that an earlier one has gets a numbered tag of its own ("ech-2"): the tag only
    ///     links a proxy outbound to its ECH outbound, and a group or a speed test puts unrelated
    ///     profiles in one config.
    /// </summary>
    private string AddEchOutbound(JsonObject echOutbound)
    {
        var same = context.EchOutbounds.FirstOrDefault(item => JsonNode.DeepEquals(item.Outbound, echOutbound));
        if (same != null)
        {
            return same.Tag;
        }
        var tag = NodeValidator.GetOutboundTag(echOutbound) ?? string.Empty;
        var uniqueTag = tag;
        for (var i = 2; context.EchOutbounds.Any(item => item.Tag == uniqueTag); i++)
        {
            uniqueTag = $"{tag}-{i}";
        }
        context.EchOutbounds.Add(new EchOutboundItem(echOutbound, uniqueTag));
        return uniqueTag;
    }

    /// <summary>
    ///     PattN: appends the ECH outbounds of the profiles after every other outbound, exactly as the
    ///     user wrote them rather than through the typed model, which would drop fields it does not know.
    ///     A tag the user wrote that another outbound of the config already has fails the config instead
    ///     of sending the ECH config query through that outbound. A numbered tag ("ech-2") that one has
    ///     moves on to a free number.
    /// </summary>
    /// <returns>The error message, or null on success.</returns>
    private string? AppendEchOutbounds(ref string coreConfigContent)
    {
        if (context.EchOutbounds.Count == 0)
        {
            return null;
        }
        if (JsonUtils.ParseJson(coreConfigContent) is not JsonObject coreConfigNode)
        {
            return ResUI.FailedGenDefaultConfiguration;
        }
        if (coreConfigNode["outbounds"] is not JsonArray outboundsNode)
        {
            outboundsNode = [];
            coreConfigNode["outbounds"] = outboundsNode;
        }

        var usedTags = outboundsNode
            .Select(o => o is JsonObject outbound ? NodeValidator.GetOutboundTag(outbound) : null)
            .OfType<string>()
            .ToHashSet();
        var takenTags = usedTags.Concat(context.EchOutbounds.Select(item => item.Tag)).ToHashSet();
        var renumbered = new Dictionary<string, string>();
        for (var i = 0; i < context.EchOutbounds.Count; i++)
        {
            var item = context.EchOutbounds[i];
            if (!usedTags.Contains(item.Tag))
            {
                continue;
            }
            var tag = NodeValidator.GetOutboundTag(item.Outbound) ?? string.Empty;
            if (item.Tag == tag)
            {
                return string.Format(ResUI.MsgEchOutboundTagConflict, tag);
            }
            var freeTag = item.Tag;
            for (var number = 2; takenTags.Contains(freeTag); number++)
            {
                freeTag = $"{tag}-{number}";
            }
            takenTags.Add(freeTag);
            renumbered[item.Tag] = freeTag;
            context.EchOutbounds[i] = item with { Tag = freeTag };
        }
        if (renumbered.Count > 0)
        {
            RelinkEchSockopts(outboundsNode, renumbered);
        }

        foreach (var item in context.EchOutbounds)
        {
            var echOutbound = item.Outbound.DeepClone().AsObject();
            echOutbound["tag"] = item.Tag;
            // PattN: the ECH queries of the Xray of an Aether scan, key run or latency test leave by the uplink under a TUN (D2)
            BindEchOutboundToUplink(echOutbound);
            outboundsNode.Add((JsonNode)echOutbound);
        }
        coreConfigContent = JsonUtils.Serialize(coreConfigNode);
        return null;
    }

    /// <summary>
    ///     PattN: points the echSockopt of the generated outbounds that use a renumbered ECH tag at its
    ///     new number. Other outbounds keep theirs: the old number is the tag of one of them.
    /// </summary>
    private void RelinkEchSockopts(JsonArray outboundsNode, Dictionary<string, string> renumbered)
    {
        var generatedTags = _coreConfig.outbounds?.Select(o => o.tag).ToHashSet() ?? [];
        foreach (var outbound in outboundsNode.OfType<JsonObject>())
        {
            if (NodeValidator.GetOutboundTag(outbound) is { } outboundTag
                && generatedTags.Contains(outboundTag)
                && outbound["streamSettings"]?["tlsSettings"]?["echSockopt"] is JsonObject echSockopt
                && echSockopt["dialerProxy"] is JsonValue value
                && value.TryGetValue<string>(out var dialerProxy)
                && renumbered.TryGetValue(dialerProxy, out var tag))
            {
                echSockopt["dialerProxy"] = tag;
            }
        }
    }

    private string ApplyCustomOutboundReplace()
    {
        var coreConfigContent = JsonUtils.Serialize(_coreConfig);
        if (context.CustomOutboundMap.Count == 0)
        {
            return coreConfigContent;
        }
        var coreConfigNode = JsonNode.Parse(coreConfigContent) as JsonObject;
        var coreConfigOutboundsNode = coreConfigNode?["outbounds"] as JsonArray ?? [];

        foreach (var outbound in _coreConfig.outbounds ?? [])
        {
            if (!context.CustomOutboundMap.TryGetValue(outbound, out var customOutboundIndex))
            {
                continue;
            }
            var outboundTag = outbound.tag;
            var outboundDetour = outbound.streamSettings?.sockopt?.dialerProxy ?? string.Empty;
            var outboundBindInterface = outbound.streamSettings?.sockopt?.Interface ?? string.Empty;
            var customOutboundContent = context.CustomOutboundContent[customOutboundIndex];
            var containTagPlaceholder = customOutboundContent.Contains("{{tag}}");
            var containDetourPlaceholder = customOutboundContent.Contains("{{detour}}");
            var containBindInterfacePlaceholder = customOutboundContent.Contains("{{interface}}");
            customOutboundContent = customOutboundContent.Replace("{{tag}}", outboundTag);
            customOutboundContent = customOutboundContent.Replace("{{detour}}", outboundDetour);
            customOutboundContent = customOutboundContent.Replace("{{interface}}", outboundBindInterface);
            var customOutboundObj = JsonUtils.ParseJson(customOutboundContent) as JsonObject;
            // PattN: the exit-node passes every name the Aether core sends on as it is, whatever its file sets (V2rayAetherService.cs)
            if (outboundTag == Global.AetherExitNodeTag)
            {
                customOutboundObj?.Remove("targetStrategy");
            }

            if (!containTagPlaceholder)
            {
                customOutboundObj?["tag"] = outboundTag;
            }
            if (!containDetourPlaceholder && !outboundDetour.IsNullOrEmpty())
            {
                customOutboundObj!["streamSettings"] ??= new JsonObject();
                customOutboundObj["streamSettings"]["sockopt"] ??= new JsonObject();
                customOutboundObj["streamSettings"]["sockopt"]["dialerProxy"] = outboundDetour;
                if (customOutboundObj["streamSettings"]?["xhttpSettings"]?["extra"]?["downloadSettings"] is JsonObject downloadSettings)
                {
                    downloadSettings["sockopt"] ??= new JsonObject();
                    downloadSettings["sockopt"]["dialerProxy"] = outboundDetour;
                }
            }
            else if (outboundDetour.IsNullOrEmpty())
            {
                (customOutboundObj?["streamSettings"]?["sockopt"] as JsonObject)?.Remove("dialerProxy");
            }
            // PattN: the uplink binds the outbound by what its own JSON says, not by its stand-in, and never over an
            // interface it names; and its ECH config query too (D2-1, D2-2)
            if (UplinkBinding is { } uplink && customOutboundObj != null)
            {
                if (!containBindInterfacePlaceholder && outboundBindInterface == uplink)
                {
                    BindCustomOutboundToUplink(customOutboundObj, outboundTag);
                    outboundBindInterface = string.Empty;
                }
                BindEchQueryToUplink(customOutboundObj);
            }
            if (!containBindInterfacePlaceholder && !outboundBindInterface.IsNullOrEmpty())
            {
                customOutboundObj!["streamSettings"] ??= new JsonObject();
                customOutboundObj["streamSettings"]["sockopt"] ??= new JsonObject();
                customOutboundObj["streamSettings"]["sockopt"]["interface"] = outboundBindInterface;
                if (customOutboundObj["streamSettings"]?["xhttpSettings"]?["extra"]?["downloadSettings"] is JsonObject downloadSettings)
                {
                    downloadSettings["sockopt"] ??= new JsonObject();
                    downloadSettings["sockopt"]["interface"] = outboundBindInterface;
                }
            }

            var index = coreConfigOutboundsNode
                .Select((node, idx) => new { node, idx })
                .FirstOrDefault(x => x.node?["tag"]?.ToString() == outboundTag)?.idx ?? -1;
            if (index != -1)
            {
                coreConfigOutboundsNode[index] = customOutboundObj;
            }
        }

        return JsonUtils.Serialize(coreConfigNode);
    }

    private string ApplyFullConfigTemplate(string coreConfigContent)
    {
        var fullConfigTemplate = context.FullConfigTemplate;
        if (fullConfigTemplate is not { Enabled: true })
        {
            return coreConfigContent;
        }

        var fullConfigTemplateItem = context.IsTunEnabled ? fullConfigTemplate.TunConfig : fullConfigTemplate.Config;
        if (fullConfigTemplateItem.IsNullOrEmpty())
        {
            return coreConfigContent;
        }

        var fullConfigTemplateNode = JsonNode.Parse(fullConfigTemplateItem);
        if (fullConfigTemplateNode == null)
        {
            return coreConfigContent;
        }
        // PattN: the template's inbounds and routing take the place of the generated ones, so the Aether core's inbound
        // and its rule go into them (V2rayAetherService.cs)
        ApplyAetherToTemplate(fullConfigTemplateNode);

        // Handle balancer and rules modifications (for multiple load scenarios)
        if (_coreConfig.routing?.balancers?.Count > 0)
        {
            var balancer =
                _coreConfig.routing.balancers.FirstOrDefault(b => b.tag == Global.ProxyTag + Global.BalancerTagSuffix, null);

            // Modify existing rules in custom config
            if (balancer != null)
            {
                var rulesNode = fullConfigTemplateNode["routing"]?["rules"];
                if (rulesNode != null)
                {
                    foreach (var rule in rulesNode.AsArray())
                    {
                        if (rule["outboundTag"]?.GetValue<string>() == Global.ProxyTag)
                        {
                            rule.AsObject().Remove("outboundTag");
                            rule["balancerTag"] = balancer.tag;
                        }
                    }
                }
            }

            // Ensure routing node exists
            fullConfigTemplateNode["routing"] ??= new JsonObject();

            // Handle balancers - append instead of override
            if (fullConfigTemplateNode["routing"]["balancers"] is JsonArray customBalancersNode)
            {
                if (JsonNode.Parse(JsonUtils.Serialize(_coreConfig.routing.balancers)) is JsonArray newBalancers)
                {
                    foreach (var balancerNode in newBalancers)
                    {
                        customBalancersNode.Add(balancerNode?.DeepClone());
                    }
                }
            }
            else
            {
                fullConfigTemplateNode["routing"]["balancers"] = JsonNode.Parse(JsonUtils.Serialize(_coreConfig.routing.balancers));
            }
        }

        if (_coreConfig.observatory != null)
        {
            if (fullConfigTemplateNode["observatory"] == null)
            {
                fullConfigTemplateNode["observatory"] = JsonNode.Parse(JsonUtils.Serialize(_coreConfig.observatory));
            }
            else
            {
                var subjectSelector = _coreConfig.observatory.subjectSelector;
                subjectSelector?.AddRange(fullConfigTemplateNode["observatory"]?["subjectSelector"]?.AsArray()?.Select(x => x?.GetValue<string>()) ?? []);
                fullConfigTemplateNode["observatory"]?["subjectSelector"] = JsonNode.Parse(JsonUtils.Serialize(subjectSelector?.Distinct().ToList()));
            }
        }

        if (_coreConfig.burstObservatory != null)
        {
            if (fullConfigTemplateNode["burstObservatory"] == null)
            {
                fullConfigTemplateNode["burstObservatory"] = JsonNode.Parse(JsonUtils.Serialize(_coreConfig.burstObservatory));
            }
            else
            {
                var subjectSelector = _coreConfig.burstObservatory.subjectSelector;
                subjectSelector?.AddRange(fullConfigTemplateNode["burstObservatory"]?["subjectSelector"]?.AsArray()?.Select(x => x?.GetValue<string>()) ?? []);
                fullConfigTemplateNode["burstObservatory"]?["subjectSelector"] = JsonNode.Parse(JsonUtils.Serialize(subjectSelector?.Distinct().ToList()));
            }
        }

        // Keep the generated policy (levels etc.) unless the template defines its own
        if (_coreConfig.policy != null && fullConfigTemplateNode["policy"] == null)
        {
            fullConfigTemplateNode["policy"] = JsonNode.Parse(JsonUtils.Serialize(_coreConfig.policy));
        }

        var customOutboundsNode = new JsonArray();
        // PattN: the outbounds to the Aether core, which it reaches on the loopback address
        var aetherOutboundTags = AetherOutboundTags();

        var coreConfigNode = JsonNode.Parse(coreConfigContent);
        var coreConfigOutboundsNode = coreConfigNode?["outbounds"] as JsonArray ?? [];
        foreach (var outbound in coreConfigOutboundsNode)
        {
            if (outbound?["protocol"]?.ToString()?.ToLower() is "blackhole" or "dns" or "freedom")
            {
                if (fullConfigTemplate.AddProxyOnly == true
                    // PattN: the exit-node the Aether core dials out by stays, a freedom one too
                    && outbound?["tag"]?.ToString() != Global.AetherExitNodeTag)
                {
                    continue;
                }
                // PattN: a freedom exit-node carries the Aether core's own connection to its server, which goes through
                // the detour as every proxy's does
                if (outbound?["tag"]?.ToString() == Global.AetherExitNodeTag && !fullConfigTemplate.ProxyDetour.IsNullOrEmpty()
                    && (outbound["streamSettings"]?["sockopt"]?["dialerProxy"]?.ToString().IsNullOrEmpty() ?? true))
                {
                    outbound["streamSettings"] ??= new JsonObject();
                    outbound["streamSettings"]["sockopt"] ??= new JsonObject();
                    outbound["streamSettings"]["sockopt"]["dialerProxy"] = fullConfigTemplate.ProxyDetour;
                }
            }
            else if (!fullConfigTemplate.ProxyDetour.IsNullOrEmpty()
                && (outbound["streamSettings"]?["sockopt"]?["dialerProxy"].ToString().IsNullOrEmpty() ?? true)
                // PattN: an Aether outbound dials its core on the loopback address, never through the detour
                && !aetherOutboundTags.Contains(outbound["tag"]?.ToString() ?? string.Empty))
            {
                var outboundAddress = outbound["settings"]?["servers"]?.AsArray()?.FirstOrDefault()?["address"]?.ToString()
                    ?? outbound["settings"]?["vnext"]?.AsArray()?.FirstOrDefault()?["address"]?.ToString()
                    ?? string.Empty;
                if (!Utils.IsPrivateNetwork(outboundAddress))
                {
                    //FillDialerProxy(outbound, fullConfigTemplate.ProxyDetour);
                    outbound["streamSettings"] ??= new JsonObject();
                    outbound["streamSettings"]["sockopt"] ??= new JsonObject();
                    outbound["streamSettings"]["sockopt"]["dialerProxy"] = fullConfigTemplate.ProxyDetour;
                    if (outbound["streamSettings"]?["xhttpSettings"]?["extra"]?["downloadSettings"] is JsonObject downloadSettings)
                    {
                        downloadSettings["sockopt"] ??= new JsonObject();
                        downloadSettings["sockopt"]["dialerProxy"] = fullConfigTemplate.ProxyDetour;
                    }
                }
            }
            customOutboundsNode.Add(JsonUtils.DeepCopy(outbound));
        }

        if (fullConfigTemplateNode["outbounds"] is JsonArray templateOutbounds)
        {
            foreach (var outbound in templateOutbounds)
            {
                customOutboundsNode.Add(outbound?.DeepClone());
            }
        }

        fullConfigTemplateNode["outbounds"] = customOutboundsNode;

        // PattN: the command line of the Aether core first, as without a template
        return JsonUtils.Serialize(WithAetherCommandFirst(fullConfigTemplateNode));
    }

    private void ApplyOutboundBindInterface()
    {
        var bindInterface = NetworkUtils.GetRealBindInterfaceName(_config.CoreBasicItem.BindInterface);
        // PattN: with none set, the Xray of an Aether scan, key run or latency test binds to the uplink under a TUN (D2)
        if (bindInterface.IsNullOrEmpty())
        {
            bindInterface = context.Aether.Uplink;
        }
        if (bindInterface.IsNullOrEmpty())
        {
            return;
        }
        // PattN: what the uplink binds besides: the names its outbounds dial, and their ECH config queries (D2-1, D2-3)
        var uplink = UplinkBinding;
        foreach (var outbound in _coreConfig.outbounds ?? [])
        {
            if (!ShouldBindNet(outbound))
            {
                continue;
            }
            // PattN: no interface but the loopback one reaches a WireGuard peer there (D2-2)
            if (uplink != null && PeerReachesLoopback(outbound))
            {
                continue;
            }
            outbound.streamSettings ??= new();
            outbound.streamSettings.sockopt ??= new();
            outbound.streamSettings.sockopt.Interface = bindInterface;
            // PattN: a custom outbound's own JSON decides (ApplyCustomOutboundReplace)
            if (uplink != null && !context.CustomOutboundMap.ContainsKey(outbound))
            {
                LookUpServerByUplink(outbound);
            }
            // xhttp download bind interface
            if (outbound?.streamSettings?.xhttpSettings?.extra is null)
            {
                continue;
            }
            var xhttpExtra = JsonUtils.ParseJson(JsonUtils.Serialize(outbound.streamSettings.xhttpSettings!.extra));
            if (xhttpExtra is not JsonObject xhttpExtraObject
                || xhttpExtraObject["downloadSettings"] is not JsonObject downloadSettings)
            {
                continue;
            }
            var sockopt = downloadSettings["sockopt"] as JsonObject ?? new JsonObject();
            sockopt["interface"] = bindInterface;
            downloadSettings["sockopt"] = sockopt;
            // PattN: (D2-3)
            if (uplink != null)
            {
                BindDownloadToUplink(downloadSettings, Utils.IsDomain(outbound.settings?.address?.ToString()));
            }
            outbound.streamSettings.xhttpSettings.extra = xhttpExtraObject;
        }
        // PattN: (D2-1)
        BindEchQueriesToUplink();
    }

    private void ApplyOutboundSendThrough()
    {
        var sendThrough = _config.CoreBasicItem.SendThrough?.TrimEx();
        if (sendThrough.IsNullOrEmpty())
        {
            return;
        }

        foreach (var outbound in _coreConfig.outbounds ?? [])
        {
            outbound.sendThrough = ShouldBindNet(outbound) ? sendThrough : null;
        }
    }

    private static bool ShouldBindNet(Outbounds4Ray outbound)
    {
        if (outbound.protocol is "freedom" or "blackhole" or "dns" or "loopback"
            // PattN: a freedom exit-node carries the Aether core's own connection to its server, as a proxy's outbound does
            && outbound.tag != Global.AetherExitNodeTag)
        {
            return false;
        }

        if (outbound.streamSettings?.sockopt?.dialerProxy.IsNullOrEmpty() == false)
        {
            return false;
        }

        var outboundAddress = outbound.settings?.address?.ToString()
                              ?? outbound.settings?.peers?.FirstOrDefault()?.endpoint
                              ?? string.Empty;

        if (outboundAddress.Equals("localhost", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return !IPAddress.TryParse(outboundAddress, out var address) || !IPAddress.IsLoopback(address);
    }
}
