namespace ServiceLib.Handler.Builder;

public record NodeValidatorResult(List<string> Errors, List<string> Warnings)
{
    public bool Success => Errors.Count == 0;

    public static NodeValidatorResult Empty()
    {
        return new NodeValidatorResult([], []);
    }
}

public class NodeValidator
{
    // Static validator rules
    private static readonly HashSet<string> SingboxUnsupportedTransports =
        [nameof(ETransport.kcp), nameof(ETransport.xhttp)];

    private static readonly HashSet<EConfigType> SingboxTransportSupportedProtocols =
        [EConfigType.VMess, EConfigType.VLESS, EConfigType.Trojan, EConfigType.Shadowsocks];

    private static readonly HashSet<string> SingboxShadowsocksAllowedTransports =
        [nameof(ETransport.raw), nameof(ETransport.ws)];

    public static NodeValidatorResult Validate(ProfileItem item, ECoreType coreType)
    {
        var v = new ValidationContext();
        ValidateNodeAndCoreSupport(item, coreType, v);
        return v.ToResult();
    }

    // PattN: the ECH outbound is parsed strictly, because every read of a parsed object that repeats
    // a key throws; comments are allowed, as in the other JSON fields
    private static readonly JsonDocumentOptions EchOutboundDocumentOptions = new()
    {
        CommentHandling = JsonCommentHandling.Skip,
        AllowDuplicateProperties = false,
    };

    /// <summary>
    ///     PattN: the ECH outbound applies where the editor shows it: TLS on the protocols Xray runs,
    ///     apart from WireGuard, which has no TLS settings, and Aether, whose outbound reaches its core on
    ///     the loopback address. Anywhere else it is kept, but neither checked nor used.
    /// </summary>
    public static bool EchOutboundApplies(ProfileItem item)
    {
        return item.StreamSecurity == Global.StreamSecurity
            && item.ConfigType != EConfigType.WireGuard
            && item.ConfigType != EConfigType.Aether
            && Global.XraySupportConfigType.Contains(item.ConfigType);
    }

    /// <summary>
    ///     PattN: the ECH outbound is a whole Xray outbound that the ECH config query is sent through
    ///     (tlsSettings.echSockopt.dialerProxy), so it has to be a JSON object with a tag of its own,
    ///     and it only applies together with EchConfigList.
    /// </summary>
    /// <returns>The error message, or null when the ECH outbound is empty, does not apply, or is valid.</returns>
    public static string? ValidateEchOutbound(ProfileItem item)
    {
        return ValidateEchOutbound(item, out _);
    }

    /// <summary>
    ///     PattN: <see cref="ValidateEchOutbound(ProfileItem)" />, also giving the parsed ECH outbound
    ///     when it is set, applies, and is valid.
    /// </summary>
    public static string? ValidateEchOutbound(ProfileItem item, out JsonObject? echOutbound)
    {
        echOutbound = null;
        if (item.EchOutbound.IsNullOrEmpty() || !EchOutboundApplies(item))
        {
            return null;
        }
        JsonObject? outbound;
        try
        {
            outbound = JsonNode.Parse(item.EchOutbound, nodeOptions: null, EchOutboundDocumentOptions) as JsonObject;
        }
        catch (JsonException)
        {
            outbound = null;
        }
        if (outbound == null)
        {
            return string.Format(ResUI.MsgInvalidProperty, ResUI.TbEchOutbound);
        }
        if (item.EchConfigList.IsNullOrEmpty())
        {
            return ResUI.MsgEchOutboundNeedsEchConfigList;
        }
        // direct and block are the config's own outbounds; balancers pick their members by the
        // "proxy" tag prefix, so an ECH outbound starting with it would carry the proxied traffic
        var tag = GetOutboundTag(outbound);
        if (tag.IsNullOrEmpty()
            || tag is Global.DirectTag or Global.BlockTag
            || tag.StartsWith(Global.ProxyTag, StringComparison.Ordinal))
        {
            return ResUI.MsgEchOutboundInvalidTag;
        }
        echOutbound = outbound;
        return null;
    }

    /// <summary>
    ///     PattN: the tag of an outbound written as JSON, read the way Xray reads it, where the last of
    ///     repeated keys wins. Reading a member of a parsed object that repeats a key would throw.
    /// </summary>
    public static string? GetOutboundTag(JsonObject outbound)
    {
        return JsonSerializer.SerializeToElement(outbound, AppJsonContext.Default.JsonObject).TryGetProperty("tag", out var tag)
            && tag.ValueKind == JsonValueKind.String
                ? tag.GetString()
                : null;
    }

    private static void ValidateNodeAndCoreSupport(ProfileItem item, ECoreType coreType, ValidationContext v)
    {
        if (item.ConfigType is EConfigType.Custom)
        {
            return;
        }

        if (item.ConfigType is EConfigType.Outbound)
        {
            if (item.CoreType != coreType)
            {
                v.Error(string.Format(ResUI.MsgCoreNotSupportProtocol, coreType.ToString(), item.ConfigType));
            }
            return;
        }

        if (item.ConfigType.IsGroupType())
        {
            // Group logic is handled in ValidateGroupNode
            return;
        }

        // PattN: an Aether profile has checks of its own
        if (item.ConfigType is EConfigType.Aether)
        {
            ValidateAether(item, coreType, v);
            return;
        }

        // Basic Property Validation
        v.Assert(!item.Address.IsNullOrEmpty(), string.Format(ResUI.MsgInvalidProperty, ResUI.TbAddress));
        v.Assert(item.Port is > 0 and <= 65535, string.Format(ResUI.MsgInvalidProperty, ResUI.TbPort));

        // Network & Core Logic
        var net = item.GetNetwork();
        if (coreType == ECoreType.sing_box)
        {
            var transportError = ValidateSingboxTransport(item.ConfigType, net);
            if (transportError != null)
            {
                v.Error(transportError);
            }

            if (!Global.SingboxSupportConfigType.Contains(item.ConfigType))
            {
                v.Error(string.Format(ResUI.MsgCoreNotSupportProtocol, nameof(ECoreType.sing_box), item.ConfigType));
            }
        }
        else if (coreType is ECoreType.Xray)
        {
            if (!Global.XraySupportConfigType.Contains(item.ConfigType))
            {
                v.Error(string.Format(ResUI.MsgCoreNotSupportProtocol, nameof(ECoreType.Xray), item.ConfigType));
            }
        }

        // Protocol Specifics
        var protocolExtra = item.GetProtocolExtra();
        switch (item.ConfigType)
        {
            case EConfigType.VMess:
                v.Assert(!item.Password.IsNullOrEmpty() && Utils.IsGuidByParse(item.Password),
                    string.Format(ResUI.MsgInvalidProperty, ResUI.TbId));
                break;

            case EConfigType.VLESS:
                v.Assert(
                    !item.Password.IsNullOrEmpty()
                    && (Utils.IsGuidByParse(item.Password) || item.Password.Length <= 30),
                    string.Format(ResUI.MsgInvalidProperty, ResUI.TbId5)
                );
                v.Assert(Global.Flows.Contains(protocolExtra.Flow ?? string.Empty),
                    string.Format(ResUI.MsgInvalidProperty, ResUI.TbFlow5));
                break;

            case EConfigType.Shadowsocks:
                v.Assert(!item.Password.IsNullOrEmpty(), string.Format(ResUI.MsgInvalidProperty, ResUI.TbId3));
                v.Assert(
                    !string.IsNullOrEmpty(protocolExtra.SsMethod) &&
                    Global.SsSecuritiesInSingbox.Contains(protocolExtra.SsMethod),
                    string.Format(ResUI.MsgInvalidProperty, ResUI.TbSecurity3));
                break;
        }

        if (coreType is ECoreType.Xray
            && (protocolExtra.Flow ?? string.Empty).StartsWith("xtls", StringComparison.OrdinalIgnoreCase)
            && item.MuxEnabled == true)
        {
            v.Warning(string.Format(ResUI.MsgOptionsConflict, "XTLS", "Mux.Cool"));
        }

        if (item.GetNetwork() is nameof(ETransport.ws)
            && item.EchConfigList.IsNullOrEmpty()
            && item.GetAlpn()?.FirstOrDefault() is "h3" or "h2")
        {
            v.Warning(
                $"WebSocket but ALPN is set to {item.Alpn}, the core may ignore the ALPN setting or cause unexpected issues.");
        }

        // TLS & Security
        if (item.StreamSecurity == Global.StreamSecurity)
        {
            var isCertProvided = !item.Cert.IsNullOrEmpty();
            if (!item.Cert.IsNullOrEmpty() && CertPemManager.ParsePemChain(item.Cert).Count == 0)
            {
                v.Error(string.Format(ResUI.MsgInvalidProperty, ResUI.TbFullCertTips));
                isCertProvided = false;
            }

            if ((coreType == ECoreType.Xray
                && item.GetAllowInsecure()
                && !isCertProvided
                && item.CertSha.IsNullOrEmpty())
                || (coreType == ECoreType.sing_box
                    && item.GetAllowInsecure()
                    && !isCertProvided))
            {
                if (coreType == ECoreType.Xray)
                {
                    v.Warning(ResUI.MsgAllowInsecureDeprecated);
                }
                v.Warning(ResUI.MsgInsecureConfiguration);
            }
        }

        if (item.StreamSecurity == Global.StreamSecurityReality)
        {
            v.Assert(!item.PublicKey.IsNullOrEmpty(), string.Format(ResUI.MsgInvalidProperty, ResUI.TbPublicKey));
        }

        var transport = item.GetTransportExtra();
        if (item.Network == nameof(ETransport.xhttp) && !transport.XhttpExtra.IsNullOrEmpty())
        {
            if (JsonUtils.ParseJson(transport.XhttpExtra) is not JsonObject)
            {
                v.Error(string.Format(ResUI.MsgInvalidProperty, ResUI.TransportExtra));
            }
        }

        if (!item.Finalmask.IsNullOrEmpty())
        {
            if (JsonUtils.ParseJson(item.Finalmask) is not JsonObject)
            {
                v.Error(string.Format(ResUI.MsgInvalidProperty, ResUI.TbFinalmask));
            }
        }

        // PattN: the checks made when an ECH outbound is saved, made again for imported profiles
        var echOutboundError = ValidateEchOutbound(item);
        if (echOutboundError != null)
        {
            v.Error(echOutboundError);
        }
    }

    /// <summary>
    ///     PattN: an Aether profile needs no endpoint (PattNG LauncherManager): without a pinned one its core scans,
    ///     and a protocol of two hops names them elsewhere. Its outbound is a SOCKS one to its core on the loopback
    ///     address, so neither the TLS, REALITY nor ECH outbound checks apply to it. Xray alone runs it, once Xray
    ///     can build that outbound (<see cref="Global.XraySupportConfigType" />); sing-box refuses it as any type it
    ///     does not run. Its finalMask is that of its exit-node freedom: blank or a JSON object, as the Aether editor
    ///     of PattNG checks it.
    /// </summary>
    private static void ValidateAether(ProfileItem item, ECoreType coreType, ValidationContext v)
    {
        if (coreType is not ECoreType.Xray || !Global.XraySupportConfigType.Contains(item.ConfigType))
        {
            v.Error(string.Format(ResUI.MsgCoreNotSupportProtocol, coreType.ToString(), item.ConfigType));
        }

        if (!AetherExit.TakesFinalMask(item.Finalmask))
        {
            v.Error(string.Format(ResUI.MsgInvalidProperty, ResUI.TbFinalmask));
        }
    }

    private static string? ValidateSingboxTransport(EConfigType configType, string net)
    {
        // sing-box does not support xhttp / kcp transports
        if (SingboxUnsupportedTransports.Contains(net))
        {
            return string.Format(ResUI.MsgCoreNotSupportNetwork, nameof(ECoreType.sing_box), net);
        }

        // sing-box does not support non-tcp transports for protocols other than vmess/trojan/vless/shadowsocks
        if (!SingboxTransportSupportedProtocols.Contains(configType) && net != nameof(ETransport.raw))
        {
            return string.Format(ResUI.MsgCoreNotSupportProtocolTransport,
                nameof(ECoreType.sing_box), configType.ToString(), net);
        }

        // sing-box shadowsocks only supports tcp/ws/quic transports
        if (configType == EConfigType.Shadowsocks && !SingboxShadowsocksAllowedTransports.Contains(net))
        {
            return string.Format(ResUI.MsgCoreNotSupportProtocolTransport,
                nameof(ECoreType.sing_box), configType.ToString(), net);
        }

        return null;
    }

    private class ValidationContext
    {
        public List<string> Errors { get; } = [];
        public List<string> Warnings { get; } = [];

        public void Error(string message)
        {
            Errors.Add(message);
        }

        public void Warning(string message)
        {
            Warnings.Add(message);
        }

        public void Assert(bool condition, string errorMsg)
        {
            if (!condition)
            {
                Error(errorMsg);
            }
        }

        public NodeValidatorResult ToResult()
        {
            return new NodeValidatorResult(Errors, Warnings);
        }
    }
}
