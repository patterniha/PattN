namespace ServiceLib.Reviver.Normalization;

public sealed record ProfileInvariantViolation(string Code, string Message);

/// <summary>
/// Cross-cutting invariants Reviver must satisfy before attempting a runtime validation.
/// This intentionally starts conservative and grows from PattN's core generators and regression corpus.
/// </summary>
public sealed class ProfileInvariantRegistry
{
    public IReadOnlyList<ProfileInvariantViolation> Validate(ProfileItem profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var violations = new List<ProfileInvariantViolation>();

        if (!profile.IsComplex() && profile.ConfigType != EConfigType.Outbound)
        {
            if (profile.Address.IsNullOrEmpty())
            {
                violations.Add(new("endpoint.address.empty", "The profile has no endpoint address."));
            }
            if (profile.Port is <= 0 or >= 65536)
            {
                violations.Add(new("endpoint.port.invalid", "The profile endpoint port is outside 1..65535."));
            }
        }

        if (!profile.Network.IsNullOrEmpty() && !Global.Networks.Contains(profile.Network))
        {
            violations.Add(new("transport.network.unknown", $"Unknown transport network '{profile.Network}'."));
        }

        if (!profile.TargetStrategy.IsNullOrEmpty()
            && !Global.TargetStrategies.Contains(profile.TargetStrategy))
        {
            violations.Add(new("dns.targetStrategy.unknown", $"Unknown Xray targetStrategy '{profile.TargetStrategy}'."));
        }

        if (profile.StreamSecurity == Global.StreamSecurityReality)
        {
            if (profile.ConfigType is not (EConfigType.VLESS or EConfigType.Trojan))
            {
                violations.Add(new("reality.protocol.invalid", "Reality is only valid for supported VLESS/Trojan profiles."));
            }
            if (profile.PublicKey.IsNullOrEmpty())
            {
                violations.Add(new("reality.publicKey.empty", "Reality requires a public key."));
            }
        }

        ValidateTransportExtras(profile, violations);
        return violations;
    }

    private static void ValidateTransportExtras(ProfileItem profile, List<ProfileInvariantViolation> violations)
    {
        var transport = profile.GetTransportExtra();
        if (profile.Network == nameof(ETransport.ws))
        {
            var earlyData = TransportPathParameters.Get(transport.Path, "ed");
            if (earlyData.IsNotEmpty() && (!int.TryParse(earlyData, out var parsed) || parsed < 0))
            {
                violations.Add(new("ws.earlyData.invalid", "WebSocket ed metadata must be a non-negative integer."));
            }
        }

        if (profile.Network != nameof(ETransport.xhttp) || transport.XhttpExtra.IsNullOrEmpty())
        {
            return;
        }
        if (JsonUtils.ParseJson(transport.XhttpExtra) is not JsonObject extra)
        {
            violations.Add(new("xhttp.extra.invalidJson", "XHTTP extra must be a JSON object."));
            return;
        }

        ValidateRange(extra, "xPaddingBytes", violations, allowZeroLower: false, allowZeroUpper: false);
        ValidateRange(extra, "uplinkChunkSize", violations, allowZeroLower: true, allowZeroUpper: true);
        ValidateRange(extra, "scMaxEachPostBytes", violations, allowZeroLower: false, allowZeroUpper: false);
        ValidateRange(extra, "scMinPostsIntervalMs", violations, allowZeroLower: true, allowZeroUpper: false);
        ValidateRange(extra, "sessionIDLength", violations, allowZeroLower: false, allowZeroUpper: false);

        if (extra["xmux"] is JsonObject xmux)
        {
            foreach (var name in new[] { "maxConnections", "maxConcurrency", "cMaxReuseTimes", "hMaxRequestTimes", "hMaxReusableSecs" })
            {
                ValidateRange(xmux, name, violations, allowZeroLower: true, allowZeroUpper: true, codePrefix: "xhttp.xmux");
            }
            if (xmux["hKeepAlivePeriod"] is { } keepAlive
                && !XhttpValueNormalizer.TryNormalizeInteger(keepAlive.ToString(), out _))
            {
                violations.Add(new("xhttp.xmux.hKeepAlivePeriod.invalid", "XHTTP xmux hKeepAlivePeriod must be an integer."));
            }
        }
        else if (extra.ContainsKey("xmux") && extra["xmux"] is not null)
        {
            violations.Add(new("xhttp.xmux.invalid", "XHTTP xmux must be a JSON object."));
        }
    }

    private static void ValidateRange(
        JsonObject owner,
        string field,
        List<ProfileInvariantViolation> violations,
        bool allowZeroLower,
        bool allowZeroUpper,
        string codePrefix = "xhttp")
    {
        if (owner[field] is not { } value)
        {
            return;
        }
        if (!XhttpValueNormalizer.TryNormalizeRange(value.ToString(), out _, allowZeroLower, allowZeroUpper))
        {
            violations.Add(new($"{codePrefix}.{field}.invalid", $"XHTTP {field} has an invalid integer/range value."));
        }
    }

}
