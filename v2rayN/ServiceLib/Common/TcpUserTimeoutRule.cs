using System.Globalization;

namespace ServiceLib.Common;

// PattN: fork-only file, PattNG core/TcpUserTimeoutRule.kt.

/// <summary>
/// PattN: where the tcpUserTimeout of a profile counts (PattNG TcpUserTimeoutRule). Like the dialMode it goes to the
/// sockopt of the outbound, in milliseconds, and Xray sets it on TCP sockets alone (TCP_USER_TIMEOUT; the fork adds
/// Windows TCP_MAXRTMS and macOS TCP_RXT_CONNDROPTIME), so the editors show it, a configuration writes it and a link
/// carries it only where the connection of the outbound is TCP. Elsewhere a value the profile holds is kept, unused.
/// </summary>
public static class TcpUserTimeoutRule
{
    /// <summary>
    /// Whether the outbound Xray builds for a profile of <paramref name="configType" />, with
    /// <paramref name="network" />, <paramref name="streamSecurity" /> and <paramref name="alpn" /> as the profile or its
    /// editor holds them, connects over TCP: never for WireGuard and Hysteria2, which run over UDP, nor for a type
    /// sing-box alone runs; MASQUE only over HTTP/2 (<see cref="TlsSettingsCheck.MasqueAlpnIsHttp2" />); any other type
    /// unless over mKCP, or over XHTTP or xdrive with TLS and the alpn h3 alone, which the fork then dials over QUIC
    /// (its splithttp and xdrive dialers; REALITY keeps them on HTTP/2). An Aether profile goes by its core instead, see
    /// <see cref="AetherCore.ConnectsOverTcp" />.
    /// </summary>
    public static bool Applies(EConfigType configType, string? network, string? streamSecurity, string? alpn)
    {
        if (configType == EConfigType.MASQUE)
        {
            return TlsSettingsCheck.MasqueAlpnIsHttp2(alpn);
        }
        if (configType is not (EConfigType.VMess or EConfigType.VLESS or EConfigType.Shadowsocks or EConfigType.Trojan
            or EConfigType.SOCKS or EConfigType.HTTP))
        {
            return false;
        }
        var transport = network.IsNullOrEmpty() ? Global.DefaultNetwork : network.TrimEx();
        if (transport == nameof(ETransport.kcp))
        {
            return false;
        }
        if (transport is nameof(ETransport.xhttp) or nameof(ETransport.xdrive))
        {
            return !(streamSecurity == Global.StreamSecurity && AlpnIsHttp3Alone(alpn));
        }
        return true;
    }

    /// <summary>
    /// Whether the tcpUserTimeout of <paramref name="profile" /> counts, see <see cref="Applies" />: for an Aether profile
    /// where its core connects out over TCP, through the exit-node, see <see cref="AetherCore.ConnectsOverTcp" />.
    /// </summary>
    public static bool AppliesTo(ProfileItem profile)
    {
        return profile.ConfigType == EConfigType.Aether
            ? AetherCore.ConnectsOverTcp(profile)
            : Applies(profile.ConfigType, profile.GetNetwork(), profile.StreamSecurity, profile.Alpn);
    }

    /// <summary>
    /// The tcpUserTimeout of <paramref name="profile" /> as its outbound, or the freedom exit-node of its Aether core,
    /// takes it: a whole number of milliseconds above 0 where it counts (<see cref="AppliesTo" />), else null.
    /// </summary>
    public static int? ValueOf(ProfileItem profile)
    {
        return profile.TcpUserTimeout is > 0 && AppliesTo(profile) ? profile.TcpUserTimeout : null;
    }

    /// <summary>
    /// A tcpUserTimeout as a link or the VMess JSON writes it, or a field holds it: a whole number above 0, read as
    /// PattNG's toIntOrNull reads it; null for anything else, a blank included.
    /// </summary>
    public static int? Parse(string? text)
    {
        var trimmed = KotlinText.TrimOrNull(text);
        return int.TryParse(trimmed, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var value) && value > 0
            ? value
            : null;
    }

    /// <summary>The alpn Xray gets, split as the outbound offers it (ProfileItem.GetAlpn), holds h3 and nothing else.</summary>
    private static bool AlpnIsHttp3Alone(string? alpn)
    {
        return Utils.String2List(alpn) is [ "h3" ];
    }
}
