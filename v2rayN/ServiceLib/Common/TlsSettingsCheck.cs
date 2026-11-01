namespace ServiceLib.Common;

// PattN: fork-only file, PattNG core/TlsSettingsCheck.kt.

/// <summary>
/// PattN: a TLS setting of a profile that the patterniha Xray-core fork would not apply, or with which it would not
/// connect (PattNG TlsSettingsCheck.Error).
/// </summary>
public enum ETlsSettingsError
{
    /// <summary>
    /// cipherSuites with a fingerprint other than unsafe on a profile Xray runs: uTLS then builds the ClientHello, and the
    /// fork passes it no cipher suites. An empty fingerprint is the default one of the settings. sing-box, for which an
    /// empty fingerprint is plain Go TLS that applies the cipher suites, is not asked (X1).
    /// </summary>
    CipherSuitesNeedUnsafe,

    /// <summary>
    /// An alpn other than http/1.1 alone for WebSocket or HTTPUpgrade, whatever the fingerprint. These transports speak
    /// HTTP/1.1 after the handshake whatever it negotiated, and Cloudflare picks h2 whenever it is offered, even after
    /// http/1.1; the unsafe fingerprint offers the alpn as written, the others offer h2,http/1.1 when it is written so;
    /// and some Cloudflare hosts refuse h3 alone. With no alpn they offer http/1.1.
    /// </summary>
    WebsocketAlpnNotHttp1,
}

/// <summary>
/// PattN: TLS settings of a profile that the patterniha Xray-core fork would not apply, or with which it would not
/// connect, so that the server editor, and the WebAPI's, do not save them (PattNG core/TlsSettingsCheck.kt; read from
/// the fork's transport/internet/tls and its WebSocket and HTTPUpgrade dialers). The fork builds the ClientHello with uTLS
/// for every fingerprint but unsafe and passes uTLS no cipher suites, so cipherSuites apply with the unsafe fingerprint
/// alone; that rule is for the profiles Xray runs (X1). The alpn rule is for every core.
/// </summary>
public static class TlsSettingsCheck
{
    /// <summary>The fingerprint with which the fork builds the ClientHello with Go's crypto/tls rather than with uTLS.</summary>
    public const string UnsafeFingerprint = "unsafe";

    /// <summary>The one alpn WebSocket and HTTPUpgrade connect with, and the one the fork offers for them when there is none.</summary>
    private const string Http1 = "http/1.1";

    /// <summary>The fingerprint REALITY falls back on where the profile and the settings name none it can use.</summary>
    private const string RealityFallbackFingerprint = "chrome";

    /// <summary>Whether <paramref name="fingerprint" /> is unsafe, as the fork reads it: lowercased.</summary>
    public static bool IsUnsafe(string? fingerprint)
    {
        return string.Equals(fingerprint, UnsafeFingerprint, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The fingerprint a REALITY profile connects with: <paramref name="fingerprint" />, the profile's, or else
    /// <paramref name="defaultFingerprint" />, the default of the settings, or else Chrome's, passing over unsafe and
    /// none. REALITY needs uTLS: the fork refuses unsafe for it (infra/conf/transport_security.go), and sing-box will not
    /// run it without uTLS (common/tls/reality_client.go).
    /// </summary>
    public static string RealityFingerprint(string? fingerprint, string? defaultFingerprint)
    {
        foreach (var candidate in new[] { fingerprint, defaultFingerprint })
        {
            if (!string.IsNullOrEmpty(candidate) && !IsUnsafe(candidate))
            {
                return candidate;
            }
        }
        return RealityFallbackFingerprint;
    }

    /// <summary>
    /// Whether the check applies to <paramref name="profile" />, which is where PattN's editor shows cipherSuites, alpn and
    /// the fingerprint: under TLS on VMess, VLESS, Shadowsocks, Trojan, SOCKS and HTTP, as for the ECH outbound
    /// (NodeValidator.EchOutboundApplies); PattNG's editor offers TLS on the first four alone. Hysteria2 and MASQUE, whose
    /// editor disables these fields, WireGuard and Aether, which have no TLS settings, and the types sing-box alone runs
    /// are left out.
    /// </summary>
    public static bool AppliesTo(ProfileItem profile)
    {
        return profile.ConfigType is EConfigType.VMess or EConfigType.VLESS or EConfigType.Shadowsocks or EConfigType.Trojan
                   or EConfigType.SOCKS or EConfigType.HTTP
               && profile.StreamSecurity == Global.StreamSecurity;
    }

    /// <summary>
    /// The TLS setting of <paramref name="profile" /> the fork would not apply or would not connect with, cipherSuites
    /// first; null where the check does not apply or there is none. <paramref name="defaultFingerprint" /> stands in for
    /// an empty fingerprint, and <paramref name="core" /> is the core that runs the profile, see
    /// <see cref="CipherSuitesNeedUnsafe" />.
    /// </summary>
    public static ETlsSettingsError? Validate(ProfileItem profile, string? defaultFingerprint, ECoreType core)
    {
        if (!AppliesTo(profile))
        {
            return null;
        }
        if (CipherSuitesNeedUnsafe(profile, defaultFingerprint, core))
        {
            return ETlsSettingsError.CipherSuitesNeedUnsafe;
        }
        if (IsUpgrade(profile) && !IsHttp1OrNone(profile))
        {
            return ETlsSettingsError.WebsocketAlpnNotHttp1;
        }
        return null;
    }

    /// <summary>
    /// Whether <paramref name="profile" />, run by <paramref name="core" />, holds cipherSuites the fork would not apply:
    /// cipherSuites that are not blank, with a fingerprint other than unsafe, which the fork lowercases before it looks it
    /// up. PattN gives Xray <paramref name="defaultFingerprint" />, the default of the settings
    /// (CoreBasicItem.DefFingerprint), in place of an empty fingerprint, where PattNG gives Chrome's; an empty one there as
    /// well is the fork's own, which is not unsafe. False where the check does not apply, and for a core other than Xray
    /// (X1): sing-box builds the ClientHello with Go's crypto/tls for an empty fingerprint and applies the cipher suites.
    /// </summary>
    public static bool CipherSuitesNeedUnsafe(ProfileItem profile, string? defaultFingerprint, ECoreType core)
    {
        if (core != ECoreType.Xray || !AppliesTo(profile) || KotlinText.IsBlank(profile.CipherSuites))
        {
            return false;
        }
        var fingerprint = string.IsNullOrEmpty(profile.Fingerprint) ? defaultFingerprint : profile.Fingerprint;
        return fingerprint?.ToLowerInvariant() != UnsafeFingerprint;
    }

    /// <summary>
    /// Gives an imported <paramref name="profile" /> the alpn its WebSocket or HTTPUpgrade transport connects with, as
    /// shared links often carry h2,http/1.1: http/1.1 in place of any alpn <see cref="Validate" /> refuses for them. No
    /// alpn is kept as it is, since the fork offers http/1.1 for it as well. The profiles of share links, subscriptions
    /// and v2rayN's own lines pass here before they are stored, whatever core runs them.
    /// </summary>
    public static void FixImportedAlpn(ProfileItem profile)
    {
        if (AppliesTo(profile) && IsUpgrade(profile) && !IsHttp1OrNone(profile))
        {
            profile.Alpn = Http1;
        }
    }

    /// <summary>Whether <paramref name="profile" /> runs over WebSocket or HTTPUpgrade, its network read as its outbound reads it.</summary>
    private static bool IsUpgrade(ProfileItem profile)
    {
        return profile.GetNetwork() is nameof(ETransport.ws) or nameof(ETransport.httpupgrade);
    }

    /// <summary>
    /// Whether the alpn of <paramref name="profile" />, read as its outbound offers it (ProfileItem.GetAlpn: split on ',',
    /// empty names skipped, the others as written), is http/1.1 alone or nothing at all.
    /// </summary>
    private static bool IsHttp1OrNone(ProfileItem profile)
    {
        return profile.GetAlpn() is null or [] or [Http1];
    }
}
