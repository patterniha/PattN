namespace ServiceLib.Reviver.Normalization;

/// <summary>
/// Conservative compatibility view derived from PattN's own outbound generators. It deliberately exposes only
/// Xray and sing-box for automatic fallback; other cores remain explicit user/runtime choices until equivalent
/// structured generators and validation coverage exist.
/// </summary>
public sealed class ProfileCoreCompatibility
{
    private static readonly HashSet<EConfigType> XrayTypes =
    [
        EConfigType.VMess, EConfigType.Shadowsocks, EConfigType.SOCKS, EConfigType.HTTP,
        EConfigType.VLESS, EConfigType.Trojan, EConfigType.Hysteria2, EConfigType.WireGuard,
    ];

    private static readonly HashSet<EConfigType> SingBoxTypes =
    [
        EConfigType.VMess, EConfigType.Shadowsocks, EConfigType.SOCKS, EConfigType.HTTP,
        EConfigType.VLESS, EConfigType.Trojan, EConfigType.Hysteria2, EConfigType.WireGuard,
        EConfigType.TUIC, EConfigType.Anytls, EConfigType.Naive,
    ];

    public bool Supports(ProfileItem profile, ECoreType coreType)
    {
        ArgumentNullException.ThrowIfNull(profile);
        if (profile.IsComplex() || profile.ConfigType is EConfigType.Custom or EConfigType.Outbound)
        {
            return false;
        }

        return coreType switch
        {
            ECoreType.Xray => XrayTypes.Contains(profile.ConfigType),
            ECoreType.sing_box => SingBoxTypes.Contains(profile.ConfigType)
                && !string.Equals(profile.GetNetwork(), nameof(ETransport.kcp), StringComparison.OrdinalIgnoreCase)
                && !string.Equals(profile.GetNetwork(), nameof(ETransport.xhttp), StringComparison.OrdinalIgnoreCase),
            _ => false,
        };
    }

    public IReadOnlyList<ECoreType> Alternatives(ProfileItem profile, ECoreType current)
        => new[] { ECoreType.Xray, ECoreType.sing_box }
            .Where(core => core != current && Supports(profile, core))
            .ToArray();
}
