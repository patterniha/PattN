namespace ServiceLib.Reviver.Normalization;

/// <summary>
/// Resolves the logical identity carried by a profile independently of the physical dial endpoint.
/// This distinction is critical for CDN/domain-fronting repairs where Address may be replaced by an IP
/// while TLS SNI and HTTP Host must remain stable.
/// </summary>
public static class ProfileIdentityResolver
{
    public static string ResolveServerName(ProfileItem profile)
    {
        ArgumentNullException.ThrowIfNull(profile);

        if (!profile.Sni.IsNullOrEmpty())
        {
            return profile.Sni.Trim();
        }

        var address = profile.Address?.Trim() ?? string.Empty;
        if (!address.IsNullOrEmpty() && !IPAddress.TryParse(TrimIpv6Brackets(address), out _))
        {
            // When an explicit SNI is absent, Xray-compatible TLS behavior uses the destination domain.
            // Prefer it over Host: Host may represent the origin while Address is the TLS fronting domain.
            return address;
        }

        var host = profile.GetTransportExtra().Host?.Trim();
        if (!host.IsNullOrEmpty())
        {
            return host;
        }

        return TrimIpv6Brackets(address);
    }

    public static string ResolveHttpHost(ProfileItem profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var host = profile.GetTransportExtra().Host?.Trim();
        return !host.IsNullOrEmpty() ? host : ResolveServerName(profile);
    }

    public static bool ServerNameIsCryptographicallyConstrained(ProfileItem profile)
        => profile.StreamSecurity.Equals(Global.StreamSecurityReality, StringComparison.OrdinalIgnoreCase);

    private static string TrimIpv6Brackets(string value)
        => value.Length >= 2 && value[0] == '[' && value[^1] == ']' ? value[1..^1] : value;
}
