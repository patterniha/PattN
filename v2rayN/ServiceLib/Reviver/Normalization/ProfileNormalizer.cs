namespace ServiceLib.Reviver.Normalization;

/// <summary>
/// Loss-minimizing canonicalizer. It only applies transformations that are representation-equivalent;
/// it must not guess alternate server-side protocol parameters.
/// </summary>
public sealed class ProfileNormalizer
{
    public ProfileItem Normalize(ProfileItem source)
    {
        ArgumentNullException.ThrowIfNull(source);
        var profile = JsonUtils.DeepCopy(source)
            ?? throw new InvalidOperationException("Could not clone profile for normalization.");

        profile.Address = NormalizeAddress(profile.Address);
        profile.Sni = profile.Sni?.Trim() ?? string.Empty;
        profile.Network = profile.Network?.Trim().ToLowerInvariant() ?? string.Empty;
        profile.StreamSecurity = profile.StreamSecurity?.Trim().ToLowerInvariant() ?? string.Empty;
        profile.Fingerprint = profile.Fingerprint?.Trim() ?? string.Empty;
        profile.Alpn = profile.Alpn?.Trim() ?? string.Empty;

        var transport = profile.GetTransportExtra();
        profile.SetTransportExtra(transport with
        {
            Host = transport.Host?.Trim(),
            Path = NormalizePath(transport.Path),
            GrpcAuthority = transport.GrpcAuthority?.Trim(),
            GrpcServiceName = transport.GrpcServiceName?.Trim(),
            XhttpMode = transport.XhttpMode?.Trim().ToLowerInvariant(),
        });

        return profile;
    }

    private static string NormalizeAddress(string? address)
    {
        var value = address?.Trim() ?? string.Empty;
        // ProfileItem stores an IPv6 host without URI brackets; URI formatters add brackets when needed.
        if (value.Length >= 2 && value[0] == '[' && value[^1] == ']')
        {
            value = value[1..^1];
        }
        return value;
    }

    private static string? NormalizePath(string? path)
    {
        if (path is null)
        {
            return null;
        }
        return path.Trim();
    }
}
