namespace ServiceLib.Discovery.Services;

/// <summary>
/// Canonical identity for literal Discovery endpoints. The same physical IP must not occupy
/// multiple candidate/history/pool identities solely because its textual representation differs.
/// </summary>
internal static class DiscoveryEndpointAddress
{
    public static bool TryNormalizeLiteral(string? value, out string normalized)
    {
        var text = (value ?? string.Empty).Trim();
        if (text.Length >= 2 && text[0] == '[' && text[^1] == ']')
        {
            text = text[1..^1];
        }

        if (!IPAddress.TryParse(text, out var address))
        {
            normalized = string.Empty;
            return false;
        }

        normalized = address.ToString();
        return true;
    }

    public static string NormalizeIfLiteral(string? value)
    {
        if (TryNormalizeLiteral(value, out var normalized))
        {
            return normalized;
        }

        var text = (value ?? string.Empty).Trim();
        if (text.Length >= 2 && text[0] == '[' && text[^1] == ']')
        {
            text = text[1..^1];
        }
        return text;
    }
}
