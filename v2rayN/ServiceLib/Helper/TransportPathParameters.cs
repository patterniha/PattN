namespace ServiceLib.Helper;

/// <summary>
/// Loss-conscious helpers for metadata encoded inside transport paths (for example WebSocket early-data
/// parameters such as ?ed=2048). Unknown query components remain byte-for-byte unchanged.
/// </summary>
public static class TransportPathParameters
{
    /// <summary>
    /// Removes all occurrences of <paramref name="parameterName"/> from the query string while preserving
    /// every unmatched query component, including empty components and their delimiter positions.
    /// Returns the first non-empty decoded value observed for the removed parameter.
    /// </summary>
    public static (string Path, string Value) Extract(string? rawPath, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(parameterName);
        var path = rawPath ?? string.Empty;
        var queryIndex = path.IndexOf('?');
        if (queryIndex < 0)
        {
            return (path, string.Empty);
        }

        var basePath = path[..queryIndex];
        var query = path[(queryIndex + 1)..];
        var kept = new List<string>();
        var value = string.Empty;

        foreach (var part in query.Split('&', StringSplitOptions.None))
        {
            var separator = part.IndexOf('=');
            var rawKey = separator < 0 ? part : part[..separator];
            var rawValue = separator < 0 ? string.Empty : part[(separator + 1)..];
            var key = Decode(rawKey);
            if (key.Equals(parameterName, StringComparison.Ordinal))
            {
                if (value.IsNullOrEmpty())
                {
                    value = Decode(rawValue);
                }
                continue;
            }

            kept.Add(part);
        }

        return (kept.Count == 0 ? basePath : $"{basePath}?{string.Join('&', kept)}", value);
    }

    /// <summary>
    /// Reads the first non-empty decoded value for <paramref name="parameterName"/> without changing the path.
    /// </summary>
    public static string Get(string? rawPath, string parameterName)
        => ExtractWithoutRemoval(rawPath, parameterName);

    /// <summary>
    /// Removes the requested metadata parameters while preserving all unrelated query bytes.
    /// </summary>
    public static string Remove(string? rawPath, params string[] parameterNames)
    {
        var path = rawPath ?? string.Empty;
        foreach (var parameterName in parameterNames.Where(x => !x.IsNullOrEmpty()).Distinct(StringComparer.Ordinal))
        {
            path = Extract(path, parameterName).Path;
        }

        return path;
    }

    /// <summary>
    /// Replaces all occurrences of <paramref name="parameterName"/> with one encoded value while retaining
    /// unrelated query components exactly as configured.
    /// </summary>
    public static string Set(string? rawPath, string parameterName, string value)
    {
        var extracted = Extract(rawPath, parameterName);
        var path = extracted.Path.IsNullOrEmpty() ? "/" : extracted.Path;
        var separator = path.Contains('?')
            ? path.EndsWith('?') || path.EndsWith('&') ? string.Empty : "&"
            : "?";
        return $"{path}{separator}{Uri.EscapeDataString(parameterName)}={Uri.EscapeDataString(value)}";
    }

    private static string ExtractWithoutRemoval(string? rawPath, string parameterName)
    {
        var path = rawPath ?? string.Empty;
        var queryIndex = path.IndexOf('?');
        if (queryIndex < 0)
        {
            return string.Empty;
        }

        foreach (var part in path[(queryIndex + 1)..].Split('&', StringSplitOptions.None))
        {
            var separator = part.IndexOf('=');
            var rawKey = separator < 0 ? part : part[..separator];
            if (!Decode(rawKey).Equals(parameterName, StringComparison.Ordinal))
            {
                continue;
            }

            var rawValue = separator < 0 ? string.Empty : part[(separator + 1)..];
            var decoded = Decode(rawValue);
            if (!decoded.IsNullOrEmpty())
            {
                return decoded;
            }
        }

        return string.Empty;
    }

    private static string Decode(string value)
    {
        try
        {
            return Uri.UnescapeDataString(value);
        }
        catch (UriFormatException)
        {
            return value;
        }
    }
}
