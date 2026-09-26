using System.Globalization;

namespace ServiceLib.Helper;

/// <summary>
/// Loss-free validation/normalization helpers for XHTTP integer/range fields. The grammar mirrors the modern
/// Xray/Mihomo subscription behavior used by Sub-Store: optional positive signs and leading zeroes are accepted,
/// internal whitespace is compacted, and descending/non-integer ranges are rejected.
/// </summary>
public static class XhttpValueNormalizer
{
    public static bool TryNormalizeRange(
        string? value,
        out string normalized,
        bool allowZeroLowerBound = true,
        bool allowZeroUpperBound = true)
    {
        normalized = string.Empty;
        if (value is null)
        {
            return false;
        }

        var parts = value.Trim().Split('-');
        if (parts.Length is < 1 or > 2 || !TryUnsigned(parts[0], out var lower))
        {
            return false;
        }
        var upper = lower;
        if (parts.Length == 2 && !TryUnsigned(parts[1], out upper))
        {
            return false;
        }
        if ((!allowZeroLowerBound && lower == 0)
            || (!allowZeroUpperBound && upper == 0)
            || upper < lower)
        {
            return false;
        }

        normalized = lower == upper
            ? lower.ToString(CultureInfo.InvariantCulture)
            : $"{lower.ToString(CultureInfo.InvariantCulture)}-{upper.ToString(CultureInfo.InvariantCulture)}";
        return true;
    }

    public static bool TryNormalizeInteger(string? value, out long normalized, bool allowNegative = true)
    {
        normalized = default;
        var text = value?.Trim();
        if (text.IsNullOrEmpty())
        {
            return false;
        }
        if (!allowNegative && text!.StartsWith("-", StringComparison.Ordinal))
        {
            return false;
        }
        if (text![0] == '+')
        {
            text = text[1..];
        }
        if (text.IsNullOrEmpty() || (text[0] == '-' ? text.Length == 1 || !text[1..].All(char.IsDigit) : !text.All(char.IsDigit)))
        {
            return false;
        }
        return long.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out normalized);
    }

    private static bool TryUnsigned(string token, out long value)
    {
        value = default;
        var text = token.Trim();
        if (text.StartsWith("+", StringComparison.Ordinal))
        {
            text = text[1..];
        }
        return text.Length > 0
               && text.All(char.IsDigit)
               && long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value);
    }
}
