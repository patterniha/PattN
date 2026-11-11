namespace ServiceLib.Common;

public static class FakeIPUtils
{
    public static bool TryParseIPv6Range(string? value, out string range, out long poolSize)
    {
        return TryParseRange(value, Global.FakeIPv6Ranges.First(), AddressFamily.InterNetworkV6, out range, out poolSize);
    }

    // PattN: the IPv4 range by the same rule as the IPv6 one
    public static bool TryParseIPv4Range(string? value, out string range, out long poolSize)
    {
        return TryParseRange(value, Global.FakeIPRanges.First(), AddressFamily.InterNetwork, out range, out poolSize);
    }

    private static bool TryParseRange(string? value, string defaultRange, AddressFamily family, out string range, out long poolSize)
    {
        range = string.IsNullOrWhiteSpace(value) ? defaultRange : value.Trim();
        poolSize = 65535;
        var addressBits = family == AddressFamily.InterNetwork ? 32 : 128;
        if (!System.Net.IPNetwork.TryParse(range, out var network)
            || network.BaseAddress.AddressFamily != family
            || network.PrefixLength == addressBits)
        {
            return false;
        }

        range = network.ToString();
        var hostBits = addressBits - network.PrefixLength;
        if (hostBits < 16)
        {
            // Xray requires the mapping capacity to be smaller than the address pool.
            poolSize = (1L << hostBits) - 1;
        }
        return true;
    }
}
