using System.Net;
using System.Net.Sockets;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Fail-closed destination policy for remote provider catalogs. Catalog fetches are
/// internet trust operations, not a general-purpose HTTP client: loopback, private,
/// link-local, documentation, benchmark, multicast, and other non-global destinations
/// are rejected before a socket is opened.
/// </summary>
public static class ProviderAsnCatalogRemoteDestinationPolicy
{
    public static async Task<IReadOnlyList<IPAddress>> ResolveAllowedAsync(
        string host,
        CancellationToken cancellationToken = default)
    {
        if (host.IsNullOrEmpty())
        {
            throw new ArgumentException("Remote catalog host is required.", nameof(host));
        }

        IPAddress[] addresses;
        if (IPAddress.TryParse(host, out var literal))
        {
            addresses = [literal];
        }
        else
        {
            addresses = await Dns.GetHostAddressesAsync(host).WaitAsync(cancellationToken);
        }

        if (addresses.Length == 0)
        {
            throw new InvalidOperationException($"Remote catalog host '{host}' resolved to no addresses.");
        }

        var normalized = new List<IPAddress>(addresses.Length);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var address in addresses)
        {
            var candidate = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
            if (!IsAllowed(candidate))
            {
                throw new InvalidOperationException(
                    $"Remote catalog host '{host}' resolved to disallowed non-public address '{candidate}'.");
            }

            var key = candidate.ToString();
            if (seen.Add(key))
            {
                normalized.Add(candidate);
            }
        }

        if (normalized.Count == 0)
        {
            throw new InvalidOperationException($"Remote catalog host '{host}' has no allowed public addresses.");
        }
        return normalized;
    }

    public static bool IsAllowed(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        var bytes = address.GetAddressBytes();
        if (bytes.Length == 4)
        {
            return IsAllowedIPv4(bytes);
        }
        if (bytes.Length == 16)
        {
            return IsAllowedIPv6(bytes);
        }
        return false;
    }

    private static bool IsAllowedIPv4(byte[] b)
    {
        // RFC 6890 / IANA special-purpose ranges that must never be catalog destinations.
        if (b[0] == 0 || b[0] == 10 || b[0] == 127 || b[0] >= 224)
        {
            return false;
        }
        if (b[0] == 100 && b[1] is >= 64 and <= 127) // shared address space 100.64/10
        {
            return false;
        }
        if (b[0] == 169 && b[1] == 254) // link-local
        {
            return false;
        }
        if (b[0] == 172 && b[1] is >= 16 and <= 31)
        {
            return false;
        }
        if (b[0] == 192)
        {
            if (b[1] == 0 && b[2] == 0) // IETF protocol assignments
            {
                return false;
            }
            if (b[1] == 0 && b[2] == 2) // TEST-NET-1
            {
                return false;
            }
            if (b[1] == 88 && b[2] == 99) // deprecated 6to4 relay anycast
            {
                return false;
            }
            if (b[1] == 168)
            {
                return false;
            }
        }
        if (b[0] == 198)
        {
            if (b[1] is 18 or 19) // benchmarking 198.18/15
            {
                return false;
            }
            if (b[1] == 51 && b[2] == 100) // TEST-NET-2
            {
                return false;
            }
        }
        if (b[0] == 203 && b[1] == 0 && b[2] == 113) // TEST-NET-3
        {
            return false;
        }
        return true;
    }

    private static bool IsAllowedIPv6(byte[] b)
    {
        // Fail closed to the current global-unicast allocation (2000::/3), then
        // remove special-purpose subranges that are not public catalog endpoints.
        if ((b[0] & 0xE0) != 0x20)
        {
            return false;
        }

        // 2001:0000::/23 contains special-purpose assignments (for example Teredo).
        if (b[0] == 0x20 && b[1] == 0x01 && b[2] <= 0x01)
        {
            return false;
        }
        // Documentation prefix 2001:db8::/32.
        if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8)
        {
            return false;
        }
        // Deprecated 6to4 2002::/16.
        if (b[0] == 0x20 && b[1] == 0x02)
        {
            return false;
        }
        return true;
    }
}
