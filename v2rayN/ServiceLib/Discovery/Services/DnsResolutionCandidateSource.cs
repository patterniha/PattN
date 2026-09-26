using ServiceLib.Discovery.Models;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Lowest-risk endpoint source: resolve the profile's existing hostname and expose its A/AAAA answers as
/// physical dial candidates. It does not reinterpret literal IP inputs and does not mutate the profile.
/// </summary>
public sealed class DnsResolutionCandidateSource : IDiscoveryCandidateSource
{
    public async IAsyncEnumerable<DiscoveryEndpointCandidate> GetCandidatesAsync(
        DiscoveryCandidateRequest request,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var host = request.OriginalAddress.Trim().Trim('[', ']');
        if (host.IsNullOrEmpty() || IPAddress.TryParse(host, out _))
        {
            yield break;
        }

        IPAddress[] addresses;
        try
        {
            addresses = await Dns.GetHostAddressesAsync(host).WaitAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            yield break;
        }

        foreach (var address in addresses.Distinct())
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return new DiscoveryEndpointCandidate
            {
                Address = address.ToString(),
                Port = request.OriginalPort,
                Source = "dns.resolve",
                Metadata = new Dictionary<string, string>
                {
                    ["addressFamily"] = address.AddressFamily == AddressFamily.InterNetworkV6 ? "ipv6" : "ipv4",
                    ["resolvedFrom"] = host,
                },
            };
        }
    }
}
