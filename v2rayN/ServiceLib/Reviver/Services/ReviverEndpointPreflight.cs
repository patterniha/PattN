using ServiceLib.Reviver.Models;

namespace ServiceLib.Reviver.Services;

/// <summary>
/// Cheap diagnosis before launching a proxy core. It only runs for TCP-based transports/protocols, resolves the
/// existing server identity, and classifies direct connection failures. UDP/QUIC-style profiles deliberately skip it.
/// </summary>
public sealed class ReviverEndpointPreflight(int connectTimeoutMs = 1200) : IReviverEndpointPreflight
{
    private readonly int _connectTimeoutMs = Math.Clamp(connectTimeoutMs, 100, 10_000);

    public async Task<EndpointPreflightResult> CheckAsync(ProfileItem profile, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(profile);
        if (!IsTcpBased(profile))
        {
            return new EndpointPreflightResult { Applicable = false };
        }

        var addresses = await ResolveAsync(profile.Address, cancellationToken);
        if (addresses.Count == 0)
        {
            return new EndpointPreflightResult
            {
                Applicable = true,
                FailureClass = ERepairFailureClass.DnsResolutionFailure,
                Evidence = [new RepairEvidence { Kind = "preflight.dns", Summary = "The endpoint hostname produced no usable A/AAAA addresses." }],
            };
        }

        var observedFailures = new List<ERepairFailureClass>();
        foreach (var address in addresses)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var client = new TcpClient(address.AddressFamily);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(_connectTimeoutMs);
            var started = Stopwatch.GetTimestamp();
            try
            {
                await client.ConnectAsync(address, profile.Port, timeout.Token);
                var elapsed = Stopwatch.GetElapsedTime(started);
                return new EndpointPreflightResult
                {
                    Applicable = true,
                    Reachable = true,
                    ResolvedAddresses = addresses.Select(x => x.ToString()).ToArray(),
                    Evidence =
                    [
                        new RepairEvidence
                        {
                            Kind = "preflight.tcp",
                            Summary = $"TCP endpoint reachable at {address}:{profile.Port}.",
                            Data = new Dictionary<string, string>
                            {
                                ["address"] = address.ToString(),
                                ["latencyMs"] = elapsed.TotalMilliseconds.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture),
                            },
                        }
                    ],
                };
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (OperationCanceledException)
            {
                observedFailures.Add(ERepairFailureClass.ConnectionTimeout);
            }
            catch (SocketException ex)
            {
                observedFailures.Add(MapSocketFailure(ex.SocketErrorCode));
            }
            catch
            {
                observedFailures.Add(ERepairFailureClass.NetworkUnreachable);
            }
        }

        var failure = ChooseFailure(observedFailures);
        return new EndpointPreflightResult
        {
            Applicable = true,
            Reachable = false,
            FailureClass = failure,
            ResolvedAddresses = addresses.Select(x => x.ToString()).ToArray(),
            Evidence = [new RepairEvidence { Kind = "preflight.tcp", Summary = $"No resolved endpoint accepted TCP on port {profile.Port}." }],
        };
    }

    private static async Task<IReadOnlyList<IPAddress>> ResolveAsync(string rawAddress, CancellationToken cancellationToken)
    {
        var host = rawAddress.Trim().Trim('[', ']');
        if (IPAddress.TryParse(host, out var literal))
        {
            return [literal];
        }
        try
        {
            return (await Dns.GetHostAddressesAsync(host).WaitAsync(cancellationToken)).Distinct().ToArray();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return [];
        }
    }

    private static bool IsTcpBased(ProfileItem profile)
    {
        if (profile.ConfigType is EConfigType.Hysteria2 or EConfigType.TUIC or EConfigType.WireGuard)
        {
            return false;
        }
        var network = profile.GetNetwork();
        return !string.Equals(network, nameof(ETransport.kcp), StringComparison.OrdinalIgnoreCase)
               && !string.Equals(network, nameof(ETransport.quic), StringComparison.OrdinalIgnoreCase);
    }

    private static ERepairFailureClass MapSocketFailure(SocketError error)
        => error switch
        {
            SocketError.ConnectionRefused => ERepairFailureClass.ConnectionRefused,
            SocketError.TimedOut => ERepairFailureClass.ConnectionTimeout,
            SocketError.HostUnreachable or SocketError.NetworkUnreachable or SocketError.AddressNotAvailable => ERepairFailureClass.NetworkUnreachable,
            _ => ERepairFailureClass.NetworkUnreachable,
        };

    private static ERepairFailureClass ChooseFailure(IReadOnlyList<ERepairFailureClass> failures)
    {
        if (failures.Contains(ERepairFailureClass.ConnectionRefused))
        {
            return ERepairFailureClass.ConnectionRefused;
        }
        if (failures.Contains(ERepairFailureClass.ConnectionTimeout))
        {
            return ERepairFailureClass.ConnectionTimeout;
        }
        return failures.FirstOrDefault(ERepairFailureClass.NetworkUnreachable);
    }
}
