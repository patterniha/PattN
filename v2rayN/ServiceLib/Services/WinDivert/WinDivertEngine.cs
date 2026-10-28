using WinDivertSharp;

namespace ServiceLib.Services.WinDivert;

/// <summary>
/// Options of the WinDivert engine.
/// </summary>
public class WinDivertOptions
{
    /// <summary>
    /// Intercept dns queries and resolve them through the proxy (dns over https).
    /// </summary>
    public bool EnableDnsHijack { get; set; } = true;

    /// <summary>
    /// Drop quic/http3 traffic, so applications fall back to tcp which can be tunneled.
    /// </summary>
    public bool DropQuic { get; set; } = true;

    /// <summary>
    /// Do not divert traffic to private/local network addresses.
    /// </summary>
    public bool BypassLan { get; set; } = true;

    /// <summary>
    /// The dns-over-https server used to resolve the intercepted queries.
    /// </summary>
    public string DnsUrl { get; set; } = "https://1.1.1.1/dns-query";

    /// <summary>
    /// Local socks/mixed port of the running core.
    /// </summary>
    public int ProxyPort { get; set; }
}

/// <summary>
/// WinDivert based traffic interception.
/// <para>
/// All outgoing tcp connections are diverted to a local relay which forwards them through
/// the running core, so applications that ignore the system proxy are tunneled as well,
/// without requiring a tun adapter (wintun).
/// </para>
/// </summary>
public class WinDivertEngine : IDisposable
{
    private const string _tag = "WinDivertEngine";
    private const string _filter = "(ip or ipv6) and (tcp or (udp and (udp.DstPort == 53 or udp.DstPort == 443 or udp.DstPort == 3478 or udp.DstPort == 19302)))";

    private readonly WinDivertRelay _relay;
    private readonly WinDivertDnsResolver _dnsResolver;
    private readonly WinDivertOptions _options;
    private readonly ConcurrentDictionary<int, bool> _excludedPids = new();
    private readonly ConcurrentDictionary<ushort, long> _bypassedPorts = new();
    private readonly CancellationTokenSource _cts = new();

    private IntPtr _handle = IntPtr.Zero;
    private Thread? _worker;
    private volatile bool _running;
    private long _lastPidRefresh;
    private long _lastCleanupTicks;
    private bool _disposed;

    public WinDivertEngine(WinDivertRelay relay, WinDivertDnsResolver dnsResolver, WinDivertOptions options)
    {
        _relay = relay;
        _dnsResolver = dnsResolver;
        _options = options;
    }

    public bool IsRunning => _running;

    public long TunneledPackets { get; private set; }

    public long BypassedPackets { get; private set; }

    /// <summary>
    /// Opens the WinDivert handle and starts the interception.
    /// </summary>
    public void Start()
    {
        if (_running)
        {
            return;
        }

        _relay.ProxyPort = _options.ProxyPort;
        _relay.Start();

        _handle = WinDivertSharp.WinDivert.WinDivertOpen(_filter, WinDivertLayer.Network, 0, WinDivertOpenFlags.None);
        if (_handle == IntPtr.Zero || _handle == new IntPtr(-1))
        {
            var error = Marshal.GetLastWin32Error();
            _relay.Stop();
            throw new InvalidOperationException(GetOpenErrorMessage(error));
        }

        _running = true;
        RefreshExcludedPids();

        _worker = new Thread(PacketLoop)
        {
            IsBackground = true,
            Name = "WinDivert-PacketLoop",
        };
        _worker.Start();
    }

    public void Stop()
    {
        _running = false;

        try
        {
            _cts.Cancel();
        }
        catch
        {
            // ignore
        }

        if (_handle != IntPtr.Zero && _handle != new IntPtr(-1))
        {
            WinDivertSharp.WinDivert.WinDivertClose(_handle);
            _handle = IntPtr.Zero;
        }

        _relay.Stop();
        _excludedPids.Clear();
    }

    private void PacketLoop()
    {
        using var packet = new WinDivertBuffer();
        var addr = new WinDivertAddress();
        uint readLen = 0;

        while (_running)
        {
            try
            {
                if (!WinDivertSharp.WinDivert.WinDivertRecv(_handle, packet, ref addr, ref readLen))
                {
                    if (!_running)
                    {
                        break;
                    }
                    continue;
                }

                RefreshExcludedPids();

                long nowTicks = Environment.TickCount64;
                if (nowTicks - _lastCleanupTicks > 5000)
                {
                    _lastCleanupTicks = nowTicks;
                    foreach (var kvp in _bypassedPorts)
                    {
                        if (nowTicks > kvp.Value)
                        {
                            _bypassedPorts.TryRemove(kvp.Key, out _);
                        }
                    }
                }

                ProcessPacket(packet, ref addr, readLen);
            }
            catch (Exception ex)
            {
                Logging.SaveLog(_tag, ex);
            }
        }
    }

    private void ProcessPacket(WinDivertBuffer packet, ref WinDivertAddress addr, uint len)
    {
        var result = WinDivertSharp.WinDivert.WinDivertHelperParsePacket(packet, len);

        if (result.IsIPv6)
        {
            // Drop outbound IPv6 packets for intercepted protocols so Windows and applications
            // immediately fall back to IPv4 (which is tunneled through proxy via WinDivert).
            // This prevents IPv6 DNS leaks and real Iranian IPv6 address disclosure.
            if (addr.Direction == WinDivertDirection.Outbound)
            {
                BypassedPackets++;
                return;
            }
            SendPacket(packet, len, ref addr);
            return;
        }

        if (!result.IsIPv4)
        {
            SendPacket(packet, len, ref addr);
            return;
        }

        if (result.IsUdp)
        {
            HandleUdp(packet, ref addr, len, result);
            return;
        }

        if (result.IsTcp)
        {
            HandleTcp(packet, ref addr, len, result);
            return;
        }

        SendPacket(packet, len, ref addr);
    }

    #region tcp

    private void HandleTcp(WinDivertBuffer packet, ref WinDivertAddress addr, uint len, WinDivertParseResult result)
    {
        ref var ipHeader = ref result.IPv4Header;
        ref var tcpHeader = ref result.TcpHeader;

        var srcPort = (ushort)(((tcpHeader.SrcPort & 0xFF) << 8) | ((tcpHeader.SrcPort >> 8) & 0xFF));
        var dstPort = (ushort)(((tcpHeader.DstPort & 0xFF) << 8) | ((tcpHeader.DstPort >> 8) & 0xFF));

        // 1. packets sent by the local relay back to the application
        if (addr.Direction == WinDivertDirection.Outbound && srcPort == _relay.LocalRelayPort)
        {
            if (_relay.NatTable.TryGetValue(dstPort, out var original))
            {
                // restore the original destination, the application expects the answer
                // to come from the server it asked for
                ipHeader.SrcAddr = original.TargetIp;
                tcpHeader.SrcPort = (ushort)(((original.TargetPort & 0xFF) << 8) | ((original.TargetPort >> 8) & 0xFF));
                ipHeader.DstAddr = original.LocalIp;

                addr.Direction = WinDivertDirection.Inbound;
                WinDivertSharp.WinDivert.WinDivertHelperCalcChecksums(packet, len, ref addr, WinDivertChecksumHelperParam.All);
                SendPacket(packet, len, ref addr);
                TunneledPackets++;
            }
            else
            {
                SendPacket(packet, len, ref addr);
            }
            return;
        }

        if (addr.Direction != WinDivertDirection.Outbound)
        {
            SendPacket(packet, len, ref addr);
            return;
        }

        // 2. Already marked bypassed connection: pass directly
        if (_bypassedPorts.TryGetValue(srcPort, out _))
        {
            if (tcpHeader.Fin == 1 || tcpHeader.Rst == 1)
            {
                _bypassedPorts.TryRemove(srcPort, out _);
            }
            SendPacket(packet, len, ref addr);
            BypassedPackets++;
            return;
        }

        // 3. a new connection, the handshake is redirected to the local relay
        if (tcpHeader.Syn == 1 && tcpHeader.Ack == 0)
        {
            var targetIp = ipHeader.DstAddr;
            var localIp = ipHeader.SrcAddr;

            if (ShouldBypass(targetIp, srcPort, false))
            {
                _bypassedPorts[srcPort] = Environment.TickCount64 + 60_000;
                BypassedPackets++;
                SendPacket(packet, len, ref addr);
                return;
            }

            _relay.NatTable[srcPort] = new OriginalDestination(targetIp, dstPort, localIp);

            // the packet is injected as inbound, so the operating system answers the
            // application on behalf of the original destination
            ipHeader.DstAddr = localIp;
            tcpHeader.DstPort = (ushort)(((_relay.LocalRelayPort & 0xFF) << 8) | ((_relay.LocalRelayPort >> 8) & 0xFF));
            ipHeader.SrcAddr = targetIp;

            addr.Direction = WinDivertDirection.Inbound;
            WinDivertSharp.WinDivert.WinDivertHelperCalcChecksums(packet, len, ref addr, WinDivertChecksumHelperParam.All);
            SendPacket(packet, len, ref addr);
            TunneledPackets++;
            return;
        }

        // 3. traffic of an already diverted connection, it is sent to the local relay
        if (_relay.NatTable.TryGetValue(srcPort, out var current))
        {
            ipHeader.DstAddr = current.LocalIp;
            tcpHeader.DstPort = (ushort)(((_relay.LocalRelayPort & 0xFF) << 8) | ((_relay.LocalRelayPort >> 8) & 0xFF));
            ipHeader.SrcAddr = current.TargetIp;

            addr.Direction = WinDivertDirection.Inbound;
            WinDivertSharp.WinDivert.WinDivertHelperCalcChecksums(packet, len, ref addr, WinDivertChecksumHelperParam.All);
            SendPacket(packet, len, ref addr);
            TunneledPackets++;
            return;
        }

        SendPacket(packet, len, ref addr);
    }

    #endregion tcp

    #region udp

    private void HandleUdp(WinDivertBuffer packet, ref WinDivertAddress addr, uint len, WinDivertParseResult result)
    {
        if (addr.Direction != WinDivertDirection.Outbound)
        {
            SendPacket(packet, len, ref addr);
            return;
        }

        ref var ipHeader = ref result.IPv4Header;
        ref var udpHeader = ref result.UdpHeader;

        var srcPort = (ushort)(((udpHeader.SrcPort & 0xFF) << 8) | ((udpHeader.SrcPort >> 8) & 0xFF));
        var dstPort = (ushort)(((udpHeader.DstPort & 0xFF) << 8) | ((udpHeader.DstPort >> 8) & 0xFF));

        // 1. WebRTC STUN Leak prevention (ports 3478, 19302):
        // Drop outbound STUN requests so WebRTC in browsers cannot discover the real Iranian public IP.
        if (dstPort == 3478 || dstPort == 19302)
        {
            BypassedPackets++;
            return;
        }

        if (dstPort != 53 && dstPort != 443)
        {
            SendPacket(packet, len, ref addr);
            return;
        }

        // 2. DNS Hijack (port 53):
        // MUST be checked BEFORE ShouldBypass because 99.9% of home routers configure DNS as
        // a private LAN IP (192.168.1.1). If we checked ShouldBypass first, all DNS queries
        // to the router would be bypassed directly to TIC (Iran), causing severe DNS leaks!
        if (dstPort == 53 && _options.EnableDnsHijack)
        {
            var pid = WinDivertProcessResolver.GetPidForLocalUdpPort(srcPort);
            if (pid > 0 && (_excludedPids.ContainsKey(pid) || pid == Environment.ProcessId))
            {
                SendPacket(packet, len, ref addr);
                return;
            }

            HandleDnsQuery(packet, ref addr, len, result, srcPort);
            return;
        }

        if (ShouldBypass(ipHeader.DstAddr, srcPort, true))
        {
            BypassedPackets++;
            SendPacket(packet, len, ref addr);
            return;
        }

        if (dstPort == 443 && _options.DropQuic)
        {
            // quic/http3 can not be tunneled here, dropping it makes the applications
            // fall back to tcp
            BypassedPackets++;
            return;
        }

        SendPacket(packet, len, ref addr);
    }

    private void HandleDnsQuery(WinDivertBuffer packet, ref WinDivertAddress addr, uint len, WinDivertParseResult result, ushort clientPort)
    {
        ref var ipHeader = ref result.IPv4Header;

        var clientIp = ipHeader.SrcAddr;
        var serverIp = ipHeader.DstAddr;

        var payload = result.PacketPayload;
        if (payload.Length == 0)
        {
            SendPacket(packet, len, ref addr);
            return;
        }

        var query = payload.ToArray();
        var originalAddr = addr;

        // the query is dropped here, it is answered by the encrypted DoH resolver
        _ = Task.Run(async () =>
        {
            try
            {
                var response = await _dnsResolver.ResolveAsync(query, _options.ProxyPort, _cts.Token);
                if (response != null)
                {
                    InjectDnsResponse(serverIp, clientIp, clientPort, response, originalAddr);
                }
                else
                {
                    // NEVER leak to the unencrypted system resolver (TIC - Iran) on failure!
                    // Return a DNS Server Failure (SERVFAIL) response so the client retries via proxy.
                    var servFail = BuildDnsServFailResponse(query);
                    if (servFail != null)
                    {
                        InjectDnsResponse(serverIp, clientIp, clientPort, servFail, originalAddr);
                    }
                }
            }
            catch (Exception ex)
            {
                Logging.SaveLog(_tag, ex);
            }
        });
    }

    private static byte[]? BuildDnsServFailResponse(byte[] query)
    {
        if (query.Length < 12)
        {
            return null;
        }

        var response = new byte[12];
        response[0] = query[0]; // ID high
        response[1] = query[1]; // ID low
        response[2] = 0x81;     // QR=1, RD=1
        response[3] = 0x82;     // RA=1, RCODE=2 (Server Failure)
        response[4] = query[4]; // QDCOUNT high
        response[5] = query[5]; // QDCOUNT low
        return response;
    }

    /// <summary>
    /// Builds an ipv4/udp packet and injects it as inbound traffic.
    /// </summary>
    private static byte[] BuildUdpPacket(IPAddress srcIp, IPAddress dstIp, ushort srcPort, ushort dstPort, byte[] payload)
    {
        var udpLength = 8 + payload.Length;
        var totalLength = 20 + udpLength;
        var buffer = new byte[totalLength];

        // ipv4 header
        buffer[0] = 0x45;
        buffer[1] = 0x00;
        buffer[2] = (byte)(totalLength >> 8);
        buffer[3] = (byte)(totalLength & 0xFF);
        buffer[4] = 0x00;
        buffer[5] = 0x00;
        buffer[6] = 0x00;
        buffer[7] = 0x00;
        buffer[8] = 64;
        buffer[9] = 17;
        buffer[10] = 0x00;
        buffer[11] = 0x00;

        var src = srcIp.GetAddressBytes();
        var dst = dstIp.GetAddressBytes();
        Buffer.BlockCopy(src, 0, buffer, 12, 4);
        Buffer.BlockCopy(dst, 0, buffer, 16, 4);

        var checksum = ComputeChecksum(buffer, 0, 20);
        buffer[10] = (byte)(checksum >> 8);
        buffer[11] = (byte)(checksum & 0xFF);

        // udp header
        buffer[20] = (byte)(srcPort >> 8);
        buffer[21] = (byte)(srcPort & 0xFF);
        buffer[22] = (byte)(dstPort >> 8);
        buffer[23] = (byte)(dstPort & 0xFF);
        buffer[24] = (byte)(udpLength >> 8);
        buffer[25] = (byte)(udpLength & 0xFF);
        buffer[26] = 0x00;
        buffer[27] = 0x00;

        Buffer.BlockCopy(payload, 0, buffer, 28, payload.Length);

        return buffer;
    }

    private static int ComputeChecksum(byte[] buffer, int offset, int length)
    {
        var sum = 0;
        for (var i = 0; i < length; i += 2)
        {
            sum += (buffer[offset + i] << 8) + buffer[offset + i + 1];
        }
        while ((sum >> 16) != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return ~sum & 0xFFFF;
    }

    #endregion udp

    #region bypass

    /// <summary>
    /// Decides if the given traffic must not be diverted.
    /// </summary>
    private bool ShouldBypass(IPAddress dstIp, ushort srcPort, bool isUdp)
    {
        if (IPAddress.IsLoopback(dstIp))
        {
            return true;
        }

        if (_options.BypassLan && IsPrivateAddress(dstIp))
        {
            return true;
        }

        var pid = isUdp
            ? WinDivertProcessResolver.GetPidForLocalUdpPort(srcPort)
            : WinDivertProcessResolver.GetPidForLocalPort(srcPort);

        if (pid <= 0 && !isUdp)
        {
            // the connection may not be listed yet when the very first packet is seen
            Thread.Sleep(1);
            pid = WinDivertProcessResolver.GetPidForLocalPort(srcPort);
        }

        if (pid <= 0)
        {
            return false;
        }

        // this application (the relay, the dns resolver, ...)
        if (pid == Environment.ProcessId)
        {
            return true;
        }

        // the proxy core, it has to reach the server without being diverted
        if (_excludedPids.ContainsKey(pid))
        {
            return true;
        }

        var (name, _) = WinDivertProcessResolver.GetProcessInfo(pid);
        if (WinDivertProcessResolver.IsKnownProxyProcess(name))
        {
            _excludedPids[pid] = true;
            return true;
        }

        return false;
    }

    private static bool IsPrivateAddress(IPAddress ip)
    {
        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return false;
        }

        var bytes = ip.GetAddressBytes();

        // 10.10.34.0/24 is Iran's national DNS poisoning redirection sinkhole IP range!
        // We must NEVER treat it as local LAN, it MUST be intercepted and tunneled.
        if (bytes[0] == 10 && bytes[1] == 10 && bytes[2] == 34)
        {
            return false;
        }

        return bytes[0] switch
        {
            10 => true,
            127 => true,
            172 => bytes[1] >= 16 && bytes[1] < 32,
            192 => bytes[1] == 168,
            169 => bytes[1] == 254,
            0 => true,
            _ => false,
        };
    }

    /// <summary>
    /// Refreshes the list of processes that must not be diverted (the running core).
    /// </summary>
    private void RefreshExcludedPids()
    {
        var now = Environment.TickCount64;
        if (now - _lastPidRefresh < 3000)
        {
            return;
        }
        _lastPidRefresh = now;

        try
        {
            if (_options.ProxyPort > 0)
            {
                var pid = WinDivertProcessResolver.GetPidListeningOnPort(_options.ProxyPort);
                if (pid > 0)
                {
                    _excludedPids[pid] = true;
                    var parentPid = WinDivertProcessResolver.GetParentProcessId(pid);
                    if (parentPid > 0)
                    {
                        _excludedPids[parentPid] = true;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
        }
    }

    #endregion bypass

    #region send

    private void SendPacket(WinDivertBuffer packet, uint len, ref WinDivertAddress addr)
    {
        try
        {
            WinDivertSharp.WinDivert.WinDivertSend(_handle, packet, len, ref addr);
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
        }
    }

    private void InjectPacket(byte[] bytes, WinDivertAddress addr)
    {
        if (!_running)
        {
            return;
        }

        try
        {
            using var buffer = new WinDivertBuffer(bytes);
            WinDivertSharp.WinDivert.WinDivertHelperCalcChecksums(buffer, (uint)bytes.Length, ref addr, WinDivertChecksumHelperParam.All);
            WinDivertSharp.WinDivert.WinDivertSend(_handle, buffer, (uint)bytes.Length, ref addr);
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
        }
    }

    private void InjectDnsResponse(IPAddress serverIp, IPAddress clientIp, ushort clientPort, byte[] dnsPayload, WinDivertAddress originalAddr)
    {
        var bytes = BuildUdpPacket(serverIp, clientIp, 53, clientPort, dnsPayload);
        var addr = originalAddr;
        addr.Direction = WinDivertDirection.Inbound;
        InjectPacket(bytes, addr);
    }

    #endregion send

    private static string GetOpenErrorMessage(int error)
    {
        return error switch
        {
            5 => "Access denied, the application must run as administrator.",
            2 => "The WinDivert driver files (WinDivert.dll / WinDivert64.sys) were not found in the application folder.",
            577 => "The digital signature of the WinDivert driver was not accepted by Windows.",
            _ => $"Could not open the WinDivert handle, error code: {error}",
        };
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        Stop();
        try
        {
            _cts.Dispose();
        }
        catch
        {
            // ignore
        }
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
