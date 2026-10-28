namespace ServiceLib.Services.WinDivert;

/// <summary>
/// Resolves the process that owns a local TCP/UDP port.
/// Used by the WinDivert engine to detect traffic that must not be intercepted
/// (the proxy core itself, this application, ...).
/// </summary>
public static class WinDivertProcessResolver
{
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, uint reserved = 0);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, uint reserved = 0);

    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const int UDP_TABLE_OWNER_PID = 1;

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ucLocalAddr;
        public uint dwLocalScopeId;
        public uint dwLocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ucRemoteAddr;
        public uint dwRemoteScopeId;
        public uint dwRemotePort;
        public uint dwState;
        public uint dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPROW_OWNER_PID
    {
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ucLocalAddr;
        public uint dwLocalScopeId;
        public uint dwLocalPort;
        public uint dwOwningPid;
    }

    private static readonly ConcurrentDictionary<int, (string? Name, string? Path, long ExpireTicks)> _pidCache = new();

    /// <summary>
    /// Known proxy cores / tunnels. Their traffic must never be diverted,
    /// otherwise the proxy would connect to itself.
    /// </summary>
    private static readonly HashSet<string> _knownProxyProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "xray", "p-xray-p", "v2ray", "wv2ray", "v2rayn", "pattn", "v2raya", "v2ray-core",
        "sing-box", "clash", "clash-meta", "clash-verge", "clash-verge-service", "mihomo",
        "nekobox", "nekoray", "hiddify", "shadowsocks", "ss-local", "outline",
        "trojan", "trojan-go", "naive", "naiveproxy", "warp-svc", "wireguard", "openvpn"
    };

    /// <summary>
    /// Finds the process id owning the given local TCP port.
    /// </summary>
    public static int GetPidForLocalPort(ushort localPort)
    {
        if (!Utils.IsWindows())
        {
            return -1;
        }

        var pid = GetPidOnPortInternal(localPort, AF_INET);
        return pid > 0 ? pid : GetPidOnPortInternal(localPort, AF_INET6);
    }

    /// <summary>
    /// Finds the process id listening on the given TCP port.
    /// </summary>
    public static int GetPidListeningOnPort(int targetPort)
    {
        if (targetPort <= 0 || targetPort > 65535)
        {
            return -1;
        }

        return GetPidForLocalPort((ushort)targetPort);
    }

    /// <summary>
    /// Finds the process id owning the given local UDP port.
    /// </summary>
    public static int GetPidForLocalUdpPort(ushort localPort)
    {
        if (!Utils.IsWindows())
        {
            return -1;
        }

        var pid = GetUdpPidOnPortInternal(localPort, AF_INET);
        return pid > 0 ? pid : GetUdpPidOnPortInternal(localPort, AF_INET6);
    }

    /// <summary>
    /// Checks whether the given process name belongs to a known proxy core or tunnel client.
    /// </summary>
    public static bool IsKnownProxyProcess(string? name)
    {
        if (name.IsNullOrEmpty())
        {
            return false;
        }

        var clean = name.Trim();
        if (clean.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            clean = clean[..^4];
        }

        if (_knownProxyProcesses.Contains(clean))
        {
            return true;
        }

        var lower = clean.ToLowerInvariant();
        return lower.Contains("xray")
            || lower.Contains("v2ray")
            || lower.Contains("pattn")
            || lower.Contains("sing-box")
            || lower.Contains("clash")
            || lower.Contains("mihomo")
            || lower.Contains("nekobox")
            || lower.Contains("hiddify");
    }

    /// <summary>
    /// Returns the process name and path for the given pid (cached for a short while).
    /// </summary>
    public static (string? Name, string? Path) GetProcessInfo(int pid)
    {
        if (pid <= 0)
        {
            return (null, null);
        }

        var now = Environment.TickCount64;
        if (_pidCache.TryGetValue(pid, out var cached) && now < cached.ExpireTicks)
        {
            return (cached.Name, cached.Path);
        }

        try
        {
            using var proc = Process.GetProcessById(pid);
            var name = proc.ProcessName;
            string? path = null;
            try
            {
                path = proc.MainModule?.FileName;
            }
            catch
            {
                // access denied for protected processes
            }

            _pidCache[pid] = (name, path, now + 30_000);
            return (name, path);
        }
        catch
        {
            return (null, null);
        }
    }

    private static int GetPidOnPortInternal(ushort targetPort, int af)
    {
        var bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, false, af, TCP_TABLE_OWNER_PID_ALL, 0);
        if (bufferSize <= 0)
        {
            return -1;
        }

        var tablePtr = Marshal.AllocHGlobal(bufferSize);
        try
        {
            if (GetExtendedTcpTable(tablePtr, ref bufferSize, false, af, TCP_TABLE_OWNER_PID_ALL, 0) != 0)
            {
                return -1;
            }

            var rowCount = Marshal.ReadInt32(tablePtr);
            var rowPtr = IntPtr.Add(tablePtr, 4);

            if (af == AF_INET)
            {
                var rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                for (var i = 0; i < rowCount; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                    var port = (ushort)(((row.dwLocalPort & 0xFF) << 8) | ((row.dwLocalPort >> 8) & 0xFF));
                    if (port == targetPort)
                    {
                        return (int)row.dwOwningPid;
                    }
                    rowPtr = IntPtr.Add(rowPtr, rowSize);
                }
            }
            else
            {
                var rowSize = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();
                for (var i = 0; i < rowCount; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(rowPtr);
                    var port = (ushort)(((row.dwLocalPort & 0xFF) << 8) | ((row.dwLocalPort >> 8) & 0xFF));
                    if (port == targetPort)
                    {
                        return (int)row.dwOwningPid;
                    }
                    rowPtr = IntPtr.Add(rowPtr, rowSize);
                }
            }
        }
        catch (Exception ex)
        {
            Logging.SaveLog("WinDivertProcessResolver", ex);
        }
        finally
        {
            Marshal.FreeHGlobal(tablePtr);
        }

        return -1;
    }

    private static int GetUdpPidOnPortInternal(ushort targetPort, int af)
    {
        var bufferSize = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, false, af, UDP_TABLE_OWNER_PID, 0);
        if (bufferSize <= 0)
        {
            return -1;
        }

        var tablePtr = Marshal.AllocHGlobal(bufferSize);
        try
        {
            if (GetExtendedUdpTable(tablePtr, ref bufferSize, false, af, UDP_TABLE_OWNER_PID, 0) != 0)
            {
                return -1;
            }

            var rowCount = Marshal.ReadInt32(tablePtr);
            var rowPtr = IntPtr.Add(tablePtr, 4);

            if (af == AF_INET)
            {
                var rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();
                for (var i = 0; i < rowCount; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                    var port = (ushort)(((row.dwLocalPort & 0xFF) << 8) | ((row.dwLocalPort >> 8) & 0xFF));
                    if (port == targetPort)
                    {
                        return (int)row.dwOwningPid;
                    }
                    rowPtr = IntPtr.Add(rowPtr, rowSize);
                }
            }
            else
            {
                var rowSize = Marshal.SizeOf<MIB_UDP6ROW_OWNER_PID>();
                for (var i = 0; i < rowCount; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_UDP6ROW_OWNER_PID>(rowPtr);
                    var port = (ushort)(((row.dwLocalPort & 0xFF) << 8) | ((row.dwLocalPort >> 8) & 0xFF));
                    if (port == targetPort)
                    {
                        return (int)row.dwOwningPid;
                    }
                    rowPtr = IntPtr.Add(rowPtr, rowSize);
                }
            }
        }
        catch (Exception ex)
        {
            Logging.SaveLog("WinDivertProcessResolver", ex);
        }
        finally
        {
            Marshal.FreeHGlobal(tablePtr);
        }

        return -1;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public UIntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr processHandle,
        int processInformationClass,
        ref PROCESS_BASIC_INFORMATION processInformation,
        int processInformationLength,
        out int returnLength);

    public static int GetParentProcessId(int pid)
    {
        if (pid <= 0) return -1;
        try
        {
            using var proc = Process.GetProcessById(pid);
            var pbi = new PROCESS_BASIC_INFORMATION();
            int returnLength;
            int status = NtQueryInformationProcess(proc.Handle, 0, ref pbi, Marshal.SizeOf(pbi), out returnLength);
            if (status == 0)
            {
                return pbi.InheritedFromUniqueProcessId.ToInt32();
            }
        }
        catch
        {
        }
        return -1;
    }
}
