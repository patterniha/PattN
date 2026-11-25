namespace ServiceLib.Aether;

/// <summary>An exit Xray process, as <see cref="AetherExitService" /> stops it: PattN's ProcessService, or a fake in tests.</summary>
public interface IAetherExitProcess
{
    bool HasExited { get; }

    /// <summary>Stops the process and releases it.</summary>
    Task StopAsync();
}

/// <summary>What <see cref="AetherExitService" /> works with: PattN's own in <see cref="Default" />, fakes in tests.</summary>
public sealed class AetherExitHost
{
    /// <summary>The Aether listen port of the settings; the exit takes none of it and the three ports after it.</summary>
    public required Func<int> ListenPort { get; init; }

    /// <summary>A loopback port free now, which the system picks.</summary>
    public Func<int> PickPort { get; init; } = PickLoopbackPort;

    /// <summary>The configuration of the exit Xray for an exit-node, with its secondary-socks inbound on a port; a failed result says why there is none.</summary>
    public required Func<AetherExit, int, Task<RetResult>> Generate { get; init; }

    /// <summary>The path of a configuration file of a name in binConfigs.</summary>
    public Func<string, string> ConfigPath { get; init; } = name => Utils.GetBinConfigPath(name);

    /// <summary>Starts Xray on the configuration file of a name in binConfigs; null when it does not run.</summary>
    public required Func<string, Task<IAetherExitProcess?>> StartXray { get; init; }

    /// <summary>Waits for a loopback port to accept connections, for at most the time given.</summary>
    public Func<int, TimeSpan, CancellationToken, Task<bool>> WaitForPort { get; init; } = AetherCoreLoad.WaitForPortAsync;

    /// <summary>How long the exit Xray may take to listen.</summary>
    public TimeSpan StartWait { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>What PattN's own exits run with.</summary>
    public static AetherExitHost Default()
    {
        return new AetherExitHost
        {
            ListenPort = () => AetherPorts.ListenPortOf(ConfigTextHandler.Config?.CoreBasicItem?.AetherListenPort),
            Generate = (exit, port) => GenerateAsync(exit, port, AetherUplinkBinding.Default),
            StartXray = async fileName =>
                await CoreManager.Instance.RunAetherExitXrayAsync(fileName) is { } process ? new XrayProcess(process) : null,
        };
    }

    /// <summary>
    /// The profile the context of an exit is built for: a profile of nothing, run by Xray, as for a latency test
    /// (CoreConfigHandler.GenerateClientSpeedtestConfig). It has no id, so that the builder checks nothing of it and goes
    /// on to the end, where it leaves out the bind interface and the send-through address the app cannot use, as it does
    /// for a session.
    /// </summary>
    public static ProfileItem ContextProfile()
    {
        return new ProfileItem { CoreType = ECoreType.Xray };
    }

    /// <summary>
    /// The exit configuration in a context of its own (<see cref="ContextProfile" />), with the node an exit names looked
    /// up by its name and registered into it as any profile of a configuration is, and its outbounds bound to the uplink
    /// as <paramref name="uplink" /> decides (under a TUN, with no bind interface set; D2).
    /// </summary>
    public static async Task<RetResult> GenerateAsync(AetherExit exit, int port, AetherUplinkBinding uplink)
    {
        var config = ConfigTextHandler.Config;
        // Its routing rules are never used: a rule's target never refuses it, nor logs that it would (E2).
        var (context, _) = await CoreConfigContextBuilder.Build(config, ContextProfile(), refuseRuleTargets: false);
        if (exit.Node is { } node)
        {
            context.Aether.ExitNodes[node] = await CoreConfigContextBuilder.LookUpAetherExitNodeAsync(context, node);
        }
        uplink.Apply(context, AetherUplinkBinding.ExitRole);
        return new CoreConfigV2rayService(context).GenerateAetherExitConfig(exit, port);
    }

    private static int PickLoopbackPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            return ((IPEndPoint)listener.LocalEndpoint).Port;
        }
        finally
        {
            listener.Stop();
        }
    }

    private sealed class XrayProcess(ProcessService process) : IAetherExitProcess
    {
        public bool HasExited => process.HasExited;

        public async Task StopAsync()
        {
            await process.StopAsync();
            process.Dispose();
        }
    }
}

/// <summary>
/// The exit of a core of its own: a scan or a key run dials out through a short-lived Xray process (design 2.6.5, the
/// desktop's stand-in for PattNG's in-process Libv2ray.openExit), whose secondary-socks inbound on a free loopback port
/// sends what the core sends out by the exit-node, as the session's Xray does for the session's core. Under the TUN its
/// freedom exit-node resolves names with the direct DNS servers (critique 19), and while a TUN runs its outbounds dial out
/// by the uplink rather than into the TUN, unless the settings name a bind interface (AetherUplinkBinding, D2).
/// </summary>
public sealed class AetherExitService(AetherExitHost host)
{
    private static readonly Lazy<AetherExitService> _default = new(() => new AetherExitService(AetherExitHost.Default()));

    /// <summary>How many ports the system may hand out that the Aether cores need before one is taken.</summary>
    private const int PortAttempts = 16;

    public static AetherExitService Default => _default.Value;

    /// <summary>
    /// Opens the exit for <paramref name="exit" />: the configuration is generated and written, Xray started on it, and its
    /// port waited for. Null, with the reason in the log, when it does not open: the exit-node gives no outbound (no
    /// profile or several have its name, it gives none, or its ECH outbound is unusable), or Xray does not run or listen.
    /// Nothing is left running then. A cancellation stops what was started and throws.
    /// </summary>
    public async Task<IAetherExit?> OpenAsync(AetherExit exit, string source, CancellationToken ct = default)
    {
        var port = FreePort(host.PickPort, host.ListenPort());
        if (port == null)
        {
            Logging.SaveLog($"AetherCore: no loopback port is free for the Xray {source} dials out through");
            return null;
        }
        RetResult result;
        try
        {
            result = await host.Generate(exit, port.Value).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Logging.SaveLog($"AetherCore: the configuration of the Xray {source} dials out through could not be generated", ex);
            return null;
        }
        if (result.Success != true)
        {
            Logging.SaveLog($"AetherCore: the exit-node {source} dials out through gives no outbound: {result.Msg}");
            return null;
        }
        var fileName = ConfigFileName();
        var file = host.ConfigPath(fileName);
        try
        {
            await File.WriteAllTextAsync(file, result.Data?.ToString(), CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Logging.SaveLog($"AetherCore: the configuration of the Xray {source} dials out through could not be written", ex);
            DeleteFile(file);
            return null;
        }
        var process = await host.StartXray(fileName).ConfigureAwait(false);
        if (process == null)
        {
            Logging.SaveLog($"AetherCore: the Xray {source} dials out through did not start");
            DeleteFile(file);
            return null;
        }
        var opened = new OpenExit(port.Value, process, file);
        try
        {
            if (!await host.WaitForPort(port.Value, host.StartWait, ct).ConfigureAwait(false))
            {
                Logging.SaveLog($"AetherCore: the Xray {source} dials out through did not listen on {port.Value} in time");
                await opened.DisposeAsync().ConfigureAwait(false);
                return null;
            }
        }
        catch
        {
            await opened.DisposeAsync().ConfigureAwait(false);
            throw;
        }
        return opened;
    }

    /// <summary>
    /// A new name for the configuration file of an exit Xray in binConfigs. Its name holds "Test", as those of the latency
    /// tests' configurations do: the hourly sweep of binConfigs (TaskManager) removes such a file an hour old, so that one
    /// left behind by a PattN that ended without closing its exit, with the outbound of the exit-node's profile in it, does
    /// not stay; Xray reads its configuration only as it starts.
    /// </summary>
    public static string ConfigFileName()
    {
        return $"configTestAetherExit{Utils.GetGuid(false)}.json";
    }

    /// <summary>
    /// A loopback port that <paramref name="pick" /> gives, never the Aether listen port <paramref name="listenPort" /> nor
    /// one of the three after it, which the cores, a test's or the session's, may need meanwhile; null when every port it
    /// gives is one of them.
    /// </summary>
    public static int? FreePort(Func<int> pick, int listenPort)
    {
        for (var attempt = 0; attempt < PortAttempts; attempt++)
        {
            var port = pick();
            if (port > 0 && !AetherPorts.IsReserved(port, listenPort))
            {
                return port;
            }
        }
        return null;
    }

    private static void DeleteFile(string file)
    {
        try
        {
            File.Delete(file);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Logging.SaveLog("AetherCore: the configuration of an exit Xray could not be removed", ex);
        }
    }

    /// <summary>An open exit; disposing it stops its Xray and removes its configuration file.</summary>
    private sealed class OpenExit(int port, IAetherExitProcess process, string file) : IAetherExit
    {
        private int _closed;

        public int Port { get; } = port;

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _closed, 1) != 0)
            {
                return;
            }
            try
            {
                await process.StopAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Logging.SaveLog("AetherCore: the Xray of an exit could not be stopped", ex);
            }
            DeleteFile(file);
        }
    }
}
