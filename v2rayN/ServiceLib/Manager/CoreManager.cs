namespace ServiceLib.Manager;

/// <summary>
/// Core process processing class
/// </summary>
public class CoreManager
{
    private static readonly Lazy<CoreManager> _instance = new(() => new());
    public static CoreManager Instance => _instance.Value;
    private Config _config;

    [SupportedOSPlatform("windows")]
    private WindowsJobService? _processJob;

    private ProcessService? _processService;
    private ProcessService? _processPreService;
    private bool _linuxSudo = false;
    private Func<bool, string, Task>? _updateFunc;
    private const string _tag = "CoreHandler";

    // PattN: loads and stops take turns with the stop that follows an Aether core exiting on its own (critique 15)
    private readonly AetherCoreTurns _turns = new();
    private bool _aetherSessionWatched;

    /// <summary>
    /// PattN: called once the cores were stopped because the Aether core exited on its own, with what the user was told;
    /// the WebAPI reflects it in its runtime state (critique 32).
    /// </summary>
    public Func<string, Task>? AetherCoresStopped { get; set; }

    // PattN: the core whose configuration has the TUN, the main one (Xray's own TUN) or the pre one (sing-box's TUN in
    // front of Xray); null while none runs
    private volatile ProcessService? _tunProcess;

    /// <summary>
    /// PattN: whether a TUN of PattN runs now: the cores were loaded with one, and the core that holds it still runs. The
    /// short-lived Xray of an Aether scan, key run or latency test then binds to the uplink (AetherUplinkBinding, D2).
    /// </summary>
    public bool IsTunRunning
    {
        get
        {
            try
            {
                return _tunProcess is { HasExited: false };
            }
            catch (InvalidOperationException)
            {
                // Stopped and released meanwhile.
                return false;
            }
        }
    }

    // PattN: the interface the configuration of the running TUN names (AetherUplink.TunInterfaceOf); null when it names
    // none (sing-box's TUN on macOS) or no TUN runs
    private volatile string? _tunInterface;

    /// <summary>
    /// PattN: the interface of the TUN that runs now as its configuration names it, which the uplink is looked for beside
    /// (AetherUplink.IsTun, D2-5): on macOS Xray numbers its utun at random, and another utun may be another VPN's. Null
    /// when no TUN runs, or its name is not known.
    /// </summary>
    public string? TunInterface => IsTunRunning ? _tunInterface : null;

    public async Task Init(Config config, Func<bool, string, Task> updateFunc)
    {
        KillLingeringCores();
        _config = config;
        _updateFunc = updateFunc;

        // PattN: the Aether cores' output goes to the message view, and a session core that exits on its own takes
        // Xray with it (design 2.6.4)
        AetherCoreManager.Instance.Relay = msg => UpdateFunc(false, msg);
        if (!_aetherSessionWatched)
        {
            _aetherSessionWatched = true;
            AetherCoreManager.Instance.SessionEnded += OnAetherSessionEnded;
        }

        //Copy the bin folder to the storage location (for init)
        if (Environment.GetEnvironmentVariable(Global.LocalAppData) == "1")
        {
            var fromPath = Utils.GetBaseDirectory("bin");
            var toPath = Utils.GetBinPath("");
            if (fromPath != toPath)
            {
                FileUtils.CopyDirectory(fromPath, toPath, true, false);
            }
        }

        // PattN: the Psiphon server list shipped with this release goes over an older list in use (design 2.11); it is
        // read from the program's own bin folder, which the copy above never refreshes (critique 27)
        await Task.Run(() => PsiphonServerList.InstallBundled(
            AetherPaths.BundledPsiphonServersFile, AetherPaths.BundledPsiphonServersStampFile, AetherPaths.ActivePsiphonServersFile));

        // PattN: on Windows Xray runs from its copy p-xray-p.exe, kept equal to xray.exe: an update of the program, or a
        // hand, may have replaced xray.exe since PattN last ran
        if (Utils.IsWindows() && CoreInfoManager.Instance.FindInstalledXray() is { } xrayExe)
        {
            string? copyFailure;
            using (await CoreInfoManager.HoldXrayFilesAsync())
            {
                copyFailure = await Task.Run(() => CoreInfoManager.SyncXrayCopy(xrayExe, out var failure) ? null : failure);
            }
            if (copyFailure != null)
            {
                await UpdateFunc(false, copyFailure);
            }
        }

        if (Utils.IsNonWindows())
        {
            var coreInfo = CoreInfoManager.Instance.GetCoreInfo();
            foreach (var it in coreInfo)
            {
                if (it.CoreType == ECoreType.v2rayN)
                {
                    if (Utils.UpgradeAppExists(out var upgradeFileName))
                    {
                        await Utils.SetLinuxChmod(upgradeFileName);
                    }
                    continue;
                }

                // PattN: the Aether core and the two helpers beside it, psiphon-tunnel-core and lyrebird
                if (it.CoreType == ECoreType.aether)
                {
                    await AetherBinaries.SetExecutableAsync(AetherBinaries.Folder);
                    continue;
                }

                foreach (var name in it.CoreExes)
                {
                    var exe = Utils.GetBinPath(Utils.GetExeName(name), it.CoreType.ToString());
                    if (File.Exists(exe))
                    {
                        await Utils.SetLinuxChmod(exe);
                    }
                }
            }
        }
    }

    /// <param name="mainContext">Resolved main context (with pre-socks ports already merged if applicable).</param>
    /// <param name="preContext">Optional pre-socks context passed to <see cref="CoreStartPreService"/>.</param>
    public async Task LoadCore(CoreConfigContext? mainContext, CoreConfigContext? preContext)
    {
        if (mainContext == null)
        {
            await UpdateFunc(false, ResUI.CheckServerSettings);
            return;
        }

        // PattN: one load or stop at a time, with the stop that follows an Aether core exiting on its own (critique 15)
        await _turns.RunAsync(async () =>
        {
            try
            {
                await LoadCoreInTurn(mainContext, preContext);
            }
            finally
            {
                AetherCoreManager.Instance.EndSessionStart();
            }
        });
    }

    // PattN: LoadCore's own work, from inside a turn
    private async Task LoadCoreInTurn(CoreConfigContext mainContext, CoreConfigContext? preContext)
    {
        var node = mainContext.Node;
        var fileName = Utils.GetBinConfigPath(Global.CoreConfigFileName);
        var result = await CoreConfigHandler.GenerateClientConfig(mainContext, fileName);
        if (result.Success != true)
        {
            await UpdateFunc(true, result.Msg);
            return;
        }
        // PattN: an Aether core that cannot run keeps the cores that run; a latency test's core gives up its port (design 2.6.4)
        var aether = AetherLoadSteps(mainContext);
        if (await AetherCoreLoad.BeforeStopAsync(aether) is not { } generation)
        {
            return;
        }

        await UpdateFunc(false, $"{node.GetSummary()}");
        await UpdateFunc(false, $"{Utils.GetRuntimeInfo()}");
        await UpdateFunc(false, string.Format(ResUI.StartService, DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")));
        await CoreStopInTurn(); // PattN: in the turn of this load
        await Task.Delay(100);
        // PattN: nothing starts while a port the Aether core or Xray's inbound for it listens on is taken (D3)
        if (!await AetherCoreLoad.BeforeXrayAsync(aether))
        {
            return;
        }

        if (Utils.IsWindows() && (mainContext?.IsTunEnabled == true || preContext?.IsTunEnabled == true))
        {
            await Task.Delay(100);
            await WindowsUtils.RemoveTunDevice();
        }

        await CoreStart(mainContext);
        // PattN: Xray's own TUN runs with the main core (IsTunRunning), on the interface its configuration names (TunInterface)
        if (mainContext.IsTunEnabled)
        {
            _tunInterface = AetherUplink.TunInterfaceOf(result.Data?.ToString());
            _tunProcess = _processService;
        }
        // PattN: the Aether core starts once Xray listens, and one that does not start stops Xray with it (design 2.6.4)
        if (await AetherCoreLoad.AfterXrayAsync(aether, generation) == AetherCoreLoadOutcome.AetherFailed)
        {
            return;
        }
        await WaitForProxyPort(preContext);
        await CoreStartPreService(preContext);
        // the WinDivert mode forwards the diverted traffic to the local inbound of the core
        WinDivertService.Instance.UpdateProxyPort(AppManager.Instance.GetLocalPort(EInboundProtocol.socks));
        if (_config.WinDivertItem.Enable && Utils.IsWindows() && Utils.IsAdministrator())
        {
            WinDivertService.Instance.Start(_config);
        }
        // PattN: sing-box's TUN in front of Xray runs with the pre core (IsTunRunning), which names its interface on macOS
        // itself (TunInterface)
        if (preContext?.IsTunEnabled == true)
        {
            _tunInterface = null;
            _tunProcess = _processPreService;
        }

        AppManager.Instance.RunningCoreType = preContext?.RunCoreType ?? mainContext.RunCoreType;

        if (_processService != null)
        {
            await UpdateFunc(true, $"{node.GetSummary()}");
        }
    }

    public async Task<ProcessService?> LoadCoreConfigSpeedtest(List<ServerTestItem> selecteds)
    {
        var coreType = selecteds.FirstOrDefault()?.CoreType == ECoreType.sing_box ? ECoreType.sing_box : ECoreType.Xray;
        var fileName = string.Format(Global.CoreSpeedtestConfigFileName, Utils.GetGuid(false));
        var configPath = Utils.GetBinConfigPath(fileName);
        var result = await CoreConfigHandler.GenerateClientSpeedtestConfig(_config, configPath, selecteds, coreType);
        await UpdateFunc(false, result.Msg);
        if (result.Success != true)
        {
            return null;
        }

        await UpdateFunc(false, string.Format(ResUI.StartService, DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")));
        await UpdateFunc(false, configPath);

        var coreInfo = CoreInfoManager.Instance.GetCoreInfo(coreType);
        return await RunProcess(coreInfo, fileName, true, false);
    }

    public async Task<ProcessService?> LoadCoreConfigSpeedtest(ServerTestItem testItem)
    {
        var node = await AppManager.Instance.GetProfileItem(testItem.IndexId);
        if (node is null)
        {
            return null;
        }

        var fileName = string.Format(Global.CoreSpeedtestConfigFileName, Utils.GetGuid(false));
        var configPath = Utils.GetBinConfigPath(fileName);
        // PattN: a test drops the routing rules, so their targets never refuse it, nor log that they would (E2)
        var (context, validatorResult) = await CoreConfigContextBuilder.Build(_config, node, refuseRuleTargets: false);
        // PattN: a profile whose subscription names a previous or next profile that no profile has, or several have, is
        // not tested, as its session is refused (N1): the context, which has no chain then, would measure it without that
        // hop. The Aether tester takes such a profile before (AetherTestCandidates); this holds when the names change
        // while the run goes on.
        if (!validatorResult.Success && await CoreConfigContextBuilder.SubscriptionChainRefusalAsync(node) is { } refusal)
        {
            Logging.SaveLog($"Speedtest: '{node.Remarks}' is not tested: {refusal}");
            return null;
        }
        var result = await CoreConfigHandler.GenerateClientSpeedtestConfig(_config, context, testItem, configPath);
        if (result.Success != true)
        {
            return null;
        }

        var coreType = context.RunCoreType;
        var coreInfo = CoreInfoManager.Instance.GetCoreInfo(coreType);
        return await RunProcess(coreInfo, fileName, true, false);
    }

    public async Task CoreStop()
    {
        // PattN: in its turn, as a new generation of the cores (critique 15)
        await _turns.RunAsync(async () =>
        {
            _turns.NewGeneration();
            await CoreStopInTurn();
        });
    }

    // PattN: CoreStop's own work, from inside a turn
    private async Task CoreStopInTurn()
    {
            KillLingeringCores();
        // PattN: no TUN runs from here on (IsTunRunning, TunInterface)
        _tunProcess = null;
        _tunInterface = null;
        try
        {
            // PattN: the Aether session first, so that a reload's old core ends before Xray restarts (PattNG)
            await AetherCoreManager.Instance.StopSessionAsync();

            if (_linuxSudo)
            {
                await CoreAdminManager.Instance.KillProcessAsLinuxSudo();
                _linuxSudo = false;
            }

            if (_processService != null)
            {
                await _processService.StopAsync();
                _processService.Dispose();
                _processService = null;
            }

            if (_processPreService != null)
            {
                await _processPreService.StopAsync();
                _processPreService.Dispose();
                _processPreService = null;
            }
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
        }
    }

    #region Private

    private async Task CoreStart(CoreConfigContext context)
    {
        KillLingeringCores();
        var node = context.Node;
        var coreType = AppManager.Instance.GetCoreType(node, node.ConfigType);
        var coreInfo = CoreInfoManager.Instance.GetCoreInfo(coreType);

        var displayLog = node.ConfigType != EConfigType.Custom || node.DisplayLog;
        var proc = await RunProcess(coreInfo, Global.CoreConfigFileName, displayLog, true, context.IsTunEnabled);
        if (proc is null)
        {
            return;
        }
        _processService = proc;
    }

    private async Task CoreStartPreService(CoreConfigContext? preContext)
    {
        if (_processService is { HasExited: false } && preContext != null)
        {
            var preCoreType = preContext?.Node?.CoreType ?? ECoreType.sing_box;
            var fileName = Utils.GetBinConfigPath(Global.CorePreConfigFileName);
            var result = await CoreConfigHandler.GenerateClientConfig(preContext, fileName);
            if (result.Success)
            {
                var coreInfo = CoreInfoManager.Instance.GetCoreInfo(preCoreType);
                var proc = await RunProcess(coreInfo, Global.CorePreConfigFileName, true, true, preContext.IsTunEnabled);
                if (proc is null)
                {
                    return;
                }
                _processPreService = proc;
            }
        }
    }

    private async Task UpdateFunc(bool notify, string msg)
    {
        await _updateFunc?.Invoke(notify, msg);
    }

    private static async Task WaitForProxyPort(CoreConfigContext? preContext)
    {
        if (preContext is null)
        {
            return;
        }
        if (!preContext.IsTunEnabled)
        {
            return;
        }

        using var rootCts = new CancellationTokenSource(Global.LocalFetch);
        var rootToken = rootCts.Token;

        var port = preContext.Node.Port;
        // SOCKS5 client greeting: VER=5, NMETHODS=1, METHOD=0x00 (no auth)
        ReadOnlyMemory<byte> greeting = new byte[] { 0x05, 0x01, 0x00 };
        var buf = new byte[2];

        while (!rootToken.IsCancellationRequested)
        {
            using var tcp = new TcpClient();
            using var attemptCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(rootToken, attemptCts.Token);
            var linkedToken = linkedCts.Token;
            try
            {
                await tcp.ConnectAsync(Global.Loopback, port, linkedToken);
                var stream = tcp.GetStream();

                await stream.WriteAsync(greeting, linkedToken);

                var read = await stream.ReadAsync(buf.AsMemory(0, 2), linkedToken);

                // Server selection: VER=5, METHOD=0x00 â€” proxy is fully ready
                if (read == 2 && buf[0] == 0x05)
                {
                    return;
                }
            }
            catch (OperationCanceledException)
            {
                if (!rootToken.IsCancellationRequested)
                {
                    continue;
                }
                Logging.SaveLog($"WaitForProxyPort Timeout waiting for proxy port {port} to be ready.");
                return;
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
            {
                // Connection refused, proxy not ready yet, wait 50ms before retrying
                try
                {
                    await Task.Delay(50, rootToken);
                }
                catch (OperationCanceledException)
                {
                    Logging.SaveLog($"WaitForProxyPort Timeout waiting for proxy port {port} to be ready.");
                    return;
                }
            }
            catch
            {
                // Ignore other exceptions and continue
            }
        }
    }
    
    public static void KillLingeringCores()
    {
        if (!Utils.IsWindows())
        {
            return;
        }

        var coreNames = new[] { "p-xray-p", "xray", "sing-box", "mihomo", "aether", "lyrebird", "psiphon-tunnel-core" };
        var currentPid = Environment.ProcessId;

        foreach (var name in coreNames)
        {
            try
            {
                foreach (var p in System.Diagnostics.Process.GetProcessesByName(name))
                {
                    try
                    {
                        if (p.Id != currentPid)
                        {
                            p.Kill();
                            p.WaitForExit(300);
                        }
                    }
                    catch { }
                    finally
                    {
                        p.Dispose();
                    }
                }
            }
            catch { }
        }
    }

    #endregion Private

    #region Process

    /// <summary>
    ///     Decides whether a core launch must be elevated on non-Windows platforms.
    ///     The TUN state comes from the immutable <see cref="CoreConfigContext" /> snapshot that
    ///     generated the config, never from the live mutable config: the generated config and the
    ///     launch mode must always agree, even if TUN is toggled while a reload is in flight.
    /// </summary>
    public static bool ShouldRunAsSudo(bool isTunLaunch, ECoreType? coreType, bool isNonWindows)
    {
        return isTunLaunch
            && coreType is ECoreType.sing_box or ECoreType.mihomo or ECoreType.Xray
            && isNonWindows;
    }

    private async Task<ProcessService?> RunProcess(CoreInfo? coreInfo, string configPath, bool displayLog, bool mayNeedSudo, bool isTunLaunch = false)
    {
        // PattN: on Windows Xray's copy is checked against xray.exe, made equal to it and started in one hold, so that no
        // update changes either file in between (CoreInfoManager.HoldXrayFilesAsync); the hold ends as soon as the process
        // has started, as Windows then keeps the copy it runs from from being replaced
        using var xrayFiles = coreInfo?.CoreType == ECoreType.Xray && Utils.IsWindows()
            ? await CoreInfoManager.HoldXrayFilesAsync()
            : null;
        var fileName = CoreInfoManager.Instance.GetCoreExecFile(coreInfo, out var msg);
        if (fileName.IsNullOrEmpty())
        {
            await UpdateFunc(false, msg);
            return null;
        }

        try
        {
            if (mayNeedSudo
                && ShouldRunAsSudo(isTunLaunch, coreInfo.CoreType, Utils.IsNonWindows()))
            {
                _linuxSudo = true;
                await CoreAdminManager.Instance.Init(_config, _updateFunc);
                return await CoreAdminManager.Instance.RunProcessAsLinuxSudo(fileName, coreInfo, configPath);
            }

            return await RunProcessNormal(fileName, coreInfo, configPath, displayLog, xrayFiles);
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
            await UpdateFunc(mayNeedSudo, ex.Message);
            return null;
        }
    }

    // PattN: startHold, Xray's hold on its files on Windows, is let go of once the process has started
    private async Task<ProcessService?> RunProcessNormal(string fileName, CoreInfo? coreInfo, string configPath, bool displayLog, IDisposable? startHold = null)
    {
        var environmentVars = new Dictionary<string, string>();
        foreach (var kv in coreInfo.Environment)
        {
            environmentVars[kv.Key] = string.Format(kv.Value, coreInfo.AbsolutePath ? Utils.GetBinConfigPath(configPath).AppendQuotes() : configPath);
        }

        var procService = new ProcessService(
            fileName: fileName,
            arguments: string.Format(coreInfo.Arguments, coreInfo.AbsolutePath ? Utils.GetBinConfigPath(configPath).AppendQuotes() : configPath),
            workingDirectory: Utils.GetBinConfigPath(),
            displayLog: displayLog,
            redirectInput: false,
            environmentVars: environmentVars,
            updateFunc: _updateFunc
        );

        await procService.StartAsync();
        startHold?.Dispose();

        await Task.Delay(100);

        if (procService is null or { HasExited: true })
        {
            throw new Exception(ResUI.FailedToRunCore);
        }
        AddProcessJob(procService.Handle);

        return procService;
    }

    private void AddProcessJob(nint processHandle)
    {
        if (Utils.IsWindows())
        {
            _processJob ??= new();
            try
            {
                _processJob?.AddProcess(processHandle);
            }
            catch { }
        }
    }

    // PattN: an Aether core ends with PattN as the other cores do (the job object kills what it holds when PattN dies)
    internal void AddProcessJob(Process process)
    {
        try
        {
            AddProcessJob(process.Handle);
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
        {
            Logging.SaveLog(_tag, ex);
        }
    }

    #endregion Process

    #region PattN: Aether

    /// <summary>
    /// PattN: what LoadCore does for the Aether core of <paramref name="mainContext" />, once it was generated (design
    /// 2.6.4): see <see cref="AetherCoreLoad" />.
    /// </summary>
    private AetherCoreLoadSteps AetherLoadSteps(CoreConfigContext mainContext)
    {
        return new AetherCoreLoadSteps
        {
            Core = () => mainContext.Aether.Core,
            MissingCore = AetherCoreLoad.MissingCoreMessage,
            NewGeneration = _turns.NewGeneration,
            CancelProbes = () => AetherCoreManager.Instance.CancelProbesAsync(),
            ReapLeftovers = AetherCoreManager.Instance.ReapLeftovers,
            SecondaryPort = () => mainContext.Aether.SecondaryInboundPort,
            XrayUp = () => _processService is { HasExited: false },
            WaitForPort = AetherCoreLoad.WaitForPortAsync,
            StartSession = (core, generation) => AetherCoreManager.Instance.StartSessionAsync(core, generation),
            StopCores = CoreStopInTurn,
            Report = UpdateFunc,
        };
    }

    /// <summary>
    /// PattN: starts the short-lived Xray a scan or a key run of the Aether core dials out through (design 2.6.5), or the
    /// Xray of a latency test that needs an Aether core (design 2.12.2), on the configuration file
    /// <paramref name="configFileName" /> in binConfigs, without its output in the message view.
    /// </summary>
    public async Task<ProcessService?> RunAetherExitXrayAsync(string configFileName)
    {
        var coreInfo = CoreInfoManager.Instance.GetCoreInfo(ECoreType.Xray);
        return await RunProcess(coreInfo, configFileName, displayLog: false, mayNeedSudo: false);
    }

    /// <summary>
    /// PattN: Xray, the Aether core and the system proxy's way out run together or not at all (design 2.6.4, PattNG
    /// ReloadOutcome): when the session core exits on its own, the cores stop, and traffic sent to the system proxy fails
    /// rather than leave another way. A load or a stop that began since owns what runs, and is left alone (critique 15).
    /// </summary>
    private async Task OnAetherSessionEnded(AetherSessionEnded ended)
    {
        var stopped = await _turns.EndIfCurrentAsync(ended.Generation, async () =>
        {
            Logging.SaveLog("CoreManager: the Aether core exited while running, stopping the cores");
            await UpdateFunc(true, ended.Message);
            await CoreStopInTurn();
        });
        if (stopped && AetherCoresStopped is { } coresStopped)
        {
            await coresStopped(ended.Message);
        }
    }

    #endregion PattN: Aether
}

