using System.Threading.Channels;

namespace ServiceLib.Aether;

/// <summary>The session core ended on its own: the generation of the cores it was started with and what to tell the user.</summary>
public sealed record AetherSessionEnded(long Generation, int ExitCode, string Message);

/// <summary>What the wait for the session core to carry traffic ends with (PattNG AetherCoreManager.WarmUpOutcome).</summary>
public enum AetherWarmUpOutcome
{
    /// <summary>The listener answers; the profile can carry traffic.</summary>
    Listening,

    /// <summary>The core exited before its listener came up; the handler of <see cref="AetherCoreManager.SessionEnded" /> reports it.</summary>
    CoreExited,

    /// <summary>The wait was cancelled, or the session was stopped or replaced meanwhile; nothing is left to report.</summary>
    Abandoned,
}

/// <summary>How a core of its own (a test, a scan, a key run) went, see <see cref="AetherCoreManager.RunStandaloneAsync{T}" />.</summary>
public enum AetherRunOutcome
{
    /// <summary>The core ran, and the block gave its value.</summary>
    Done,

    /// <summary>
    /// A latency test found a scan or a key run at the exit, a load bringing up a session that will need the listen port,
    /// or a session that holds it already, and left without waiting (critique 9).
    /// </summary>
    Busy,

    /// <summary>
    /// The exit it dials out through did not open, so no core ran: it would have reached the internet without it. For a
    /// latency test, its own Xray did not come up.
    /// </summary>
    NoExit,

    /// <summary>
    /// The core could not start (design 2.4.4): its program could not be run, or it ended at once, without a line or for
    /// want of a DLL Windows did not find (<see cref="AetherCoreManager.CouldNotStart" />). What the user is told is
    /// ResUI.MsgAetherCoreCannotStart.
    /// </summary>
    NotStarted,

    /// <summary>
    /// Every core was stopped (<see cref="AetherCoreManager.StopAllAsync" />, when PattN exits), or held while the core's
    /// files are replaced (<see cref="AetherCoreManager.HoldAsync" />): before this one started, while it waited for its
    /// turn, or while it ran. The value is what the block gave before, if anything.
    /// </summary>
    Stopped,
}

public sealed record AetherRunResult<T>(AetherRunOutcome Outcome, T? Value = default);

/// <summary>Whether the Psiphon data could be cleared (PattNG clearPsiphonData).</summary>
public enum AetherPsiphonClear
{
    Cleared,
    Failed,

    /// <summary>A core runs, which holds a datastore under a lock: the session, or a test, scan or key run.</summary>
    Blocked,
}

/// <summary>
/// A core of its own: one that serves no session (PattNG withProcess). It dials out through the exit Xray opened for
/// <see cref="Exit" /> (a scan, a key run); a latency test's core brings its own Xray, <see cref="OwnXray" />, which its
/// arguments name with --upstream already, and has no <see cref="Exit" />.
/// </summary>
/// <param name="Arguments">The arguments of the core, without the program name.</param>
/// <param name="Role">Not <see cref="AetherRole.Session" />.</param>
public sealed record AetherStandaloneRun(IReadOnlyList<string> Arguments, AetherRole Role)
{
    /// <summary>The exit-node of the exit Xray the core dials out through; null when the run brings its own Xray.</summary>
    public AetherExit? Exit { get; init; }

    /// <summary>Where a key run writes the keys it registers; the working folder otherwise.</summary>
    public string? KeysDir { get; init; }

    /// <summary>Each line the core writes, as it comes, for the log panel of a window.</summary>
    public Action<string>? OnOutput { get; init; }

    /// <summary>
    /// Starts the Xray a latency test brings, which its core dials out through, once the run's turn has come and before
    /// the core starts, as an exit opens (PattNG withProcess with a configuration); null when it does not come up.
    /// Disposing what it gives stops it, once the core has ended, before the run is over: a stop of every core or a hold
    /// waits for it as it waits for an exit. Its token is the run's.
    /// </summary>
    public Func<CancellationToken, Task<IAsyncDisposable?>>? OwnXray { get; init; }
}

/// <summary>An exit Xray opened for a core of its own, see <see cref="AetherExitService" />; disposing it closes it.</summary>
public interface IAetherExit : IAsyncDisposable
{
    /// <summary>The loopback port of its secondary-socks inbound.</summary>
    int Port { get; }
}

/// <summary>What <see cref="AetherCoreManager" /> works with: PattN's own in <see cref="Default" />, fakes in tests.</summary>
public sealed class AetherCoreHost
{
    public required AetherFolders Folders { get; init; }

    /// <summary>Starts a core, see <see cref="AetherProcess.Start" />; throws when it cannot.</summary>
    public required Func<ProcessStartInfo, Action<string>, IAetherCoreProcess> Spawn { get; init; }

    /// <summary>The Aether listen port of the settings (<see cref="AetherPorts.ListenPortOf(int?)" />).</summary>
    public Func<int> ListenPort { get; init; } = () => AetherPorts.DefaultListenPort;

    /// <summary>The Xray log level of the app, which the session's core follows (design 2.6.2).</summary>
    public Func<string?> AppLogLevel { get; init; } = () => null;

    /// <summary>Opens the exit Xray of a scan or a key run; null when it does not open.</summary>
    public Func<AetherExit, AetherRole, CancellationToken, Task<IAetherExit?>> OpenExit { get; init; } =
        (_, _, _) => Task.FromResult<IAetherExit?>(null);

    /// <summary>Has a started core end with PattN (the Windows job object of CoreManager).</summary>
    public Action<IAetherCoreProcess>? Adopt { get; init; }

    /// <summary>Keeps Psiphon's report of the countries it can leave from (critique 33).</summary>
    public Action<IReadOnlyList<string>>? RememberRegions { get; init; }

    /// <summary>Whether cores leave pid files for a later start to find them by (Linux and macOS, design 2.6.6).</summary>
    public bool UsesPidFiles { get; init; }

    /// <summary>How long a kill waits for a core and what it started to be gone (PattNG EXIT_WAIT_MS).</summary>
    public TimeSpan ExitWait { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary>How long a session start waits for the core of a test, a scan or a key run to be gone (PattNG PROBE_EXIT_WAIT_MS).</summary>
    public TimeSpan ProbeExitWait { get; init; } = TimeSpan.FromSeconds(3);

    /// <summary>How long a test of the running configuration waits for its Aether core to carry traffic (<see cref="AetherCoreManager.TestBudget" />).</summary>
    public TimeSpan TestWait { get; init; } = AetherCoreManager.TestBudget;

    /// <summary>What PattN's own cores run with.</summary>
    public static AetherCoreHost Default()
    {
        return new AetherCoreHost
        {
            Folders = AetherFolders.Default(),
            Spawn = AetherProcess.Start,
            ListenPort = () => AetherPorts.ListenPortOf(ConfigTextHandler.Config?.CoreBasicItem?.AetherListenPort),
            AppLogLevel = () => ConfigTextHandler.Config?.CoreBasicItem?.Loglevel,
            OpenExit = (exit, role, ct) => AetherExitService.Default.OpenAsync(exit, AetherCoreManager.SourceOf(role), ct),
            Adopt = process =>
            {
                if (process is AetherProcess real)
                {
                    CoreManager.Instance.AddProcessJob(real.Process);
                }
            },
            RememberRegions = RememberInConfig,
            UsesPidFiles = Utils.IsNonWindows(),
        };
    }

    private static void RememberInConfig(IReadOnlyList<string> regions)
    {
        var config = ConfigTextHandler.Config;
        if (config == null)
        {
            return;
        }
        config.AetherItem ??= new();
        if (PsiphonServerList.Remember(config.AetherItem, regions))
        {
            _ = ConfigTextHandler.SaveConfig();
        }
    }
}

/// <summary>
/// The live session core: what it was started with, and what its output has said so far (PattNG AetherCoreManager.Session).
/// </summary>
public sealed class AetherSession
{
    private volatile bool _wordSeen;
    private volatile bool _noEchKey;
    private volatile bool _hadOutput;
    private volatile string? _lastError;

    // The process and the chain's end, which its first lines may report before it is attached.
    private readonly object _processGate = new();
    private IAetherCoreProcess? _process;
    private string? _chainEnd;

    internal AetherSession(AetherCore core, IReadOnlyList<string> arguments, long generation)
    {
        Core = core;
        Arguments = arguments;
        Generation = generation;
        NeedsWord = AetherArguments.ReadyNeedsWord(arguments) && AetherArguments.ShowsInfo(arguments);
        _wordSeen = !NeedsWord;
    }

    /// <summary>The core as the configuration needs it: dialling out through Xray, without a log level.</summary>
    public AetherCore Core { get; }

    /// <summary>The arguments the process was started with: at the session's log level, the shipped Psiphon list in place.</summary>
    public IReadOnlyList<string> Arguments { get; }

    /// <summary>The generation of the cores this session was started with, see <see cref="AetherCoreTurns" />.</summary>
    public long Generation { get; }

    /// <summary>The loopback port Xray's Aether outbounds dial.</summary>
    public int Port => Core.Port;

    /// <summary>The key of the exit-node the core dials out through, see <see cref="AetherExit.Key" />.</summary>
    public string ExitKey => Core.Exit.Key;

    public AetherProtocol Protocol => Core.Protocol;

    /// <summary>
    /// Whether the listener the app dials is Psiphon's, which may answer the SOCKS greeting before it carries anything
    /// (<see cref="AetherLogLine.IsReadyWord" />), so that readiness needs the core's word as well; false when the core
    /// writes no info line to say it.
    /// </summary>
    public bool NeedsWord { get; }

    /// <summary>Whether the core has said that Psiphon carries traffic; true from the start where no word is needed.</summary>
    public bool WordSeen => _wordSeen;

    /// <summary>Whether the core said it stopped for want of an ECH key.</summary>
    public bool NoEchKey => _noEchKey;

    /// <summary>The last error line the core wrote ("Error: ..."), the one it stops on; null without one.</summary>
    public string? LastError => _lastError;

    /// <summary>
    /// The core's words that Tor or Psiphon inside the tunnel had ended, for which PattN ended it (see
    /// <see cref="AetherLogLine.ChainEndWords" />); null otherwise.
    /// </summary>
    public string? ChainEnd
    {
        get
        {
            lock (_processGate)
            {
                return _chainEnd;
            }
        }
    }

    internal bool HadOutput => _hadOutput;
    internal Stopwatch Lifetime { get; } = Stopwatch.StartNew();

    /// <summary>The process of the session, once it is spawned and attached (<see cref="Attach" />).</summary>
    internal IAetherCoreProcess? Process
    {
        get
        {
            lock (_processGate)
            {
                return _process;
            }
        }
    }

    /// <summary>
    /// Attaches the spawned <paramref name="process" />; returns it when the core has said meanwhile, among its first
    /// lines, that Tor or Psiphon inside the tunnel ended (<see cref="Saw" />), for the caller to end it.
    /// </summary>
    internal IAetherCoreProcess? Attach(IAetherCoreProcess process)
    {
        lock (_processGate)
        {
            _process = process;
            return _chainEnd != null ? process : null;
        }
    }

    /// <summary>Set when PattN stops the session; an exit then is no exit on its own.</summary>
    internal bool StopRequested { get; set; }

    /// <summary>
    /// Whether a scan of <paramref name="protocol" /> would disturb this session: it opens a second tunnel on the key of
    /// that protocol (PattNG AetherSession.disturbedByScanOf).
    /// </summary>
    public bool DisturbedByScanOf(AetherProtocol protocol)
    {
        return AetherIdentityManager.SharesIdentity(protocol, Protocol);
    }

    /// <summary>
    /// Whether this session uses a key that new keys of <paramref name="kind" /> would replace (PattNG
    /// AetherSession.usesKeysOf); the keys of the other protocols can change under it.
    /// </summary>
    public bool UsesKeysOf(AetherKeyKind kind)
    {
        return AetherIdentityManager.UsesKeysOf(Protocol, kind);
    }

    /// <summary>
    /// Reads a line of the core's output. When it says that Tor or Psiphon inside the tunnel ended, the core goes on
    /// without the listener Xray dials, which another program may hold then: the process is returned for the caller to
    /// end, once it is attached (<see cref="Attach" /> returns it otherwise). Null for every other line.
    /// </summary>
    internal IAetherCoreProcess? Saw(string line)
    {
        _hadOutput = true;
        if (!_wordSeen && AetherLogLine.IsReadyWord(line))
        {
            _wordSeen = true;
        }
        if (AetherLogLine.IsNoEchKeyWord(line))
        {
            _noEchKey = true;
        }
        var text = line.Trim();
        if (AetherLogLine.IsFatalError(text))
        {
            _lastError = text;
        }
        if (AetherLogLine.ChainEndWords(text, Arguments) is not { } words)
        {
            return null;
        }
        lock (_processGate)
        {
            if (_chainEnd != null)
            {
                return null;
            }
            _chainEnd = words;
            return _process;
        }
    }
}

/// <summary>
/// Owns the Aether cores PattN runs (design 2.6.3, PattNG core/AetherCoreManager.kt): one live session at a time, which
/// CoreManager starts after Xray and stops before it, and reports through <see cref="SessionEnded" /> when it exits on its
/// own; cores of their own for tests, scans and key runs, which take turns at the exit; the readiness of a listener; and
/// the relay of every core's output to the message view. Nothing here watches a running core: its exit is the process's
/// exit event, and the only waits are bounded ones while a core comes up.
/// </summary>
public sealed class AetherCoreManager
{
    /// <summary>How long a readiness probe waits to connect, and then for the answer (PattNG PROBE_TIMEOUT_MS).</summary>
    public static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(1);

    /// <summary>How often the readiness of a starting core is looked at (PattNG READY_POLL_MS).</summary>
    public static readonly TimeSpan ReadyPoll = TimeSpan.FromMilliseconds(500);

    /// <summary>One round of the wait for a session to carry traffic; it goes on round after round while the session lives (PattNG AETHER_WARM_UP_MS).</summary>
    public static readonly TimeSpan WarmUpRound = TimeSpan.FromSeconds(30);

    /// <summary>The budget of a latency test, the start of its tunnel included: the same as other profiles' (PattNG TEST_BUDGET_MS).</summary>
    public static readonly TimeSpan TestBudget = TimeSpan.FromSeconds(12);

    /// <summary>A core that ends within this time without a word did not really start (design 2.4.4).</summary>
    public static readonly TimeSpan StartWindow = TimeSpan.FromSeconds(1);

    /// <summary>The questions of <see cref="AnswersSocksAsync" />, with the connections they keep waiting, one per port, for the whole process.</summary>
    private static readonly AetherSocksAnswers SocksAnswers = new(ProbeTimeout);

    private static readonly Lazy<AetherCoreManager> _instance = new(() => new AetherCoreManager(AetherCoreHost.Default()));

    private readonly AetherCoreHost _host;
    private readonly object _gate = new();

    /// <summary>
    /// Session starts and stops, the end of a core that exited on its own, and a hold, one after another: a start comes up
    /// only once the old core and its helpers are gone.
    /// </summary>
    private readonly SemaphoreSlim _lifecycle = new(1, 1);

    /// <summary>One core of its own at a time (PattNG exitTurns): scans and key runs wait their turn, tests do not (critique 9).</summary>
    private readonly SemaphoreSlim _exitTurns = new(1, 1);

    private AetherSession? _session;
    private Standalone? _run;
    private string _stoppedMessage = ResUI.MsgAetherCoreStopped;

    /// <summary>
    /// Set from <see cref="CancelProbesAsync" /> until the session that load starts is there or the load is over
    /// (<see cref="EndSessionStart" />): a latency test's core started meanwhile would take the listen port the session is
    /// about to need (PattNG cancels the test service as a whole and checks again before the spawn). Under <see cref="_gate" />.
    /// </summary>
    private bool _sessionStarting;

    /// <summary>How many holds of <see cref="HoldAsync" /> last: no core of its own starts while one does. Under <see cref="_gate" />.</summary>
    private int _holds;

    /// <summary>
    /// Replaced by every <see cref="StopAllAsync" />, and cancelled then: a core of its own waiting for its turn at the
    /// exit gives up, and one whose turn came gives it back, rather than start once every core was meant to be gone.
    /// Under <see cref="_gate" />.
    /// </summary>
    private CancellationTokenSource _stopAll = new();

    public AetherCoreManager(AetherCoreHost host)
    {
        _host = host;
    }

    public static AetherCoreManager Instance => _instance.Value;

    /// <summary>The loopback port every Aether core listens on unless its command names another (PattNG socksPort).</summary>
    public int ListenPort => _host.ListenPort();

    /// <summary>The port of Xray's secondary-socks inbound a session's core dials out through: three above <see cref="ListenPort" />.</summary>
    public int SecondarySocksPort => AetherPorts.SecondarySocksPortOf(ListenPort);

    /// <summary>The live session, scanning or connected; null without one.</summary>
    public AetherSession? Session => Volatile.Read(ref _session);

    public bool IsRunning => Session != null;

    /// <summary>
    /// The process id of the session's core, which the WebAPI tracks as a core it started; null without one. The cores
    /// of tests, scans and key runs run the same program and are none of the session's.
    /// </summary>
    public int? SessionProcessId
    {
        get
        {
            try
            {
                return Session?.Process?.Id;
            }
            catch (InvalidOperationException)
            {
                return null;
            }
        }
    }

    /// <summary>Whether a load that needs an Aether core is under way and its session is not there yet (<see cref="CancelProbesAsync" />).</summary>
    public bool SessionStarting
    {
        get
        {
            lock (_gate)
            {
                return _sessionStarting;
            }
        }
    }

    /// <summary>Whether a core of its own (a test, a scan, a key run) holds the exit.</summary>
    public bool IsStandaloneRunning => Volatile.Read(ref _run) != null;

    /// <summary>
    /// Where every core's output goes, a line at a time, as "[source] message": the message view (CoreManager.Init sets
    /// it). The label tells the session's core (aether) from those of tests, scans and key runs.
    /// </summary>
    public Func<string, Task>? Relay { get; set; }

    /// <summary>
    /// Raised when the session core exits on its own, never when PattN stops it. Xray, the Aether core and the system
    /// proxy's way out run together or not at all (PattNG ReloadOutcome), so CoreManager stops Xray then.
    /// </summary>
    public event Func<AetherSessionEnded, Task>? SessionEnded;

    /// <summary>
    /// Raised, on the thread that made the change, whenever <see cref="Session" /> becomes another one or none: a session
    /// starts, is stopped, or exits on its own (design 3.2.5). The Aether editor follows it, as PattNG's re-reads the
    /// session when it comes back to the screen, since a session can start or stop while the editor is open; nothing
    /// polls for it.
    /// </summary>
    public event Action? SessionChanged;

    /// <summary>The label of the output of a core of <paramref name="role" /> (design 2.14).</summary>
    public static string SourceOf(AetherRole role)
    {
        return role switch
        {
            AetherRole.Test => "aether-test",
            AetherRole.Scan => AetherScanner.Source,
            AetherRole.Key => AetherIdentityManager.Source,
            _ => "aether",
        };
    }

    #region session

    /// <summary>
    /// Starts the session core <paramref name="core" />, which already dials out through Xray, after the session before it
    /// is gone, at the app's log level unless its command names one. <paramref name="generation" /> is the generation of
    /// the cores it starts with, which <see cref="SessionEnded" /> gives back. Null once the process runs; the localized
    /// reason otherwise.
    /// </summary>
    public async Task<string?> StartSessionAsync(AetherCore core, long generation = 0, CancellationToken ct = default)
    {
        await _lifecycle.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await EndSessionAsync().ConfigureAwait(false);
            // The ready word is an info line; a quieter setting must not leave a Psiphon session waiting for it.
            var level = AetherArguments.SessionLogLevel(core.Arguments, _host.AppLogLevel());
            IReadOnlyList<string> arguments;
            try
            {
                arguments = PrepareArguments(AetherArguments.WithLogLevel(core.Arguments, level));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Logging.SaveLog("AetherCore: the working folder of the core could not be prepared", ex);
                return ResUI.MsgAetherCoreCannotStart;
            }
            var session = new AetherSession(core, arguments, generation);
            lock (_gate)
            {
                _session = session;
                _sessionStarting = false;
            }
            RaiseSessionChanged();
            IAetherCoreProcess process;
            try
            {
                PsiphonStateDir(_host.Folders.ConfigDir, _host.Folders.WorkDir);
                ReapLeftovers();
                process = _host.Spawn(AetherProcess.StartInfo(_host.Folders, arguments, AetherRole.Session), line =>
                {
                    var ended = session.Saw(line);
                    RelayLine(SourceOf(AetherRole.Session), line);
                    if (ended != null)
                    {
                        EndForChain(session, ended);
                    }
                });
                // A core that ends at once without a word did not start (design 2.4.4): its time counts from its spawn,
                // not from the work before it, a leftover core killed and waited for among it.
                session.Lifetime.Restart();
            }
            catch (Exception ex) when (IsStartFailure(ex))
            {
                Logging.SaveLog("AetherCore: failed to launch the core", ex);
                lock (_gate)
                {
                    if (_session == session)
                    {
                        _session = null;
                    }
                }
                RaiseSessionChanged();
                return ResUI.MsgAetherCoreCannotStart;
            }
            var endedEarly = session.Attach(process);
            _host.Adopt?.Invoke(process);
            if (_host.UsesPidFiles)
            {
                AetherLeftovers.Write(_host.Folders.SessionPidFile, process);
            }
            _ = WatchAsync(session, process);
            if (endedEarly != null)
            {
                EndForChain(session, endedEarly);
            }
            return null;
        }
        finally
        {
            _lifecycle.Release();
        }
    }

    /// <summary>
    /// Ends the core <paramref name="process" /> of <paramref name="session" /> once Tor or Psiphon inside the tunnel ended
    /// (<see cref="AetherSession.ChainEnd" />): an aether-core before 2.3.4 goes on without the listener Xray dials then,
    /// and a later one ends on its own as well. Its exit then ends the session as an exit on its own does, Xray with it
    /// (<see cref="WatchAsync" />; PattNG AetherCoreManager.watch). A session PattN stopped, or one a new start replaced,
    /// has had its core ended already.
    /// </summary>
    private void EndForChain(AetherSession session, IAetherCoreProcess process)
    {
        if (session.StopRequested)
        {
            return;
        }
        Logging.SaveLog("AetherCore: ending the session core, Tor or Psiphon inside the tunnel has ended");
        _ = EndProcessAsync(process, SourceOf(AetherRole.Session));
    }

    /// <summary>Stops the session core and whatever it started, and waits for them; raises nothing.</summary>
    public async Task StopSessionAsync()
    {
        await _lifecycle.WaitAsync().ConfigureAwait(false);
        try
        {
            await EndSessionAsync().ConfigureAwait(false);
        }
        finally
        {
            _lifecycle.Release();
        }
    }

    /// <summary>
    /// Waits up to <paramref name="timeout" /> until the live session carries traffic: its listener answers the SOCKS
    /// greeting, and the core has said so where that is not enough (Psiphon). False when there is no session, it ends or
    /// is replaced meanwhile, or the time is up.
    /// </summary>
    public Task<bool> AwaitListeningAsync(TimeSpan timeout, CancellationToken ct = default)
    {
        var session = Session;
        return session == null ? Task.FromResult(false) : AwaitListeningAsync(session, timeout, ct);
    }

    /// <summary>
    /// Waits for <paramref name="session" /> to carry traffic in rounds of <see cref="WarmUpRound" />, round after round
    /// while it lives: a scan may take minutes (PattNG announceAetherWarmUp). Bounded by the session itself, which ends
    /// on its own, or is stopped or replaced.
    /// </summary>
    public async Task<AetherWarmUpOutcome> AwaitWarmUpAsync(AetherSession session, CancellationToken ct = default)
    {
        var listening = false;
        while (!ct.IsCancellationRequested && !listening && IsCurrent(session))
        {
            listening = await AwaitListeningAsync(session, WarmUpRound, ct).ConfigureAwait(false);
        }
        return WarmUpOutcome(listening, active: !ct.IsCancellationRequested && !session.StopRequested, serviceRunning: true);
    }

    /// <summary>
    /// Why the running configuration cannot be tested now (critique 20, PattNG measureV2rayDelay): its Aether core still
    /// connecting after a test's budget of waiting, or gone meanwhile; null when it carries traffic or no session runs.
    /// As PattNG's awaitListening, the wait follows whichever session is the live one: a reload that replaces the session
    /// meanwhile leaves its new core connecting, not stopped, and so does the moment between the two sessions of a load.
    /// </summary>
    public async Task<string?> AwaitTestableAsync(CancellationToken ct = default)
    {
        if (Session == null)
        {
            return null;
        }
        var listening = await AwaitReadyAsync(
            _host.TestWait,
            ReadyPoll,
            () => IsRunning || SessionStarting,
            async token => Session is { } current && current.WordSeen && await AnswersSocksAsync(current.Port, token).ConfigureAwait(false),
            ct).ConfigureAwait(false);
        if (listening)
        {
            return null;
        }
        return IsRunning || SessionStarting ? ResUI.MsgAetherConnecting : ResUI.MsgAetherCoreStopped;
    }

    /// <summary>What to tell the user of the session core that ended on its own last, in the words it ended with.</summary>
    public string StoppedMessage()
    {
        lock (_gate)
        {
            return _stoppedMessage;
        }
    }

    #endregion session

    #region cores of their own

    /// <summary>
    /// Runs a core of its own (PattNG withProcess): it takes its turn at the exit, a latency test only when the exit is
    /// free (critique 9), the exit Xray of <see cref="AetherStandaloneRun.Exit" />, or the test's own
    /// (<see cref="AetherStandaloneRun.OwnXray" />), opens before the core starts and closes once it has ended, and
    /// <paramref name="block" /> reads the core's lines while it runs. The core and what it started are killed once
    /// <paramref name="block" /> is over, however it ends. A test's run is a probe that a session start cancels
    /// (<see cref="CancelProbesAsync" />: its block's token is cancelled, and <see cref="OperationCanceledException" />
    /// comes out), and none starts while that start is under way or beside a session. A stop of every core
    /// (<see cref="StopAllAsync" />) or a hold (<see cref="HoldAsync" />) ends a run, or keeps it from starting, with
    /// <see cref="AetherRunOutcome.Stopped" />. Only a cancellation of <paramref name="ct" /> throws
    /// <see cref="OperationCanceledException" /> for a scan or a key run.
    /// </summary>
    public async Task<AetherRunResult<T>> RunStandaloneAsync<T>(
        AetherStandaloneRun run,
        Func<ChannelReader<string>, CancellationToken, Task<T?>> block,
        CancellationToken ct = default)
    {
        if (run.Role == AetherRole.Session)
        {
            throw new ArgumentException("A session core is no core of its own", nameof(run));
        }
        CancellationTokenSource stopAll;
        lock (_gate)
        {
            if (_holds > 0)
            {
                // The core's files are being replaced.
                return new AetherRunResult<T>(AetherRunOutcome.Stopped);
            }
            stopAll = _stopAll;
        }
        using (var waiting = CancellationTokenSource.CreateLinkedTokenSource(ct, stopAll.Token))
        {
            try
            {
                if (run.Role == AetherRole.Test)
                {
                    // A scan or a key run may take minutes; a test does not wait for it, and leaves its row untested.
                    if (!await _exitTurns.WaitAsync(0, waiting.Token).ConfigureAwait(false))
                    {
                        return new AetherRunResult<T>(AetherRunOutcome.Busy);
                    }
                }
                else
                {
                    await _exitTurns.WaitAsync(waiting.Token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                // Every core was stopped while this one waited for its turn.
                return new AetherRunResult<T>(AetherRunOutcome.Stopped);
            }
        }
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var state = new Standalone(run.Role, cancellation);
        AetherRunOutcome? refused = null;
        lock (_gate)
        {
            if (_holds > 0 || _stopAll != stopAll)
            {
                refused = AetherRunOutcome.Stopped;
            }
            else if (run.Role == AetherRole.Test && (_sessionStarting || _session != null))
            {
                // A session is about to take the listen port this test's core would hold, or holds it already: one that
                // started after the test chose a tunnel of its own. The row is left untested; PattNG cancels the tests
                // of every start.
                refused = AetherRunOutcome.Busy;
            }
            else
            {
                _run = state;
            }
        }
        if (refused is { } outcome)
        {
            _exitTurns.Release();
            return new AetherRunResult<T>(outcome);
        }
        try
        {
            IAetherExit? exit = null;
            IAsyncDisposable? ownXray = null;
            var (opened, result) = await InExitAsync(
                async () =>
                {
                    if (run.OwnXray != null)
                    {
                        ownXray = await run.OwnXray(cancellation.Token).ConfigureAwait(false);
                        return ownXray == null ? null : 0;
                    }
                    if (run.Exit == null)
                    {
                        return 0;
                    }
                    exit = await _host.OpenExit(run.Exit, run.Role, cancellation.Token).ConfigureAwait(false);
                    return exit?.Port;
                },
                async () =>
                {
                    if (ownXray != null)
                    {
                        await ownXray.DisposeAsync().ConfigureAwait(false);
                    }
                    if (exit != null)
                    {
                        await exit.DisposeAsync().ConfigureAwait(false);
                    }
                },
                port => RunCoreAsync(
                    state,
                    run,
                    port == 0 ? run.Arguments : AetherArguments.StandaloneArguments(run.Arguments, port),
                    block,
                    cancellation.Token),
                cancellation.Token).ConfigureAwait(false);
            if (state.StoppedWithAll)
            {
                return new AetherRunResult<T>(AetherRunOutcome.Stopped, result is { } given ? given.Value : default);
            }
            if (!opened)
            {
                Logging.SaveLog(run.Exit != null
                    ? $"AetherCore: the exit-node {SourceOf(run.Role)} dials out through gives no outbound: no profile or several have its name, it gives none, or its ECH outbound is unusable; no core runs"
                    : $"AetherCore: the Xray {SourceOf(run.Role)} dials out through did not come up; no core runs");
                return new AetherRunResult<T>(AetherRunOutcome.NoExit);
            }
            return result!;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested && state.StoppedWithAll)
        {
            // Every core was stopped while this one ran: no cancellation its caller asked for.
            Logging.SaveLog($"AetherCore: the {SourceOf(run.Role)} core was stopped with every other core");
            return new AetherRunResult<T>(AetherRunOutcome.Stopped);
        }
        finally
        {
            Volatile.Write(ref _run, null);
            state.Ended.TrySetResult();
            _exitTurns.Release();
        }
    }

    /// <summary>
    /// Runs a core of its own (<see cref="RunStandaloneAsync{T}" />) until a line of its output gives what
    /// <paramref name="match" /> looks for (PattNG runUntil): a scan until it names its endpoint, a key run until it says
    /// its keys are saved. The value is null when the core ends first, or when <paramref name="timeout" />, counted from
    /// the core's start, passes first; a core that ended at once gives <see cref="AetherRunOutcome.NotStarted" />, and a
    /// stop of every core <see cref="AetherRunOutcome.Stopped" />. Only a cancellation of <paramref name="ct" /> throws
    /// <see cref="OperationCanceledException" />.
    /// </summary>
    public Task<AetherRunResult<T>> RunUntilAsync<T>(
        AetherStandaloneRun run,
        TimeSpan timeout,
        Func<string, T?> match,
        CancellationToken ct = default)
        where T : class
    {
        return RunStandaloneAsync(run, (lines, token) => FirstMatchAsync(lines, match, timeout, token), ct);
    }

    /// <summary>
    /// The first of <paramref name="lines" /> that <paramref name="match" /> gives a value for; null when the lines end
    /// (the core exited) or <paramref name="timeout" /> passes first. A cancellation of <paramref name="ct" /> throws.
    /// </summary>
    public static async Task<T?> FirstMatchAsync<T>(
        ChannelReader<string> lines,
        Func<string, T?> match,
        TimeSpan timeout,
        CancellationToken ct = default)
        where T : class
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(timeout);
        try
        {
            await foreach (var line in lines.ReadAllAsync(deadline.Token).ConfigureAwait(false))
            {
                if (match(line) is { } found)
                {
                    return found;
                }
            }
            return null;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            // The time is up.
            return null;
        }
    }

    /// <summary>
    /// For a load whose configuration needs an Aether core: cancels the core of a latency test, which holds the Aether
    /// listen port the session needs, and waits up to <paramref name="wait" /> (3 s by default) for whatever core of its
    /// own runs to be gone (PattNG afterProbes): a scan or a key run is not cancelled, and the session starts beside it
    /// after the wait. Until the session is there, or the load calls <see cref="EndSessionStart" />, a latency test finds
    /// its run busy rather than start a core on that port.
    /// </summary>
    public async Task CancelProbesAsync(TimeSpan? wait = null)
    {
        Standalone? run;
        lock (_gate)
        {
            _sessionStarting = true;
            run = _run;
        }
        if (run == null)
        {
            return;
        }
        if (run.Role == AetherRole.Test)
        {
            run.Cancel();
        }
        if (!await run.EndsWithinAsync(wait ?? _host.ProbeExitWait).ConfigureAwait(false))
        {
            Logging.SaveLog("AetherCore: a core of a test or scan is still up; the session starts beside it");
        }
    }

    /// <summary>The load <see cref="CancelProbesAsync" /> was called for is over, with its session or without one.</summary>
    public void EndSessionStart()
    {
        lock (_gate)
        {
            _sessionStarting = false;
        }
    }

    /// <summary>
    /// Ends every Aether core PattN runs, the session's and a core of its own, and waits for them: when PattN exits. A
    /// scan or a key run waiting for its turn at the exit gives up, rather than start once the others are gone; it and the
    /// one that ran end with <see cref="AetherRunOutcome.Stopped" />.
    /// </summary>
    public async Task StopAllAsync()
    {
        await StopSessionAsync().ConfigureAwait(false);
        await StopRunsAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Ends every Aether core PattN runs, as <see cref="StopAllAsync" /> does, and keeps any from starting until the hold
    /// it returns is disposed: while the core's files are replaced (a running program's file is locked on Windows). A
    /// session start meanwhile waits for the hold to end; a test, a scan or a key run does not start
    /// (<see cref="AetherRunOutcome.Stopped" />). The run that is ended closes its exit Xray, or a test's own Xray, before
    /// it is over, and the hold waits for that as it waits for the core, so that Xray's files can be replaced under it too.
    /// </summary>
    public async Task<IAsyncDisposable> HoldAsync()
    {
        lock (_gate)
        {
            _holds++;
        }
        var lifecycleTaken = false;
        try
        {
            await _lifecycle.WaitAsync().ConfigureAwait(false);
            lifecycleTaken = true;
            await EndSessionAsync().ConfigureAwait(false);
            await StopRunsAsync().ConfigureAwait(false);
            return new Hold(this);
        }
        catch
        {
            if (lifecycleTaken)
            {
                _lifecycle.Release();
            }
            lock (_gate)
            {
                _holds--;
            }
            throw;
        }
    }

    /// <summary>
    /// Forgets what the Psiphon client has learned (PattNG clearPsiphonData): its datastores and the countries it reported.
    /// Refused while a core runs, which holds a datastore under a lock.
    /// </summary>
    public AetherPsiphonClear ClearPsiphonData()
    {
        if (IsRunning || IsStandaloneRunning)
        {
            return AetherPsiphonClear.Blocked;
        }
        if (!ClearPsiphonState(_host.Folders.ConfigDir, _host.Folders.WorkDir))
        {
            return AetherPsiphonClear.Failed;
        }
        _host.RememberRegions?.Invoke([]);
        return AetherPsiphonClear.Cleared;
    }

    #endregion cores of their own

    #region pure parts

    /// <summary>
    /// Waits until <paramref name="listening" /> holds, looking every <paramref name="poll" /> while
    /// <paramref name="running" /> holds, for at most <paramref name="timeout" /> (PattNG awaitReady); false when the core
    /// stops or the time is up. A cancellation of <paramref name="ct" /> throws.
    /// </summary>
    public static async Task<bool> AwaitReadyAsync(
        TimeSpan timeout,
        TimeSpan poll,
        Func<bool> running,
        Func<CancellationToken, Task<bool>> listening,
        CancellationToken ct = default)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(timeout);
        try
        {
            while (running())
            {
                if (await listening(deadline.Token).ConfigureAwait(false))
                {
                    return true;
                }
                await Task.Delay(poll, deadline.Token).ConfigureAwait(false);
            }
            return false;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return false;
        }
    }

    /// <summary>
    /// True when a SOCKS server answers on the loopback <paramref name="port" /> (PattNG answersSocks): the connection is
    /// taken and the greeting gets its reply. A listener bound before anything serves it, as Tor's is bound before Tor has
    /// bootstrapped, takes the connection into its backlog and says nothing, so it does not count until it does; one that
    /// closes every connection, as Psiphon's does until it has a tunnel, does not count either. The whole reply to the
    /// greeting is read, the version and a method the greeting allows: two probes of loopback ports nothing listens on can
    /// be connected to each other by a simultaneous open when each was given the other's port to dial from, and each then
    /// reads the other's greeting, which begins with the version as well. A connection to itself
    /// (<see cref="AetherCoreLoad.IsSelfConnect" />, D6) is closed unasked, as no answer. A greeting that got no answer yet
    /// is kept waiting for the next question about that port, and questions asked at the same time share one answer
    /// (<see cref="AetherSocksAnswers" />): a backlog never fills with dead connections. A cancellation of
    /// <paramref name="ct" /> throws.
    /// </summary>
    public static Task<bool> AnswersSocksAsync(int port, CancellationToken ct = default)
    {
        return SocksAnswers.AnswersAsync(port, ct);
    }

    /// <summary>
    /// What the warm-up wait reports (PattNG warmUpOutcome): a listener, a core that died before its listener came up while
    /// the service still runs (which its exit reports as well), or nothing once the wait or the service is over.
    /// </summary>
    public static AetherWarmUpOutcome WarmUpOutcome(bool listening, bool active, bool serviceRunning)
    {
        if (!active || !serviceRunning)
        {
            return AetherWarmUpOutcome.Abandoned;
        }
        return listening ? AetherWarmUpOutcome.Listening : AetherWarmUpOutcome.CoreExited;
    }

    /// <summary>
    /// What to tell the user of a session core that ended on its own, or was ended as Tor or Psiphon inside the tunnel had
    /// ended (<paramref name="chainEnd" />, the core's words), in the words it ended with (PattNG stoppedMessage): for want
    /// of an ECH key, with the error it stopped on (critique 30), or plainly.
    /// </summary>
    public static string StoppedMessage(bool noEchKey, string? lastError = null, string? chainEnd = null)
    {
        if (chainEnd != null)
        {
            return string.Format(ResUI.MsgAetherCoreStoppedChainEnded, chainEnd);
        }
        if (noEchKey)
        {
            return ResUI.MsgAetherCoreStoppedNoEchKey;
        }
        return lastError == null ? ResUI.MsgAetherCoreStopped : string.Format(ResUI.MsgAetherCoreStoppedWithError, lastError);
    }

    /// <summary>
    /// Whether a core that exited with <paramref name="exitCode" /> after <paramref name="lifetime" /> never really started
    /// (design 2.4.4): Windows did not find a DLL it needs, or it ended at once without a word.
    /// </summary>
    public static bool CouldNotStart(int exitCode, TimeSpan lifetime, bool hadOutput)
    {
        return exitCode == AetherProcess.DllNotFoundExitCode || (!hadOutput && lifetime < StartWindow);
    }

    /// <summary>
    /// <paramref name="run" /> with the port of the exit <paramref name="open" /> opens, taking its turn by
    /// <paramref name="turns" />; nothing runs when it does not open, and <paramref name="close" /> closes it once
    /// <paramref name="run" /> is over, however it ends (PattNG throughExit). An exit that opens after a cancellation landed
    /// is closed all the same, with nothing run through it.
    /// </summary>
    public static async Task<T?> ThroughExitAsync<T>(
        SemaphoreSlim turns,
        Func<Task<int?>> open,
        Func<Task> close,
        Func<int, Task<T?>> run,
        CancellationToken ct = default)
    {
        await turns.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            return (await InExitAsync(open, close, run, ct).ConfigureAwait(false)).Value;
        }
        finally
        {
            turns.Release();
        }
    }

    /// <summary>
    /// Where the Psiphon client of the session keeps its datastore: guiConfigs/psiphon, beside the working folder rather
    /// than inside it (PattNG psiphonStateDir). A datastore the core put inside the working folder moves out once.
    /// </summary>
    public static string PsiphonStateDir(string configDir, string workDir)
    {
        var dir = Path.Combine(configDir, AetherPaths.PsiphonStateDirName);
        var inside = Path.Combine(workDir, AetherPaths.PsiphonInsideDirName);
        try
        {
            if (!Directory.Exists(dir) && Directory.Exists(inside))
            {
                Directory.Move(inside, dir);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Logging.SaveLog("AetherCoreManager: the Psiphon datastore could not leave the identity directory; the client starts over", ex);
        }
        return dir;
    }

    /// <summary>Where the Psiphon client of a test, a scan or a key run keeps its datastore (PattNG psiphonProbeDir).</summary>
    public static string PsiphonProbeDir(string configDir)
    {
        return Path.Combine(configDir, AetherPaths.PsiphonProbeDirName);
    }

    /// <summary>
    /// Removes what the Psiphon client has learned: the session's datastore, one still inside the working folder, and the
    /// one the probes keep (PattNG clearPsiphonState). For when no core runs. True when all are gone.
    /// </summary>
    public static bool ClearPsiphonState(string configDir, string workDir)
    {
        string[] dirs =
        [
            Path.Combine(configDir, AetherPaths.PsiphonStateDirName),
            Path.Combine(workDir, AetherPaths.PsiphonInsideDirName),
            PsiphonProbeDir(configDir),
        ];
        foreach (var dir in dirs)
        {
            try
            {
                if (Directory.Exists(dir))
                {
                    Directory.Delete(dir, recursive: true);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Logging.SaveLog("AetherCoreManager: Psiphon data could not be cleared", ex);
            }
        }
        return dirs.All(dir => !Directory.Exists(dir));
    }

    #endregion pure parts

    #region private

    private static async Task<(bool Opened, T? Value)> InExitAsync<T>(
        Func<Task<int?>> open,
        Func<Task> close,
        Func<int, Task<T?>> run,
        CancellationToken ct)
    {
        // A cancellation can land while the exit opens; whether it opened is kept, so that it is closed on that path too.
        var opened = false;
        try
        {
            var port = await open().ConfigureAwait(false);
            if (port is not { } exitPort)
            {
                return (false, default);
            }
            opened = true;
            ct.ThrowIfCancellationRequested();
            return (true, await run(exitPort).ConfigureAwait(false));
        }
        finally
        {
            if (opened)
            {
                await close().ConfigureAwait(false);
            }
        }
    }

    private async Task<AetherRunResult<T>> RunCoreAsync<T>(
        Standalone state,
        AetherStandaloneRun run,
        IReadOnlyList<string> arguments,
        Func<ChannelReader<string>, CancellationToken, Task<T?>> block,
        CancellationToken ct)
    {
        var source = SourceOf(run.Role);
        var output = Channel.CreateUnbounded<string>(new UnboundedChannelOptions { SingleReader = true });
        // Whether the core wrote a line, and how long after its spawn it exited (-1 while it runs): a core that ends at
        // once without a line did not start (design 2.4.4), as the session's does not.
        var hadOutput = 0;
        var exitedAfterTicks = -1L;
        IAetherCoreProcess process;
        try
        {
            ct.ThrowIfCancellationRequested();
            arguments = PrepareArguments(arguments);
            ReapLeftovers();
            process = _host.Spawn(AetherProcess.StartInfo(_host.Folders, arguments, run.Role, run.KeysDir), line =>
            {
                Volatile.Write(ref hadOutput, 1);
                RelayLine(source, line);
                run.OnOutput?.Invoke(line);
                output.Writer.TryWrite(line);
            });
        }
        catch (Exception ex) when (IsStartFailure(ex))
        {
            Logging.SaveLog($"AetherCore: failed to launch {source}", ex);
            return new AetherRunResult<T>(AetherRunOutcome.NotStarted);
        }
        var lifetime = Stopwatch.StartNew();
        state.Process = process;
        _host.Adopt?.Invoke(process);
        if (_host.UsesPidFiles)
        {
            AetherLeftovers.Write(_host.Folders.RunPidFile, process);
        }
        _ = process.Exited.ContinueWith(exited =>
        {
            // A failed wait for the exit is no failure of the run; it is read here, so that it goes unobserved nowhere.
            _ = exited.Exception;
            Interlocked.Exchange(ref exitedAfterTicks, lifetime.Elapsed.Ticks);
            output.Writer.TryComplete();
        }, TaskScheduler.Default);
        try
        {
            ct.ThrowIfCancellationRequested();
            var value = await block(output.Reader, ct).ConfigureAwait(false);
            // A block that found nothing because the core is gone: a core that never really started is told apart from
            // one that ran and gave up (a scan without an endpoint, a key run without its word).
            if (value is null && Interlocked.Read(ref exitedAfterTicks) is >= 0 and var exitedAfter)
            {
                var exitCode = await ExitCodeOf(process).ConfigureAwait(false);
                if (CouldNotStart(exitCode, TimeSpan.FromTicks(exitedAfter), Volatile.Read(ref hadOutput) != 0))
                {
                    Logging.SaveLog($"AetherCore: the {source} core could not start (code {exitCode})");
                    return new AetherRunResult<T>(AetherRunOutcome.NotStarted);
                }
            }
            return new AetherRunResult<T>(AetherRunOutcome.Done, value);
        }
        finally
        {
            await EndProcessAsync(process, source).ConfigureAwait(false);
            state.Process = null;
            if (_host.UsesPidFiles)
            {
                AetherLeftovers.Delete(_host.Folders.RunPidFile);
            }
            process.Dispose();
        }
    }

    /// <summary>The arguments as the core is started with them: the keys of a finished renewal in place, the shipped Psiphon list unpacked.</summary>
    private IReadOnlyList<string> PrepareArguments(IReadOnlyList<string> arguments)
    {
        var workDir = _host.Folders.WorkDir;
        Directory.CreateDirectory(workDir);
        // A renewal stopped while it moved its new keys into place is finished before a core reads them.
        if (!AetherIdentityManager.SettleIn(_host.Folders.ConfigDir))
        {
            Logging.SaveLog("AetherCore: the renewed keys could not all be moved into place; the keys not moved yet stay in use");
        }
        if (!arguments.Contains(AetherArguments.PsiphonServerEntries))
        {
            return arguments;
        }
        var entries = PsiphonServerList.EntriesFile(workDir, workDir, onProblem: problem =>
            Logging.SaveLog($"AetherCore: {AetherPaths.PsiphonServersFileName} is not a usable Psiphon list; the entries kept from before stay", problem));
        return AetherArguments.WithShippedList(arguments, entries);
    }

    /// <summary>
    /// Kills the cores an earlier PattN left behind, whatever they ran for (PattNG reapStale): a test's core holds the
    /// listen port a session needs as a session's core does, and either may be the one that survived. A core this
    /// manager runs now, the session's or one of its own, keeps running and keeps its file. A load calls it as well, before
    /// it checks the ports (AetherCoreLoad.BeforeXrayAsync).
    /// </summary>
    internal void ReapLeftovers()
    {
        if (!_host.UsesPidFiles)
        {
            return;
        }
        foreach (var pidFile in new[] { _host.Folders.SessionPidFile, _host.Folders.RunPidFile })
        {
            AetherLeftovers.Reap(pidFile, _host.Folders.CoreFile, IsLiveCore);
        }
    }

    /// <summary>Whether <paramref name="pid" /> is the process of a core this manager runs now.</summary>
    private bool IsLiveCore(int pid)
    {
        return IdOf(Session?.Process) == pid || IdOf(Volatile.Read(ref _run)?.Process) == pid;

        static int? IdOf(IAetherCoreProcess? process)
        {
            try
            {
                return process?.Id;
            }
            catch (InvalidOperationException)
            {
                return null;
            }
        }
    }

    /// <summary>
    /// Ends the core of its own that runs, and makes every one waiting for its turn give up (<see cref="_stopAll" />).
    /// </summary>
    private async Task StopRunsAsync()
    {
        CancellationTokenSource stopped;
        Standalone? run;
        lock (_gate)
        {
            stopped = _stopAll;
            _stopAll = new CancellationTokenSource();
            run = _run;
        }
        stopped.Cancel();
        if (run == null)
        {
            return;
        }
        run.StopWithAll();
        if (run.Process is { } process)
        {
            await process.KillAsync(_host.ExitWait).ConfigureAwait(false);
        }
        if (!await run.EndsWithinAsync(_host.ExitWait + _host.ExitWait).ConfigureAwait(false))
        {
            Logging.SaveLog("AetherCore: a core of a test, scan or key run did not end in time");
        }
    }

    /// <summary>Ends the session, if any, as asked: its exit raises nothing.</summary>
    private async Task EndSessionAsync()
    {
        AetherSession? current;
        lock (_gate)
        {
            current = _session;
            if (current == null)
            {
                return;
            }
            current.StopRequested = true;
            _session = null;
        }
        RaiseSessionChanged();
        if (current.Process is { } process)
        {
            await EndProcessAsync(process, SourceOf(AetherRole.Session)).ConfigureAwait(false);
            if (_host.UsesPidFiles)
            {
                AetherLeftovers.Delete(_host.Folders.SessionPidFile);
            }
        }
    }

    private async Task EndProcessAsync(IAetherCoreProcess process, string source)
    {
        try
        {
            if (!await process.KillAsync(_host.ExitWait).ConfigureAwait(false))
            {
                Logging.SaveLog($"AetherCore: the {source} core did not end in time after it was killed with what it started");
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or ObjectDisposedException)
        {
            // Ended and released already.
        }
    }

    /// <summary>The exit code of <paramref name="process" />, once it has exited; -1 when it cannot be read.</summary>
    private static async Task<int> ExitCodeOf(IAetherCoreProcess process)
    {
        try
        {
            return await process.Exited.ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is InvalidOperationException or ObjectDisposedException or Win32Exception)
        {
            return -1;
        }
    }

    private async Task WatchAsync(AetherSession session, IAetherCoreProcess process)
    {
        var exitCode = await ExitCodeOf(process).ConfigureAwait(false);
        // The end of a core that exited on its own takes its turn with starts and stops: a start that follows comes up only
        // once what the old core started is gone too, with its listener and Psiphon's datastore lock (PattNG queues it
        // behind the old core's end on the core's executor).
        string? message = null;
        await _lifecycle.WaitAsync().ConfigureAwait(false);
        try
        {
            lock (_gate)
            {
                // Stopped on request, or by a start that came first: that stop has ended it already.
                if (_session == session && !session.StopRequested)
                {
                    _session = null;
                    message = CouldNotStart(exitCode, session.Lifetime.Elapsed, session.HadOutput)
                        ? ResUI.MsgAetherCoreCannotStart
                        : StoppedMessage(session.NoEchKey, session.LastError, session.ChainEnd);
                    _stoppedMessage = message;
                }
            }
            if (message != null)
            {
                RaiseSessionChanged();
                // What it started may still run, holding its listener and Psiphon's datastore lock until it notices its
                // pipes gone.
                await EndProcessAsync(process, SourceOf(AetherRole.Session)).ConfigureAwait(false);
                if (_host.UsesPidFiles)
                {
                    AetherLeftovers.Delete(_host.Folders.SessionPidFile);
                }
            }
            process.Dispose();
        }
        finally
        {
            _lifecycle.Release();
        }
        if (message == null)
        {
            return;
        }
        Logging.SaveLog($"AetherCore: the core exited on its own with code {exitCode}");
        var ended = new AetherSessionEnded(session.Generation, exitCode, message);
        if (SessionEnded is not { } handlers)
        {
            return;
        }
        foreach (var handler in handlers.GetInvocationList().Cast<Func<AetherSessionEnded, Task>>())
        {
            try
            {
                await handler(ended).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Logging.SaveLog("AetherCore: the end of the session could not be handled", ex);
            }
        }
    }

    private bool IsCurrent(AetherSession session)
    {
        return Volatile.Read(ref _session) == session;
    }

    /// <summary>Tells <see cref="SessionChanged" />; a handler that throws is logged, so that the change goes on.</summary>
    private void RaiseSessionChanged()
    {
        if (SessionChanged is not { } handlers)
        {
            return;
        }
        foreach (var handler in handlers.GetInvocationList().Cast<Action>())
        {
            try
            {
                handler();
            }
            catch (Exception ex)
            {
                Logging.SaveLog("AetherCore: a change of the session could not be handled", ex);
            }
        }
    }

    private Task<bool> AwaitListeningAsync(AetherSession session, TimeSpan timeout, CancellationToken ct)
    {
        return AwaitReadyAsync(
            timeout,
            ReadyPoll,
            () => IsCurrent(session),
            async token => session.WordSeen && await AnswersSocksAsync(session.Port, token).ConfigureAwait(false),
            ct);
    }

    /// <summary>
    /// Relays a line of the core of <paramref name="source" /> to the message view, without its log header, and keeps
    /// Psiphon's report of the countries it can leave from, whichever core wrote it (critique 33).
    /// </summary>
    private void RelayLine(string source, string line)
    {
        var text = line.Trim();
        if (text.Length == 0)
        {
            return;
        }
        if (PsiphonServerList.RegionsOf(text) is { } regions)
        {
            try
            {
                _host.RememberRegions?.Invoke(regions);
            }
            catch (Exception ex)
            {
                Logging.SaveLog("AetherCore: the countries Psiphon can leave from could not be kept", ex);
            }
        }
        if (Relay is not { } relay)
        {
            return;
        }
        var message = $"[{source}] {AetherLogLine.OutputMessage(text)}";
        _ = RelayAsync(relay, message);
    }

    private static async Task RelayAsync(Func<string, Task> relay, string message)
    {
        try
        {
            await relay(message).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Logging.SaveLog("AetherCore: a line of the core's output could not be shown", ex);
        }
    }

    private static bool IsStartFailure(Exception ex)
    {
        return ex is Win32Exception or IOException or InvalidOperationException or UnauthorizedAccessException
            or PlatformNotSupportedException;
    }

    /// <summary>What <see cref="HoldAsync" /> returns; disposing it lets the cores start again.</summary>
    private sealed class Hold(AetherCoreManager manager) : IAsyncDisposable
    {
        private int _released;

        public ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _released, 1) == 0)
            {
                lock (manager._gate)
                {
                    manager._holds--;
                }
                manager._lifecycle.Release();
            }
            return ValueTask.CompletedTask;
        }
    }

    /// <summary>The core of its own that holds the exit: what it runs for, how to stop it, and when it is over.</summary>
    private sealed class Standalone(AetherRole role, CancellationTokenSource cancellation)
    {
        private volatile bool _stoppedWithAll;

        public AetherRole Role { get; } = role;
        public TaskCompletionSource Ended { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public IAetherCoreProcess? Process { get; set; }

        /// <summary>Whether it was ended by a stop of every core or a hold, rather than by its caller or a session start.</summary>
        public bool StoppedWithAll => _stoppedWithAll;

        /// <summary>Ends it with every other core (<see cref="StopRunsAsync" />): its run gives <see cref="AetherRunOutcome.Stopped" />.</summary>
        public void StopWithAll()
        {
            _stoppedWithAll = true;
            Cancel();
        }

        public void Cancel()
        {
            try
            {
                cancellation.Cancel();
            }
            catch (ObjectDisposedException)
            {
                // Over already.
            }
        }

        public async Task<bool> EndsWithinAsync(TimeSpan wait)
        {
            return await Task.WhenAny(Ended.Task, Task.Delay(wait)).ConfigureAwait(false) == Ended.Task;
        }
    }

    #endregion private
}
