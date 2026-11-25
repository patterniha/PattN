using System.Globalization;
using System.Threading.Channels;

namespace ServiceLib.Aether;

/// <summary>Where a latency test of a profile that needs an Aether core goes (PattNG AetherDelayTester.Route).</summary>
public enum AetherTestRoute
{
    /// <summary>Through the live session, which runs the core the test needs, on the port its configuration dials.</summary>
    ActiveSession,

    /// <summary>Through a core of its own on the Aether listen port: no session runs on Aether.</summary>
    NewTunnel,

    /// <summary>Nowhere: the live session runs another core, which holds the listen port every core listens on.</summary>
    Skip,

    /// <summary>Nowhere yet: the live session runs the core the test needs, and is still connecting.</summary>
    NotReady,
}

/// <summary>
/// The live session as a test sees it (PattNG LiveSession): the arguments its core was started with, the port of its
/// listener, whether that listener carries traffic yet, and the key of the exit-node its core dials out through
/// (<see cref="AetherExit.Key" />).
/// </summary>
public sealed record AetherLiveSession(IReadOnlyList<string> Arguments, int Port, bool Listening, string ExitKey);

/// <summary>
/// What a latency test of a profile that needs an Aether core gave: the delay in milliseconds, -1 when the profile
/// failed, or <see cref="AetherDelayTester.Untested" /> when it was left untested, with what the row shows for it
/// (critique 24: never "0").
/// </summary>
public sealed record AetherTestResult(int Delay, string? Reason = null)
{
    public static readonly AetherTestResult Failed = new(-1);

    public bool IsUntested => Delay == AetherDelayTester.Untested;

    public static AetherTestResult Untested(string reason)
    {
        return new AetherTestResult(AetherDelayTester.Untested, reason);
    }
}

/// <summary>
/// What a test measures once the tunnel it needs is up: <paramref name="port" /> is the loopback port of the test's
/// mixed inbound, which leads into that tunnel, and <paramref name="left" /> tells what is left of the test's budget.
/// Returns the delay in milliseconds, or -1.
/// </summary>
public delegate Task<int> AetherTestProbe(int port, Func<TimeSpan> left, CancellationToken ct);

/// <summary>What <see cref="AetherDelayTester" /> works with: PattN's own in <see cref="Default" />, fakes in tests.</summary>
public sealed class AetherTestHost
{
    /// <summary>The Aether cores: the live session, and the core of the test's own.</summary>
    public required AetherCoreManager Cores { get; init; }

    /// <summary>
    /// The context of a profile, with the checks a session start makes on it (CoreConfigContextBuilder.Build), but for the
    /// targets of the routing rules, which a test drops (E2).
    /// </summary>
    public required Func<ProfileItem, Task<CoreConfigContextBuilderResult>> Build { get; init; }

    /// <summary>The test configuration of a context with its mixed inbound on a port (CoreConfigV2rayService.GenerateClientSpeedtestConfig).</summary>
    public required Func<CoreConfigContext, int, RetResult> Generate { get; init; }

    /// <summary>Starts the test's Xray on a configuration; disposing what it gives stops it. Null when it does not run.</summary>
    public required Func<string, Task<IAsyncDisposable?>> StartXray { get; init; }

    /// <summary>A loopback port free now, which the system picks.</summary>
    public Func<int> PickPort { get; init; } = AetherPorts.PickLoopbackPort;

    /// <summary>Waits for a loopback port to accept connections, for at most the time given.</summary>
    public Func<int, TimeSpan, CancellationToken, Task<bool>> WaitForPort { get; init; } = AetherCoreLoad.WaitForPortAsync;

    /// <summary>Whether a SOCKS server answers on a loopback port (<see cref="AetherCoreManager.AnswersSocksAsync" />).</summary>
    public Func<int, CancellationToken, Task<bool>> AnswersSocks { get; init; } = AetherCoreManager.AnswersSocksAsync;

    /// <summary>
    /// Why the Aether core cannot run here, as when its program is missing (<see cref="AetherCoreLoad.MissingCoreMessage" />);
    /// null when it can, and in fakes that leave it out.
    /// </summary>
    public Func<string?> MissingCore { get; init; } = () => null;

    /// <summary>
    /// Whether, and to what, the outbounds of the test's Xray are bound while a TUN runs (D2); none in fakes that leave it
    /// out.
    /// </summary>
    public AetherUplinkBinding? Uplink { get; init; }

    /// <summary>The budget of a test, the start of its tunnel included (<see cref="AetherCoreManager.TestBudget" />).</summary>
    public TimeSpan Budget { get; init; } = AetherCoreManager.TestBudget;

    /// <summary>How often a test looks whether its tunnel is up (PattNG POLL_INTERVAL_MS).</summary>
    public TimeSpan Poll { get; init; } = AetherDelayTester.PollInterval;

    /// <summary>What PattN's own tests run with.</summary>
    public static AetherTestHost Default()
    {
        return new AetherTestHost
        {
            Cores = AetherCoreManager.Instance,
            // A test measures the profile alone and drops the routing rules: a rule's target never refuses it (E2).
            Build = profile => CoreConfigContextBuilder.Build(ConfigTextHandler.Config, profile, refuseRuleTargets: false),
            Generate = (context, port) => new CoreConfigV2rayService(context).GenerateClientSpeedtestConfig(port),
            StartXray = StartTestXrayAsync,
            Uplink = AetherUplinkBinding.Default,
            MissingCore = AetherCoreLoad.MissingCoreMessage,
        };
    }

    /// <summary>
    /// Writes <paramref name="content" /> into binConfigs under a name the hourly sweep of test configurations removes,
    /// and starts Xray on it without its output in the message view.
    /// </summary>
    private static async Task<IAsyncDisposable?> StartTestXrayAsync(string content)
    {
        var fileName = string.Format(Global.CoreSpeedtestConfigFileName, Utils.GetGuid(false));
        var file = Utils.GetBinConfigPath(fileName);
        try
        {
            await File.WriteAllTextAsync(file, content).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Logging.SaveLog("AetherTest: the test configuration could not be written", ex);
            TestXray.DeleteFile(file);
            return null;
        }
        var process = await CoreManager.Instance.RunAetherExitXrayAsync(fileName).ConfigureAwait(false);
        if (process == null)
        {
            TestXray.DeleteFile(file);
            return null;
        }
        return new TestXray(process, file);
    }

    /// <summary>The Xray of a test; disposing it stops the process and removes its configuration file.</summary>
    private sealed class TestXray(ProcessService process, string file) : IAsyncDisposable
    {
        private int _stopped;

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _stopped, 1) != 0)
            {
                return;
            }
            try
            {
                await process.StopAsync().ConfigureAwait(false);
                process.Dispose();
            }
            catch (Exception ex)
            {
                Logging.SaveLog("AetherTest: the Xray of a test could not be stopped", ex);
            }
            DeleteFile(file);
        }

        public static void DeleteFile(string file)
        {
            try
            {
                File.Delete(file);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Logging.SaveLog("AetherTest: a test configuration could not be removed", ex);
            }
        }
    }
}

/// <summary>
/// Latency tests of the profiles that need an Aether core (design 2.12.2, PattNG core/AetherDelayTester.kt): an Aether
/// profile, a group or a chain with one among its members, a profile its subscription chains with one. Every core
/// listens on the one Aether listen port, so such a test runs alone: through the live session when it runs the core the
/// test needs, through a core of its own while no session runs on Aether, and not at all beside a session that runs
/// another core. Its configuration is the latency test's of the profile, which a test Xray of its own runs; a core of
/// its own dials out through that same Xray, as the session's core dials out through the session's; while a TUN runs,
/// that Xray dials out by the uplink rather than into the TUN (D2). The whole test, the start of its tunnel included,
/// has the budget other profiles have (12 s).
/// </summary>
public sealed class AetherDelayTester(AetherTestHost host)
{
    /// <summary>Stored for "no result": the row shows nothing instead of a stale or a failed number (PattNG UNTESTED).</summary>
    public const int Untested = 0;

    /// <summary>How many requests a probe makes at most; the second goes over the connection of the first.</summary>
    public const int Attempts = 2;

    /// <summary>No further attempt starts with less than this left; it could not tell anything (PattNG MIN_REQUEST_MS).</summary>
    public static readonly TimeSpan MinRequest = TimeSpan.FromSeconds(1);

    /// <summary>How often a test looks whether its tunnel is up (PattNG POLL_INTERVAL_MS).</summary>
    public static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(250);

    /// <summary>Port every Cloudflare edge answers on TCP, whatever port the tunnel itself uses (PattNG EDGE_TCP_PORT).</summary>
    public const int EdgeTcpPort = 443;

    /// <summary>How long a TCP ping of an edge may take (PattNG REACH_TIMEOUT_MS).</summary>
    public static readonly TimeSpan ReachTimeout = TimeSpan.FromSeconds(1);

    private static readonly Lazy<AetherDelayTester> _default = new(() => new AetherDelayTester(AetherTestHost.Default()));

    /// <summary>
    /// One test through a tunnel of its own at a time, whichever run of tests it belongs to (PattNG tunnels): every such
    /// core listens on the Aether listen port, and the tests of a run that overlaps another wait their turn rather than
    /// find the exit taken. Its budget starts once its turn has come.
    /// </summary>
    private readonly SemaphoreSlim _tunnels = new(1, 1);

    public static AetherDelayTester Default => _default.Value;

    /// <summary>
    /// Measures <paramref name="profile" /> with <paramref name="probe" />, once the tunnel it needs is up: the live
    /// session's when it runs the core the profile needs, one of the test's own while no session runs on Aether, none
    /// beside a session that runs another core. A profile that cannot run as a session is refused (-1) as a session would
    /// be; a test that a scan or a key run would have to wait for, that a session start ends, that a stop of every core
    /// ends (an update of aether-core), or that would need a core of its own while the core cannot run here (D5) is left
    /// untested, with no Xray started for it. A cancellation inside <paramref name="probe" /> that is not the test's is a
    /// probe that got no answer (-1). A cancellation of <paramref name="ct" /> throws
    /// <see cref="OperationCanceledException" />.
    /// </summary>
    public async Task<AetherTestResult> MeasureAsync(ProfileItem profile, AetherTestProbe probe, CancellationToken ct = default)
    {
        var id = profile.IndexId;
        var (context, checks) = await host.Build(profile).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        if (!checks.Success)
        {
            // The checks a session start makes (stage-2 note: the speed test path of other profiles skips them).
            Logging.SaveLog($"AetherTest: the profile cannot run: {string.Join("; ", checks.Errors)}, id={id}");
            return AetherTestResult.Failed;
        }
        if (context.RunCoreType != ECoreType.Xray)
        {
            Logging.SaveLog($"AetherTest: only Xray runs an Aether profile, id={id}");
            return AetherTestResult.Failed;
        }
        var listenPort = host.Cores.ListenPort;
        var testPort = AetherExitService.FreePort(host.PickPort, listenPort);
        var secondaryPort = testPort is { } taken
            ? AetherExitService.FreePort(() => host.PickPort() is var port && port != taken ? port : 0, listenPort)
            : null;
        if (testPort is not { } test || secondaryPort is not { } secondary)
        {
            Logging.SaveLog($"AetherTest: no loopback port is free for the test, id={id}");
            return AetherTestResult.Failed;
        }

        // The configuration of a core of the test's own: its core dials out through this Xray, on the secondary port.
        context.Aether.SecondaryPort = secondary;
        var generated = host.Generate(context, test);
        if (generated.Success != true)
        {
            Logging.SaveLog($"AetherTest: the test configuration could not be generated: {generated.Msg}, id={id}");
            return AetherTestResult.Failed;
        }
        if (context.Aether.Core is not { } core)
        {
            // It needs no core after all.
            return BoundToUplink(context, test, generated, id) is { } alone
                ? await ThroughXrayAsync(alone, test, probe, id, ct).ConfigureAwait(false)
                : AetherTestResult.Failed;
        }
        switch (Route(core, await LiveSessionAsync(ct).ConfigureAwait(false)))
        {
            case AetherTestRoute.Skip:
                // The live session's core holds the port every core listens on.
                Logging.SaveLog($"AetherTest: left untested beside the live Aether session, id={id}");
                return AetherTestResult.Untested(ResUI.MsgAetherTestSkipped);

            case AetherTestRoute.NotReady:
                // The running profile is not a failure before its tunnel is up; it is just not measurable yet.
                Logging.SaveLog($"AetherTest: left untested, the live session is still connecting, id={id}");
                return AetherTestResult.Untested(ResUI.MsgAetherConnecting);

            case AetherTestRoute.ActiveSession:
                // The same configuration without a core of its own: its Aether outbounds dial the live core, whose way
                // out is the session's Xray.
                context.Aether.SecondaryPort = null;
                ApplyUplink(context);
                var throughSession = host.Generate(context, test);
                if (throughSession.Success != true)
                {
                    Logging.SaveLog($"AetherTest: the test configuration could not be generated: {throughSession.Msg}, id={id}");
                    return AetherTestResult.Failed;
                }
                return await ThroughXrayAsync(throughSession, test, probe, id, ct).ConfigureAwait(false);

            default:
                if (host.MissingCore() is { } missing)
                {
                    // D5: the app's state, not the profile's failure, which "Remove invalid" would take -1 for: the core is
                    // not there yet, or an update of aether-core is replacing it. No test Xray starts for a core that cannot.
                    Logging.SaveLog($"AetherTest: left untested, the Aether core cannot run: {missing}, id={id}");
                    return AetherTestResult.Untested(missing);
                }
                return BoundToUplink(context, test, generated, id) is { } ownTunnel
                    ? await ThroughNewTunnelAsync(core, ownTunnel, test, probe, id, ct).ConfigureAwait(false)
                    : AetherTestResult.Failed;
        }
    }

    /// <summary>
    /// Has the outbounds of the test's Xray bound to the uplink while a TUN runs (D2), once the test knows it starts that
    /// Xray (D2-4): a test left untested looks for no uplink, nor says it found none. True when they are bound.
    /// </summary>
    private bool ApplyUplink(CoreConfigContext context)
    {
        return host.Uplink?.Apply(context, AetherUplinkBinding.TestRole) != null;
    }

    /// <summary>
    /// <paramref name="generated" />, the test configuration of <paramref name="context" /> on <paramref name="test" />, as
    /// the test's Xray starts on it: generated again with its outbounds bound to the uplink when they are
    /// (<see cref="ApplyUplink" />); null when that generation fails.
    /// </summary>
    private RetResult? BoundToUplink(CoreConfigContext context, int test, RetResult generated, string id)
    {
        if (!ApplyUplink(context))
        {
            return generated;
        }
        var bound = host.Generate(context, test);
        if (bound.Success != true)
        {
            Logging.SaveLog($"AetherTest: the test configuration could not be generated: {bound.Msg}, id={id}");
            return null;
        }
        return bound;
    }

    /// <summary>
    /// Where a test goes (PattNG route): through the live session for the core it runs, on the port the test dials and
    /// out through the same exit-node; nowhere for any other core while the session runs, since every core listens on
    /// the one Aether listen port, which the session's core holds; through a tunnel of its own on that port while no
    /// session runs on Aether. While the session is still connecting, the running core is left untested rather than
    /// failed. PattN always knows the arguments of its session's core, so no selected profile stands in for them.
    /// </summary>
    public static AetherTestRoute Route(AetherCore core, AetherLiveSession? session)
    {
        if (session == null)
        {
            return AetherTestRoute.NewTunnel;
        }
        var running = core.RunsAs(session.Arguments) && core.Port == session.Port && core.Exit.Key == session.ExitKey;
        if (!running)
        {
            return AetherTestRoute.Skip;
        }
        return session.Listening ? AetherTestRoute.ActiveSession : AetherTestRoute.NotReady;
    }

    /// <summary>
    /// The live session as a test sees it, see <see cref="AetherLiveSession" />; null without one. Its listener carries
    /// traffic once it answers the SOCKS greeting and, where that is not enough (Psiphon), the core has said so.
    /// </summary>
    public static async Task<AetherLiveSession?> LiveSessionOf(
        AetherSession? session,
        Func<int, CancellationToken, Task<bool>> answers,
        CancellationToken ct = default)
    {
        if (session == null)
        {
            return null;
        }
        var listening = session.WordSeen && await answers(session.Port, ct).ConfigureAwait(false);
        return new AetherLiveSession(session.Core.Arguments, session.Port, listening, session.ExitKey);
    }

    /// <summary>
    /// The cheap probe behind "TCP ping" (PattNG reachability): a TCP connect to port 443 of the pinned edge address
    /// within a second, instead of a full tunnel. It tells whether that edge is reachable, not whether the tunnel works,
    /// and a profile left to the scanner has nothing to probe (<see cref="Untested" />).
    /// </summary>
    public static Task<int> ReachabilityAsync(ProfileItem profile, CancellationToken ct = default)
    {
        return ReachabilityAsync(profile, ConnectTimeAsync, ct);
    }

    /// <summary><see cref="ReachabilityAsync(ProfileItem, CancellationToken)" /> with <paramref name="connect" /> making the connection.</summary>
    public static async Task<int> ReachabilityAsync(
        ProfileItem profile,
        Func<string, int, CancellationToken, Task<int>> connect,
        CancellationToken ct = default)
    {
        var probed = ProbeHost(profile);
        return probed == null ? Untested : await connect(probed, EdgeTcpPort, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// The edge a TCP ping of <paramref name="profile" /> probes: the outer hop of a two-hop tunnel, else the pinned
    /// endpoint; null when there is none, or it is no IP address and port.
    /// </summary>
    public static string? ProbeHost(ProfileItem profile)
    {
        var extra = profile.GetProtocolExtra();
        if (AetherProtocol.FromString(extra.AetherProtocol).TwoHops)
        {
            return AetherEndpoint.Parse(extra.AetherWiwOuter)?.Host;
        }
        var port = profile.Port == 0 ? null : profile.Port.ToString(CultureInfo.InvariantCulture);
        return AetherEndpoint.Of(profile.Address, port)?.Host;
    }

    /// <summary>
    /// The budget arithmetic of a probe (PattNG requestDelay): the best of up to <see cref="Attempts" /> attempts, each
    /// given what <paramref name="left" /> says is left of the budget, none started with less than
    /// <see cref="MinRequest" /> left; -1 when none was answered. <paramref name="attempt" /> gives the time of one
    /// attempt within the time it is given, or -1.
    /// </summary>
    public static async Task<int> BestOfAttemptsAsync(
        Func<TimeSpan> left,
        Func<TimeSpan, CancellationToken, Task<int>> attempt,
        CancellationToken ct = default)
    {
        var best = -1;
        for (var index = 0; index < Attempts; index++)
        {
            var remaining = left();
            if (remaining < MinRequest)
            {
                return best;
            }
            var time = await attempt(remaining, ct).ConfigureAwait(false);
            if (time >= 0 && (best < 0 || time < best))
            {
                best = time;
            }
        }
        return best;
    }

    /// <summary>
    /// Waits until the listener on <paramref name="port" /> answers, and, with <paramref name="needsWord" />, until the
    /// core has also written its word that the listener carries traffic (PattNG awaitListening); false when the core
    /// ends (its <paramref name="lines" /> end) or <paramref name="left" /> says the time is up. A cancellation of
    /// <paramref name="ct" /> throws.
    /// </summary>
    public static async Task<bool> AwaitTunnelAsync(
        int port,
        ChannelReader<string> lines,
        Func<TimeSpan> left,
        bool needsWord,
        Func<int, CancellationToken, Task<bool>> answers,
        TimeSpan poll,
        CancellationToken ct = default)
    {
        var wordSeen = !needsWord;
        while (left() > TimeSpan.Zero)
        {
            while (lines.TryRead(out var line))
            {
                if (!wordSeen && AetherLogLine.IsReadyWord(line))
                {
                    wordSeen = true;
                }
            }
            if (lines.Completion.IsCompleted)
            {
                return false;
            }
            if (wordSeen && await answers(port, ct).ConfigureAwait(false))
            {
                return true;
            }
            var wait = left() < poll ? left() : poll;
            if (wait > TimeSpan.Zero)
            {
                await Task.Delay(wait, ct).ConfigureAwait(false);
            }
        }
        return false;
    }

    private async Task<AetherLiveSession?> LiveSessionAsync(CancellationToken ct)
    {
        return await LiveSessionOf(host.Cores.Session, host.AnswersSocks, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// The test of a configuration that needs no core of the test's own: its Xray alone, with a budget of its own (PattNG
    /// gives the live session's route a fresh budget).
    /// </summary>
    private async Task<AetherTestResult> ThroughXrayAsync(RetResult configuration, int testPort, AetherTestProbe probe, string id, CancellationToken ct)
    {
        var clock = Stopwatch.StartNew();
        TimeSpan Left() => host.Budget - clock.Elapsed;
        await using var xray = await host.StartXray(configuration.Data?.ToString() ?? string.Empty).ConfigureAwait(false);
        if (xray == null)
        {
            Logging.SaveLog($"AetherTest: the Xray of the test did not start, id={id}");
            return AetherTestResult.Failed;
        }
        if (!await host.WaitForPort(testPort, Left(), ct).ConfigureAwait(false))
        {
            Logging.SaveLog($"AetherTest: the Xray of the test did not listen in time, id={id}");
            return AetherTestResult.Failed;
        }
        return await ProbedAsync(probe, testPort, Left, id, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// The test through a tunnel of its own (PattNG throughNewTunnel), in its turn among such tests: once the run has its
    /// turn at the exit, the test's Xray comes up first, whose secondary-socks inbound the core dials out through, then
    /// the core on the Aether listen port, as a core of its own that a session start cancels and that never waits behind a
    /// scan or a key run (critique 9). The core and what it started are killed once the test is over, and the Xray stopped
    /// after them, before the run is over.
    /// </summary>
    private async Task<AetherTestResult> ThroughNewTunnelAsync(
        AetherCore core,
        RetResult configuration,
        int testPort,
        AetherTestProbe probe,
        string id,
        CancellationToken ct)
    {
        await _tunnels.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            // The clock starts before the spawn: the budget covers the whole test, as it does for every other profile.
            var clock = Stopwatch.StartNew();
            TimeSpan Left() => host.Budget - clock.Elapsed;
            var arguments = core.Arguments;
            var needsWord = AetherArguments.ReadyNeedsWord(arguments) && AetherArguments.ShowsInfo(arguments);
            var run = await host.Cores.RunStandaloneAsync(
                new AetherStandaloneRun(arguments, AetherRole.Test)
                {
                    OwnXray = token => StartTestXrayAsync(configuration, testPort, Left, id, token),
                },
                async (lines, token) =>
                {
                    if (!await AwaitTunnelAsync(core.Port, lines, Left, needsWord, host.AnswersSocks, host.Poll, token).ConfigureAwait(false))
                    {
                        Logging.SaveLog($"AetherTest: the tunnel did not come up, id={id}");
                        return AetherTestResult.Failed;
                    }
                    return await ProbedAsync(probe, testPort, Left, id, token).ConfigureAwait(false);
                },
                ct).ConfigureAwait(false);
            switch (run.Outcome)
            {
                case AetherRunOutcome.Done:
                    return run.Value ?? AetherTestResult.Failed;

                case AetherRunOutcome.Busy:
                    return Busy(id);

                case AetherRunOutcome.Stopped:
                    // Not the profile's failure: every core was stopped, as an update of aether-core does; one that took
                    // the core's program away meanwhile is told as a missing core is (D5).
                    Logging.SaveLog($"AetherTest: left untested, every Aether core was stopped, id={id}");
                    return AetherTestResult.Untested(host.MissingCore() ?? ResUI.SpeedtestingSkip);

                case AetherRunOutcome.NoExit:
                    // Its own Xray did not come up, which it logged.
                    return AetherTestResult.Failed;

                default:
                    Logging.SaveLog($"AetherTest: the core of the test did not start ({run.Outcome}), id={id}");
                    return AetherTestResult.Failed;
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            // The run's own token, which only a session start cancels here: it took the listen port this test's core held.
            Logging.SaveLog($"AetherTest: left untested, a session started meanwhile, id={id}");
            return AetherTestResult.Untested(ResUI.SpeedtestingSkip);
        }
        finally
        {
            _tunnels.Release();
        }
    }

    /// <summary>
    /// The Xray of a test through a tunnel of its own, once its run has its turn (<see cref="AetherStandaloneRun.OwnXray" />):
    /// up and listening on <paramref name="testPort" /> within what <paramref name="left" /> says is left, or null. The
    /// core dials out through it as soon as it starts; its test inbound is there in every case, the secondary-socks one
    /// only for a core that names no upstream of its own, and Xray opens its inbounds together.
    /// </summary>
    private async Task<IAsyncDisposable?> StartTestXrayAsync(RetResult configuration, int testPort, Func<TimeSpan> left, string id, CancellationToken token)
    {
        var xray = await host.StartXray(configuration.Data?.ToString() ?? string.Empty).ConfigureAwait(false);
        if (xray == null)
        {
            Logging.SaveLog($"AetherTest: the Xray of the test did not start, id={id}");
            return null;
        }
        try
        {
            if (await host.WaitForPort(testPort, left(), token).ConfigureAwait(false))
            {
                return xray;
            }
            Logging.SaveLog($"AetherTest: the Xray of the test did not listen in time, id={id}");
        }
        catch
        {
            // Cancelled meanwhile, by a session start, a stop of every core or the test's caller: the Xray goes, and the
            // cancellation goes on to the run.
            await xray.DisposeAsync().ConfigureAwait(false);
            throw;
        }
        await xray.DisposeAsync().ConfigureAwait(false);
        return null;
    }

    /// <summary>
    /// What <paramref name="probe" /> measured through <paramref name="testPort" />. A cancellation inside it that is not
    /// one of <paramref name="token" />, a timeout of its own that it let out, is no answer (-1), never taken for a
    /// session start or a cancelled run.
    /// </summary>
    private static async Task<AetherTestResult> ProbedAsync(AetherTestProbe probe, int testPort, Func<TimeSpan> left, string id, CancellationToken token)
    {
        try
        {
            return Measured(await probe(testPort, left, token).ConfigureAwait(false), id);
        }
        catch (OperationCanceledException ex) when (!token.IsCancellationRequested)
        {
            Logging.SaveLog($"AetherTest: the probe gave up on a timeout of its own, id={id}", ex);
            return AetherTestResult.Failed;
        }
    }

    private AetherTestResult Busy(string id)
    {
        string why;
        if (host.Cores.SessionStarting)
        {
            why = "a session is starting";
        }
        else if (host.Cores.IsRunning)
        {
            why = "a session started meanwhile";
        }
        else
        {
            why = "a scan or a key run holds the exit";
        }
        Logging.SaveLog($"AetherTest: left untested, {why}, id={id}");
        return AetherTestResult.Untested(ResUI.SpeedtestingSkip);
    }

    private static AetherTestResult Measured(int delay, string id)
    {
        if (delay < 0)
        {
            Logging.SaveLog($"AetherTest: no answer through the tunnel, id={id}");
            return AetherTestResult.Failed;
        }
        return new AetherTestResult(delay);
    }

    /// <summary>The time a TCP connection to <paramref name="host" />, an IP address, takes, within <see cref="ReachTimeout" />; -1 when it fails.</summary>
    private static async Task<int> ConnectTimeAsync(string host, int port, CancellationToken ct)
    {
        if (!IPAddress.TryParse(host, out var address))
        {
            return -1;
        }
        using var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(ReachTimeout);
        var timer = Stopwatch.StartNew();
        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, port), timeout.Token).ConfigureAwait(false);
            // At least 1 ms: 0 is what a test left untested stores.
            return Math.Max(1, (int)timer.ElapsedMilliseconds);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return -1;
        }
        catch (SocketException)
        {
            return -1;
        }
    }
}
