using System.ComponentModel;
using System.Threading.Channels;
using TUnit.Assertions.Enums;

namespace ServiceLib.Tests.Aether;

/// <summary>
/// From PattNG AetherCoreManagerTest, the runtime tests stage 1 left for the processes (readiness, warm-up, the exit, the
/// end of a core, the Psiphon datastores), and PattN's own tests of the session and of the cores of their own, against a
/// fake process factory: no core runs, and nothing reaches the network (listeners are the test's own, on the loopback).
/// </summary>
public class AetherCoreManagerTests : IDisposable
{
    private static readonly TimeSpan Soon = TimeSpan.FromSeconds(5);

    private readonly string _root = Directory.CreateTempSubdirectory("pattn-aether-core-").FullName;

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
            // A fake core's folder may still be in use by a background step; the temp folder is the system's to clean.
        }
    }

    // ---- fakes

    /// <summary>A core that writes what the test says, exits when told, and ends when killed unless told not to.</summary>
    private sealed class FakeCore(Rig rig, ProcessStartInfo info, Action<string> onLine, int id) : IAetherCoreProcess
    {
        private readonly TaskCompletionSource<int> _exited = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public ProcessStartInfo Info { get; } = info;
        public List<string> Arguments => Info.ArgumentList.ToList();
        public int Id { get; } = id;
        public DateTime StartedAt { get; } = DateTime.UtcNow;
        public bool HasExited => _exited.Task.IsCompleted;
        public Task<int> Exited => _exited.Task;
        public bool Killed { get; private set; }

        /// <summary>How often it was killed, a kill of a core that is gone already among them.</summary>
        public int Kills => Volatile.Read(ref _kills);

        private int _kills;
        public bool Disposed { get; private set; }

        public void Write(string line)
        {
            onLine(line);
        }

        public void Exit(int code)
        {
            _exited.TrySetResult(code);
        }

        public async Task<bool> KillAsync(TimeSpan wait)
        {
            Interlocked.Increment(ref _kills);
            if (!Killed)
            {
                Killed = true;
                rig.Log($"kill {Id}");
            }
            if (rig.KillTakes > TimeSpan.Zero)
            {
                // What the core started takes a while to end with it.
                await Task.Delay(rig.KillTakes);
                rig.Log($"killed {Id}");
            }
            if (rig.CoresEndWhenKilled)
            {
                Exit(-9);
                return true;
            }
            await Task.Delay(wait);
            return false;
        }

        public void Dispose()
        {
            Disposed = true;
        }
    }

    private sealed class FakeExit(Rig rig, int port) : IAetherExit
    {
        public int Port { get; } = port;

        public ValueTask DisposeAsync()
        {
            rig.Log("close");
            return ValueTask.CompletedTask;
        }
    }

    /// <summary>An <see cref="AetherCoreManager" /> on fakes, and what happened to them, in order.</summary>
    private sealed class Rig
    {
        private readonly List<string> _events = [];
        private int _ids;

        public Rig(string root, int? exitPort = 41234, bool usesPidFiles = false)
        {
            Folders = new AetherFolders(Path.Combine(root, "guiConfigs"), Path.Combine(root, "bin", "aether"));
            Manager = new AetherCoreManager(new AetherCoreHost
            {
                Folders = Folders,
                Spawn = (info, onLine) =>
                {
                    if (SpawnFails)
                    {
                        throw new Win32Exception(2, "The system cannot find the file specified");
                    }
                    if (SpawnTakes > TimeSpan.Zero)
                    {
                        // A start the system is slow to make, as an antivirus scan of a new program makes it.
                        Thread.Sleep(SpawnTakes);
                    }
                    var core = new FakeCore(this, info, onLine, Interlocked.Increment(ref _ids));
                    lock (Cores)
                    {
                        Cores.Add(core);
                    }
                    Log($"spawn {core.Id}");
                    if (FirstLine is { } first)
                    {
                        // A line the core writes before its spawn has returned.
                        core.Write(first);
                    }
                    return core;
                },
                AppLogLevel = () => AppLogLevel,
                OpenExit = (exit, role, _) =>
                {
                    Log("open");
                    OpenedFor.Add((exit, role));
                    return Task.FromResult<IAetherExit?>(exitPort is { } port ? new FakeExit(this, port) : null);
                },
                RememberRegions = regions =>
                {
                    lock (Regions)
                    {
                        Regions.Add(regions);
                    }
                },
                ExitWait = TimeSpan.FromMilliseconds(300),
                ProbeExitWait = TimeSpan.FromMilliseconds(300),
                TestWait = TimeSpan.FromSeconds(3),
                UsesPidFiles = usesPidFiles,
            })
            {
                Relay = message =>
                {
                    lock (Relayed)
                    {
                        Relayed.Add(message);
                    }
                    return Task.CompletedTask;
                },
            };
        }

        public AetherFolders Folders { get; }
        public AetherCoreManager Manager { get; }
        public List<FakeCore> Cores { get; } = [];
        public List<string> Relayed { get; } = [];
        public List<IReadOnlyList<string>> Regions { get; } = [];
        public List<(AetherExit Exit, AetherRole Role)> OpenedFor { get; } = [];
        public string? AppLogLevel { get; set; } = "warning";
        public bool CoresEndWhenKilled { get; set; } = true;
        public bool SpawnFails { get; set; }

        /// <summary>A line each core writes as it is spawned, before the spawn returns.</summary>
        public string? FirstLine { get; set; }
        public TimeSpan SpawnTakes { get; set; }
        public TimeSpan KillTakes { get; set; }

        public List<string> Events
        {
            get
            {
                lock (_events)
                {
                    return [.. _events];
                }
            }
        }

        public FakeCore Core(int index)
        {
            lock (Cores)
            {
                return Cores[index];
            }
        }

        public void Log(string text)
        {
            lock (_events)
            {
                _events.Add(text);
            }
        }

        /// <summary>The session ends it reports, as they come.</summary>
        public Channel<AetherSessionEnded> WatchEnds()
        {
            var ends = Channel.CreateUnbounded<AetherSessionEnded>();
            Manager.SessionEnded += ended =>
            {
                ends.Writer.TryWrite(ended);
                return Task.CompletedTask;
            };
            return ends;
        }
    }

    private static AetherCore Core(params string[] arguments)
    {
        return new AetherCore(arguments.Length == 0 ? ["--masque", "--bind", "127.0.0.1:10819"] : arguments);
    }

    private static async Task<T> Within<T>(Task<T> task)
    {
        return await task.WaitAsync(Soon);
    }

    private static async Task<T> Next<T>(Channel<T> channel)
    {
        return await channel.Reader.ReadAsync().AsTask().WaitAsync(Soon);
    }

    private static int ClosedPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    /// <summary>Answers the SOCKS5 greeting and nothing more, as a served listener does.</summary>
    private sealed class SocksGreeter : IDisposable
    {
        private readonly TcpListener _server = new(IPAddress.Loopback, 0);

        public SocksGreeter()
        {
            _server.Start();
            _ = Task.Run(async () =>
            {
                while (true)
                {
                    TcpClient client;
                    try
                    {
                        client = await _server.AcceptTcpClientAsync();
                    }
                    catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
                    {
                        return;
                    }
                    _ = Task.Run(async () =>
                    {
                        using (client)
                        {
                            try
                            {
                                var stream = client.GetStream();
                                var head = new byte[2];
                                await stream.ReadExactlyAsync(head);
                                await stream.ReadExactlyAsync(new byte[head[1]]);
                                await stream.WriteAsync(new byte[] { 5, 0 });
                            }
                            catch (Exception ex) when (ex is IOException or SocketException or EndOfStreamException)
                            {
                            }
                        }
                    });
                }
            });
        }

        public int Port => ((IPEndPoint)_server.LocalEndpoint).Port;

        public void Dispose()
        {
            _server.Stop();
        }
    }

    // ---- readiness (PattNG awaitReady, answersSocks, warmUpOutcome)

    [Test]
    public async Task TheTestWaitsUntilTheCoreStartsListening()
    {
        var polls = 0;
        await (await AetherCoreManager.AwaitReadyAsync(TimeSpan.FromSeconds(5), TimeSpan.FromMilliseconds(10), () => true,
            _ => Task.FromResult(++polls >= 3))).Should().BeTrue();
        await polls.Should().BeEqualTo(3);
    }

    [Test]
    public async Task TheTestGivesUpWhenTheCoreStopsOrTakesTooLong()
    {
        await (await AetherCoreManager.AwaitReadyAsync(TimeSpan.FromSeconds(5), TimeSpan.FromMilliseconds(10), () => false,
            _ => Task.FromResult(true))).Should().BeFalse();

        var polls = 0;
        await (await AetherCoreManager.AwaitReadyAsync(TimeSpan.FromSeconds(5), TimeSpan.FromMilliseconds(10), () => polls < 2,
            _ =>
            {
                polls++;
                return Task.FromResult(false);
            })).Should().BeFalse();

        await (await AetherCoreManager.AwaitReadyAsync(TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(10), () => true,
            _ => Task.FromResult(false))).Should().BeFalse();
    }

    [Test]
    public async Task TheWarmUpReportsAListenerACoreExitOrNothingAtAll()
    {
        await AetherCoreManager.WarmUpOutcome(listening: true, active: true, serviceRunning: true).Should().BeEqualTo(AetherWarmUpOutcome.Listening);
        await AetherCoreManager.WarmUpOutcome(listening: false, active: true, serviceRunning: true).Should().BeEqualTo(AetherWarmUpOutcome.CoreExited);
        await AetherCoreManager.WarmUpOutcome(listening: false, active: false, serviceRunning: true).Should().BeEqualTo(AetherWarmUpOutcome.Abandoned);
        await AetherCoreManager.WarmUpOutcome(listening: true, active: true, serviceRunning: false).Should().BeEqualTo(AetherWarmUpOutcome.Abandoned);
        await AetherCoreManager.WarmUpOutcome(listening: true, active: false, serviceRunning: true).Should().BeEqualTo(AetherWarmUpOutcome.Abandoned);
    }

    [Test]
    public async Task AListenerCountsOnceItAnswersTheSocksGreeting()
    {
        // Bound but not served yet, as Tor's listener is before Tor has bootstrapped: the connection is taken, nothing is said.
        var silent = new TcpListener(IPAddress.Loopback, 0);
        silent.Start();
        try
        {
            await (await AetherCoreManager.AnswersSocksAsync(((IPEndPoint)silent.LocalEndpoint).Port)).Should().BeFalse();
        }
        finally
        {
            silent.Stop();
        }
        await (await AetherCoreManager.AnswersSocksAsync(ClosedPort())).Should().BeFalse();
        using var greeter = new SocksGreeter();
        await (await AetherCoreManager.AnswersSocksAsync(greeter.Port)).Should().BeTrue();
    }

    // PattN: Psiphon's listener answers nothing until it has a tunnel: it closes every connection.
    [Test]
    public async Task AListenerThatClosesEveryConnectionDoesNotCount()
    {
        var closing = new TcpListener(IPAddress.Loopback, 0);
        closing.Start();
        using var stopping = new CancellationTokenSource();
        var serving = Task.Run(async () =>
        {
            try
            {
                while (true)
                {
                    using var client = await closing.AcceptTcpClientAsync(stopping.Token);
                }
            }
            catch (OperationCanceledException) when (stopping.IsCancellationRequested)
            {
            }
        });
        try
        {
            await (await AetherCoreManager.AnswersSocksAsync(((IPEndPoint)closing.LocalEndpoint).Port)).Should().BeFalse();
        }
        finally
        {
            // Finish the accept loop before stopping the listener so it cannot accept after Stop.
            stopping.Cancel();
            try
            {
                await serving;
            }
            finally
            {
                closing.Stop();
            }
        }
    }

    // PattN: two probes of ports nothing listens on can be connected to each other by a simultaneous open, when each was
    // given the other's port to dial from; each then reads the other's greeting, which is no SOCKS server's answer.
    [Test]
    public async Task AGreetingThatComesBackIsNoAnswer()
    {
        await (await AnswersWith([5, 1, 0])).Should().BeFalse();
        await (await AnswersWith([5])).Should().BeFalse();
        // A server that accepts no method the greeting offers is a SOCKS server all the same, as one that accepts it is.
        await (await AnswersWith([5, 0xFF])).Should().BeTrue();
        await (await AnswersWith([5, 0])).Should().BeTrue();
    }

    /// <summary>What the probe makes of a listener that reads the greeting and writes <paramref name="reply" />.</summary>
    private static async Task<bool> AnswersWith(byte[] reply)
    {
        var server = new TcpListener(IPAddress.Loopback, 0);
        server.Start();
        using var stopping = new CancellationTokenSource();
        var serving = Task.Run(async () =>
        {
            try
            {
                using var client = await server.AcceptTcpClientAsync(stopping.Token);
                var stream = client.GetStream();
                await stream.ReadExactlyAsync(new byte[3]);
                await stream.WriteAsync(reply);
                // The connection stays open until the probe is done with it.
                await stream.CopyToAsync(Stream.Null);
            }
            catch (OperationCanceledException) when (stopping.IsCancellationRequested)
            {
            }
            catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
            {
            }
        });
        try
        {
            return await AetherCoreManager.AnswersSocksAsync(((IPEndPoint)server.LocalEndpoint).Port);
        }
        finally
        {
            // As in AListenerThatClosesEveryConnectionDoesNotCount: a server task the thread pool starts only after the
            // probe gave up must not accept after Stop, so its accept is cancelled and awaited first.
            stopping.Cancel();
            try
            {
                await serving.WaitAsync(Soon);
            }
            finally
            {
                server.Stop();
            }
        }
    }

    // ---- what the end of a session says (PattNG aCoreThatStoppedForWantOfAnEchKeyIsReportedSo, critique 30, design 2.4.4)

    [Test]
    public async Task ACoreThatStoppedForWantOfAnEchKeyIsReportedSo()
    {
        await AetherCoreManager.StoppedMessage(noEchKey: true).Should().BeEqualTo(ResUI.MsgAetherCoreStoppedNoEchKey);
        await AetherCoreManager.StoppedMessage(noEchKey: false).Should().BeEqualTo(ResUI.MsgAetherCoreStopped);
        // The want of a key says more than the error line it ends with.
        await AetherCoreManager.StoppedMessage(noEchKey: true, "Error: Ech(\"...\")").Should().BeEqualTo(ResUI.MsgAetherCoreStoppedNoEchKey);
    }

    [Test]
    public async Task ACoreThatStoppedOnAnErrorIsReportedWithIt()
    {
        await AetherCoreManager.StoppedMessage(noEchKey: false, "Error: Api(\"too many registrations\")")
            .Should().BeEqualTo(string.Format(ResUI.MsgAetherCoreStoppedWithError, "Error: Api(\"too many registrations\")"));
        // A core ended as Tor or Psiphon inside the tunnel had ended says so, in the core's words.
        await AetherCoreManager.StoppedMessage(noEchKey: false, null, "tor: the tor socks5 listener cannot use 127.0.0.1:10819")
            .Should().BeEqualTo(string.Format(ResUI.MsgAetherCoreStoppedChainEnded, "tor: the tor socks5 listener cannot use 127.0.0.1:10819"));
    }

    private const string TorTakenText = "the tor socks5 listener cannot use 127.0.0.1:10819: Address already in use (os error 98); "
                                        + "another program already listens there, so stop it or choose another port with --bind";

    /// <summary>The core's line when Tor cannot take its listener, as an aether-core before 2.3.4 writes it.</summary>
    private const string TorTakenLine = "[2026-10-23T10:00:00.000Z ERROR aether] [-] tor: other: " + TorTakenText;

    /// <summary>The words of <see cref="TorTakenLine" /> the stop message gives.</summary>
    private const string TorTakenWords = "tor: " + TorTakenText;

    private static AetherCore TorInside()
    {
        return Core("--masque", "--tor", "--tor-bind", "127.0.0.1:10819", "--bind", "127.0.0.1:10820");
    }

    [Test]
    public async Task ACoreWhoseTorInsideTheTunnelEndedIsEndedAndEndsTheSession()
    {
        var rig = new Rig(_root);
        var ends = rig.WatchEnds();

        await rig.Manager.StartSessionAsync(TorInside(), generation: 7);
        // An aether-core before 2.3.4 goes on without the listener Xray dials, which another program holds.
        rig.Core(0).Write(TorTakenLine);

        var ended = await Next(ends);
        await rig.Core(0).Killed.Should().BeTrue();
        await ended.Generation.Should().BeEqualTo(7);
        await ended.Message.Should().BeEqualTo(string.Format(ResUI.MsgAetherCoreStoppedChainEnded, TorTakenWords));
        await rig.Manager.Session.Should().BeNull();
    }

    [Test]
    public async Task ACoreThatEndsItselfAsTorInsideTheTunnelEndedIsReportedSo()
    {
        // An aether-core since 2.3.4 ends on its own after that line, with the error it names, which also tells the
        // option that sets the port.
        const string text = "the tor socks5 listener cannot use 127.0.0.1:10819: Address already in use (os error 98); "
                            + "another program already listens there, so stop it or choose another port with --tor-bind";
        var rig = new Rig(_root);
        var ends = rig.WatchEnds();

        await rig.Manager.StartSessionAsync(TorInside(), generation: 8);
        rig.Core(0).Write("[2026-10-23T10:00:00.000Z ERROR aether] [-] tor: other: " + text);
        rig.Core(0).Write("Error: Other(\"" + text + "\")");
        rig.Core(0).Exit(1);

        var ended = await Next(ends);
        await ended.Generation.Should().BeEqualTo(8);
        await ended.Message.Should().BeEqualTo(string.Format(ResUI.MsgAetherCoreStoppedChainEnded, "tor: " + text));
        await rig.Manager.Session.Should().BeNull();
    }

    [Test]
    public async Task ACoreThatSaysSoBeforeItIsAttachedIsEndedOnceItIs()
    {
        // Tor binds its listener as the core starts, and the word may come before the spawn returns.
        var rig = new Rig(_root) { FirstLine = TorTakenLine };
        var ends = rig.WatchEnds();

        await rig.Manager.StartSessionAsync(TorInside());

        await (await Next(ends)).Message.Should().BeEqualTo(string.Format(ResUI.MsgAetherCoreStoppedChainEnded, TorTakenWords));
        await rig.Core(0).Killed.Should().BeTrue();
    }

    [Test]
    public async Task AnErrorThePsiphonClientReportsLeavesTheSessionUp()
    {
        var rig = new Rig(_root);

        await rig.Manager.StartSessionAsync(Core("--masque", "--psiphon", "--psiphon-bind", "127.0.0.1:10819", "--bind", "127.0.0.1:10820"));
        // The client's own notices, which the core passes on from its psiphon module; the core's word that Psiphon ended
        // would follow them.
        rig.Core(0).Write("[2026-10-23T10:00:00.000Z ERROR aether::psiphon] [-] psiphon: tunnel establishment failed: dial timeout");
        rig.Core(0).Write("[2026-10-23T10:00:00.000Z ERROR aether::psiphon] [-] psiphon: psiphon.(*Controller).Run#412: tunnel failed");

        await rig.Core(0).Killed.Should().BeFalse();
        await rig.Manager.Session.Should().NotBeNull();
    }

    [Test]
    public async Task TheCoreSayingThatPsiphonInsideTheTunnelEndedEndsTheSession()
    {
        var rig = new Rig(_root);
        var ends = rig.WatchEnds();

        await rig.Manager.StartSessionAsync(Core("--masque", "--psiphon", "--psiphon-bind", "127.0.0.1:10819", "--bind", "127.0.0.1:10820"));
        // As a PattNG device logged it on 2026-09-24.
        rig.Core(0).Write("[2026-09-24T16:12:36.142Z ERROR aether] [-] psiphon: other: psiphon did not come up in time; it may be blocked on this network");

        await (await Next(ends)).Message.Should().BeEqualTo(
            string.Format(ResUI.MsgAetherCoreStoppedChainEnded, "psiphon: psiphon did not come up in time; it may be blocked on this network"));
        await rig.Core(0).Killed.Should().BeTrue();
    }

    [Test]
    public async Task AWordOfAStoppedSessionEndsNothingMore()
    {
        var rig = new Rig(_root) { CoresEndWhenKilled = false };

        await rig.Manager.StartSessionAsync(TorInside());
        await rig.Manager.StopSessionAsync();
        var killsAtTheStop = rig.Core(0).Kills;
        // A line still in the pipe once the session was stopped.
        rig.Core(0).Write(TorTakenLine);

        await rig.Manager.StoppedMessage().Should().BeEqualTo(ResUI.MsgAetherCoreStopped);
        await rig.Core(0).Kills.Should().BeEqualTo(killsAtTheStop);
    }

    [Test]
    public async Task ACoreThatNeverReallyStartedIsToldApart()
    {
        // Windows did not find a DLL the core needs (an aether-core before 2.3.2 without the Visual C++ runtime).
        await AetherProcess.DllNotFoundExitCode.Should().BeEqualTo(-1073741515);
        await AetherCoreManager.CouldNotStart(AetherProcess.DllNotFoundExitCode, TimeSpan.FromSeconds(30), hadOutput: true).Should().BeTrue();
        // Ended at once without a word.
        await AetherCoreManager.CouldNotStart(1, TimeSpan.FromMilliseconds(200), hadOutput: false).Should().BeTrue();
        // A word, or a while, says it started.
        await AetherCoreManager.CouldNotStart(1, TimeSpan.FromMilliseconds(200), hadOutput: true).Should().BeFalse();
        await AetherCoreManager.CouldNotStart(1, TimeSpan.FromSeconds(5), hadOutput: false).Should().BeFalse();
    }

    // ---- the session

    [Test]
    public async Task AStartEndsTheSessionBeforeIt()
    {
        var rig = new Rig(_root);

        await (await rig.Manager.StartSessionAsync(Core())).Should().BeNull();
        var first = rig.Manager.Session;
        await (await rig.Manager.StartSessionAsync(Core("--wg", "--bind", "127.0.0.1:10819"))).Should().BeNull();

        // The old core and what it started are gone before the new one comes up, with their listeners.
        await rig.Events.Should().BeEquivalentTo(["spawn 1", "kill 1", "spawn 2"], CollectionOrdering.Matching);
        await rig.Manager.Session.Should().NotBeNull();
        await ReferenceEquals(rig.Manager.Session, first).Should().BeFalse();
        await rig.Manager.Session!.Protocol.Should().BeEqualTo(AetherProtocol.WireGuard);
    }

    [Test]
    public async Task TheSessionFollowsTheAppLogLevelUnlessItsCommandNamesOne()
    {
        var rig = new Rig(_root) { AppLogLevel = "warning" };

        await rig.Manager.StartSessionAsync(Core());
        await rig.Core(0).Arguments.TakeLast(2).Should().BeEquivalentTo(["--log-level", "warn"], CollectionOrdering.Matching);

        // The ready word is an info line; a quieter setting must not leave a Psiphon session waiting for it.
        await rig.Manager.StartSessionAsync(Core("--psiphon", "--psiphon-bind", "127.0.0.1:10819", "--bind", "127.0.0.1:10820"));
        await rig.Core(1).Arguments.TakeLast(2).Should().BeEquivalentTo(["--log-level", "info"], CollectionOrdering.Matching);
        await rig.Manager.Session!.NeedsWord.Should().BeTrue();
        await rig.Manager.Session!.WordSeen.Should().BeFalse();

        await rig.Manager.StartSessionAsync(Core("--masque", "--bind", "127.0.0.1:10819", "--log-level", "debug"));
        await rig.Core(2).Arguments.Count(argument => argument == "--log-level").Should().BeEqualTo(1);
        await rig.Core(2).Arguments.TakeLast(2).Should().BeEquivalentTo(["--log-level", "debug"], CollectionOrdering.Matching);
    }

    [Test]
    public async Task TheSessionRunsWithItsOwnPsiphonDatastoreAndWithoutAListThatIsNotThere()
    {
        var rig = new Rig(_root);
        // A datastore the core had put inside the working folder moves out first.
        var inside = Directory.CreateDirectory(Path.Combine(rig.Folders.WorkDir, "aether.toml-psiphon")).FullName;
        File.WriteAllText(Path.Combine(inside, "datastore"), "servers");

        await rig.Manager.StartSessionAsync(Core("--psiphon", "--psiphon-bind", "127.0.0.1:10819", "--bind", "127.0.0.1:10820",
            "--psiphon-server-entries", "shipped-list"));

        var core = rig.Core(0);
        await core.Info.Environment["AETHER_PSIPHON_DIR"].Should().BeEqualTo(Path.Combine(rig.Folders.ConfigDir, "psiphon"));
        await File.ReadAllText(Path.Combine(rig.Folders.ConfigDir, "psiphon", "datastore")).Should().BeEqualTo("servers");
        // No psiphon_servers.dat in the working folder: the flag goes, and the client fetches a list itself.
        await core.Arguments.Contains("--psiphon-server-entries").Should().BeFalse();
        await core.Arguments.Contains("shipped-list").Should().BeFalse();
    }

    [Test]
    public async Task ACoreThatExitsOnItsOwnEndsTheSessionInTheWordsItEndedWith()
    {
        var rig = new Rig(_root);
        var ends = rig.WatchEnds();

        await rig.Manager.StartSessionAsync(Core(), generation: 7);
        // A word says it started, however soon it ends.
        rig.Core(0).Write("[2026-10-21T10:00:00.000Z INFO  aether] [+] scanning");
        rig.Core(0).Write("Error: Api(\"too many registrations\")");
        rig.Core(0).Exit(1);

        var ended = await Next(ends);
        await ended.Generation.Should().BeEqualTo(7);
        await ended.ExitCode.Should().BeEqualTo(1);
        await ended.Message.Should().BeEqualTo(string.Format(ResUI.MsgAetherCoreStoppedWithError, "Error: Api(\"too many registrations\")"));
        await rig.Manager.Session.Should().BeNull();
        await rig.Manager.StoppedMessage().Should().BeEqualTo(ended.Message);
    }

    [Test]
    public async Task ACoreThatStoppedForWantOfAnEchKeyEndsTheSessionSo()
    {
        var rig = new Rig(_root);
        var ends = rig.WatchEnds();

        await rig.Manager.StartSessionAsync(Core());
        // The core's last line as its main prints the error it ends with (fork aether/src/lib.rs, session_ech_key).
        rig.Core(0).Write("Error: Ech(\"ECH is on but there is no ECH key to offer (udp://1.1.1.1:53 did not answer for " +
                          "cloudflare-ech.com); stopping rather than send the server name in the clear\")");
        rig.Core(0).Exit(1);

        await (await Next(ends)).Message.Should().BeEqualTo(ResUI.MsgAetherCoreStoppedNoEchKey);
        await rig.Manager.Session.Should().BeNull();
    }

    [Test]
    public async Task ACoreThatEndsAtOnceWithoutAWordCouldNotStart()
    {
        var rig = new Rig(_root);
        var ends = rig.WatchEnds();

        await rig.Manager.StartSessionAsync(Core());
        rig.Core(0).Exit(AetherProcess.DllNotFoundExitCode);

        await (await Next(ends)).Message.Should().BeEqualTo(ResUI.MsgAetherCoreCannotStart);
    }

    [Test]
    public async Task ACoreThatEndsAtOnceWithAnOrdinaryCodeAndNoWordCouldNotStart()
    {
        // Design 2.4.4, through the session as it runs: no DLL is missing, and the core never said a thing.
        var rig = new Rig(_root);
        var ends = rig.WatchEnds();

        await rig.Manager.StartSessionAsync(Core());
        rig.Core(0).Exit(1);

        await (await Next(ends)).Message.Should().BeEqualTo(ResUI.MsgAetherCoreCannotStart);
    }

    [Test]
    public async Task TheTimeOfACoreThatCouldNotStartCountsFromItsSpawn()
    {
        // The work before the spawn (a leftover core killed and waited for, a slow start of the program) is no time the
        // core ran: one that ends at once without a word still could not start.
        var rig = new Rig(_root) { SpawnTakes = AetherCoreManager.StartWindow + TimeSpan.FromMilliseconds(300) };
        var ends = rig.WatchEnds();

        await rig.Manager.StartSessionAsync(Core());
        rig.Core(0).Exit(1);

        await (await Next(ends)).Message.Should().BeEqualTo(ResUI.MsgAetherCoreCannotStart);
    }

    [Test]
    public async Task AStopOnRequestRaisesNothing()
    {
        var rig = new Rig(_root);
        var ends = rig.WatchEnds();

        await rig.Manager.StartSessionAsync(Core());
        await rig.Manager.StopSessionAsync();

        await rig.Core(0).Killed.Should().BeTrue();
        await rig.Manager.Session.Should().BeNull();
        await Task.Delay(300);
        await ends.Reader.TryRead(out _).Should().BeFalse();
        // Nor does a start that replaces the session.
        await rig.Manager.StartSessionAsync(Core());
        await rig.Manager.StartSessionAsync(Core());
        await Task.Delay(300);
        await ends.Reader.TryRead(out _).Should().BeFalse();
    }

    [Test]
    public async Task AStopWaitsForTheCoreButNotForever()
    {
        // The core does not end in time even when killed: the stop goes on after the wait, and says so in the log.
        var rig = new Rig(_root) { CoresEndWhenKilled = false };
        await rig.Manager.StartSessionAsync(Core());

        var stop = Stopwatch.StartNew();
        await rig.Manager.StopSessionAsync().WaitAsync(Soon);

        await rig.Core(0).Killed.Should().BeTrue();
        await (stop.Elapsed >= TimeSpan.FromMilliseconds(250)).Should().BeTrue();
        await rig.Manager.Session.Should().BeNull();
    }

    [Test]
    public async Task AStartAfterACoreExitedOnItsOwnComesUpOnceWhatTheOldCoreStartedIsGone()
    {
        // PattNG queues a start behind the end of the old core: Psiphon or lyrebird of the old core would otherwise hold
        // its listener and Psiphon's datastore lock while the new core comes up.
        var rig = new Rig(_root) { KillTakes = TimeSpan.FromMilliseconds(400) };
        var ends = rig.WatchEnds();
        await rig.Manager.StartSessionAsync(Core());

        rig.Core(0).Write("[2026-10-21T10:00:00.000Z INFO  aether] [+] scanning");
        rig.Core(0).Exit(1);
        // The end of the old core is under way: what it started is being killed.
        var waited = Stopwatch.StartNew();
        while (!rig.Events.Contains("kill 1") && waited.Elapsed < Soon)
        {
            await Task.Delay(10);
        }
        await rig.Manager.StartSessionAsync(Core());

        var events = rig.Events;
        await events.IndexOf("killed 1").Should().BeGreaterThan(-1);
        await events.IndexOf("spawn 2").Should().BeGreaterThan(events.IndexOf("killed 1"));
        await rig.Manager.Session.Should().NotBeNull();
        await rig.Core(1).HasExited.Should().BeFalse();
        // The end was told once its cleanup was over, and the new session is left alone.
        await (await Next(ends)).Message.Should().BeEqualTo(ResUI.MsgAetherCoreStopped);
        await rig.Manager.IsRunning.Should().BeTrue();
    }

    [Test]
    public async Task EveryChangeOfTheSessionIsTold()
    {
        // Design 3.2.5: the Aether editor follows the session as it starts and ends; nothing polls for it. Each change is
        // told once the session it leaves is the one Session gives.
        var rig = new Rig(_root);
        var ends = rig.WatchEnds();
        var told = new ConcurrentQueue<bool>();
        rig.Manager.SessionChanged += () => told.Enqueue(rig.Manager.Session != null);

        await rig.Manager.StartSessionAsync(Core());
        await rig.Manager.StopSessionAsync();
        await told.ToList().Should().BeEquivalentTo([true, false], CollectionOrdering.Matching);
        // A stop with no session tells nothing.
        await rig.Manager.StopSessionAsync();
        await told.Count.Should().BeEqualTo(2);

        // A start that replaces a session tells its end, then the new one.
        await rig.Manager.StartSessionAsync(Core());
        await rig.Manager.StartSessionAsync(Core());
        await told.ToList().Should().BeEquivalentTo([true, false, true, false, true], CollectionOrdering.Matching);

        // A core that exits on its own.
        rig.Core(2).Write("[2026-10-21T10:00:00.000Z INFO  aether] [+] scanning");
        rig.Core(2).Exit(1);
        await Next(ends);
        await told.ToList().Should().BeEquivalentTo([true, false, true, false, true, false], CollectionOrdering.Matching);

        // A core that does not start is a session for a moment only.
        var failing = new Rig(_root) { SpawnFails = true };
        var toldFailing = new ConcurrentQueue<bool>();
        failing.Manager.SessionChanged += () => toldFailing.Enqueue(failing.Manager.Session != null);
        await failing.Manager.StartSessionAsync(Core());
        await toldFailing.ToList().Should().BeEquivalentTo([true, false], CollectionOrdering.Matching);
    }

    [Test]
    public async Task ACoreThatDoesNotStartLeavesNoSessionAndSaysWhy()
    {
        var rig = new Rig(_root) { SpawnFails = true };

        await (await rig.Manager.StartSessionAsync(Core())).Should().BeEqualTo(ResUI.MsgAetherCoreCannotStart);
        await rig.Manager.Session.Should().BeNull();
        await rig.Manager.IsRunning.Should().BeFalse();
    }

    [Test]
    public async Task TheSessionCountsAsListeningOnceItsListenerAnswers()
    {
        var rig = new Rig(_root);
        using var greeter = new SocksGreeter();

        await rig.Manager.StartSessionAsync(Core("--masque", "--bind", $"127.0.0.1:{greeter.Port}"));

        await rig.Manager.Session!.Port.Should().BeEqualTo(greeter.Port);
        await (await rig.Manager.AwaitListeningAsync(Soon)).Should().BeTrue();
        await (await rig.Manager.AwaitWarmUpAsync(rig.Manager.Session!)).Should().BeEqualTo(AetherWarmUpOutcome.Listening);
        await (await rig.Manager.AwaitTestableAsync()).Should().BeNull();
    }

    [Test]
    public async Task APsiphonSessionCountsAsListeningOnlyOnceTheCoreSaysPsiphonIsReady()
    {
        var rig = new Rig(_root);
        using var greeter = new SocksGreeter();
        await rig.Manager.StartSessionAsync(Core("--psiphon", "--psiphon-bind", $"127.0.0.1:{greeter.Port}", "--bind", "127.0.0.1:10820"));

        // Psiphon's listener answers the greeting as soon as it is bound, before it carries anything.
        await (await rig.Manager.AwaitListeningAsync(TimeSpan.FromMilliseconds(700))).Should().BeFalse();

        rig.Core(0).Write("[2026-10-21T10:00:00.000Z INFO  aether::psiphon] psiphon is ready");
        await (await rig.Manager.AwaitListeningAsync(Soon)).Should().BeTrue();
    }

    [Test]
    public async Task TheWarmUpEndsWithTheSession()
    {
        var rig = new Rig(_root);
        var port = ClosedPort();

        // A core that exits before its listener comes up.
        await rig.Manager.StartSessionAsync(Core("--masque", "--bind", $"127.0.0.1:{port}"));
        var exited = rig.Manager.AwaitWarmUpAsync(rig.Manager.Session!);
        await Task.Delay(200);
        rig.Core(0).Write("[2026-10-21T10:00:00.000Z INFO  aether] [+] scanning");
        rig.Core(0).Exit(1);
        await (await Within(exited)).Should().BeEqualTo(AetherWarmUpOutcome.CoreExited);

        // A session stopped, or replaced by a reload, leaves nothing to report.
        await rig.Manager.StartSessionAsync(Core("--masque", "--bind", $"127.0.0.1:{port}"));
        var stopped = rig.Manager.AwaitWarmUpAsync(rig.Manager.Session!);
        await Task.Delay(200);
        await rig.Manager.StopSessionAsync();
        await (await Within(stopped)).Should().BeEqualTo(AetherWarmUpOutcome.Abandoned);
    }

    [Test]
    public async Task ATestOfTheRunningConfigurationSaysWhenItsCoreStopped()
    {
        var rig = new Rig(_root);
        // No session: nothing to wait for.
        await (await rig.Manager.AwaitTestableAsync()).Should().BeNull();

        await rig.Manager.StartSessionAsync(Core("--masque", "--bind", $"127.0.0.1:{ClosedPort()}"));
        var testable = rig.Manager.AwaitTestableAsync();
        await Task.Delay(200);
        rig.Core(0).Write("[2026-10-21T10:00:00.000Z INFO  aether] [+] scanning");
        rig.Core(0).Exit(1);

        await (await Within(testable)).Should().BeEqualTo(ResUI.MsgAetherCoreStopped);
    }

    [Test]
    public async Task ATestOfTheRunningConfigurationSaysWhenItsCoreStillConnects()
    {
        var rig = new Rig(_root);
        await rig.Manager.StartSessionAsync(Core("--masque", "--bind", $"127.0.0.1:{ClosedPort()}"));

        await (await rig.Manager.AwaitTestableAsync().WaitAsync(TimeSpan.FromSeconds(10))).Should().BeEqualTo(ResUI.MsgAetherConnecting);
    }

    [Test]
    public async Task ATestOfTheRunningConfigurationFollowsASessionThatReplacesTheOneItWaitedFor()
    {
        // PattNG awaitListening follows whichever session is the live one: a reload that replaces the session while the test
        // waits leaves a core that is connecting, not one that stopped.
        var rig = new Rig(_root);
        await rig.Manager.StartSessionAsync(Core("--masque", "--bind", $"127.0.0.1:{ClosedPort()}"));

        var testable = rig.Manager.AwaitTestableAsync();
        await Task.Delay(600);
        // A load: a latency test's core is cancelled, the old cores stop, and the new session starts.
        await rig.Manager.CancelProbesAsync();
        await rig.Manager.StopSessionAsync();
        await rig.Manager.StartSessionAsync(Core("--masque", "--bind", $"127.0.0.1:{ClosedPort()}"));
        rig.Manager.EndSessionStart();

        await (await Within(testable)).Should().BeEqualTo(ResUI.MsgAetherConnecting);

        // And one whose new core carries traffic by the end counts as testable.
        using var greeter = new SocksGreeter();
        var replaced = rig.Manager.AwaitTestableAsync();
        await Task.Delay(600);
        await rig.Manager.CancelProbesAsync();
        await rig.Manager.StartSessionAsync(Core("--masque", "--bind", $"127.0.0.1:{greeter.Port}"));
        await (await Within(replaced)).Should().BeNull();
    }

    [Test]
    public async Task EveryCoresOutputReachesTheMessageViewUnderItsLabel()
    {
        var rig = new Rig(_root);
        await rig.Manager.StartSessionAsync(Core());

        rig.Core(0).Write("[2026-10-21T10:00:00.000Z INFO  aether::prober] selected MASQUE gateway 162.159.198.1:443");
        rig.Core(0).Write("   ");

        await rig.Relayed.Should().BeEquivalentTo(["[aether] selected MASQUE gateway 162.159.198.1:443"], CollectionOrdering.Matching);
    }

    [Test]
    public async Task TheCountriesPsiphonCanLeaveFromAreKeptWhicheverCoreReportsThem()
    {
        // Critique 33: PattNG's relay keeps them for every core, a scan's and a test's as well as the session's.
        var rig = new Rig(_root);
        await rig.Manager.StartSessionAsync(Core());
        rig.Core(0).Write("[2026-10-21T10:00:00.000Z INFO  aether::psiphon] psiphon can leave from: DE NL US");

        await rig.Manager.RunStandaloneAsync<string>(new AetherStandaloneRun(["--psiphon-only"], AetherRole.Scan) { Exit = AetherExit.Plain },
            (_, _) =>
            {
                rig.Core(1).Write("[2026-10-21T10:00:01.000Z INFO  aether::psiphon] psiphon can leave from: CA FR");
                return Task.FromResult<string?>(null);
            });

        await rig.Regions.Count.Should().BeEqualTo(2);
        await rig.Regions[0].Should().BeEquivalentTo(["DE", "NL", "US"], CollectionOrdering.Matching);
        await rig.Regions[1].Should().BeEquivalentTo(["CA", "FR"], CollectionOrdering.Matching);
        await rig.Relayed.Contains("[aether-scan] psiphon can leave from: CA FR").Should().BeTrue();
    }

    [Test]
    public async Task ASessionIsToldWhichScansAndKeyRunsWouldDisturbIt()
    {
        var rig = new Rig(_root);
        await rig.Manager.StartSessionAsync(Core("--masque", "--bind", "127.0.0.1:10819"));
        var session = rig.Manager.Session!;

        // A scan opens a second tunnel on the key of its protocol; MASQUE and the protocols over it share one.
        await session.DisturbedByScanOf(AetherProtocol.Masque).Should().BeTrue();
        await session.DisturbedByScanOf(AetherProtocol.WireGuard).Should().BeFalse();
        // New keys of a kind replace the keys the session uses, or leave them alone.
        await session.UsesKeysOf(AetherKeyKind.AllKeys).Should().BeTrue();
        await session.UsesKeysOf(AetherKeyKind.Masque).Should().BeTrue();
        await session.UsesKeysOf(AetherKeyKind.WireGuard).Should().BeFalse();
    }

    // ---- cores of their own (PattNG throughExit, withProcess; critique 9)

    /// <summary>An exit that opens on <paramref name="port" />, or not at all with null, and what was done with it, in order.</summary>
    private sealed class CountedExit(int? port = 41234)
    {
        public List<string> Events { get; } = [];

        public Task<int?> Open()
        {
            lock (Events)
            {
                Events.Add("open");
            }
            return Task.FromResult(port);
        }

        public Task Close()
        {
            lock (Events)
            {
                Events.Add("close");
            }
            return Task.CompletedTask;
        }
    }

    [Test]
    public async Task TheExitOfACoreOfItsOwnClosesOnceTheCoreIsOver()
    {
        var exit = new CountedExit();
        var found = await AetherCoreManager.ThroughExitAsync(new SemaphoreSlim(1, 1), exit.Open, exit.Close, port =>
        {
            exit.Events.Add($"core on {port}");
            return Task.FromResult<string?>("endpoint");
        });
        await found.Should().BeEqualTo("endpoint");
        await exit.Events.Should().BeEquivalentTo(["open", "core on 41234", "close"], CollectionOrdering.Matching);
    }

    [Test]
    public async Task TheExitClosesWhenTheCoreDoesNotStart()
    {
        // withProcess has nothing to give back then.
        var exit = new CountedExit();
        await (await AetherCoreManager.ThroughExitAsync(new SemaphoreSlim(1, 1), exit.Open, exit.Close, _ => Task.FromResult<string?>(null))).Should().BeNull();
        await exit.Events.Should().BeEquivalentTo(["open", "close"], CollectionOrdering.Matching);
    }

    [Test]
    public async Task AnExitThatDoesNotOpenRunsNoCoreAndIsNotClosed()
    {
        var exit = new CountedExit(port: null);
        var found = await AetherCoreManager.ThroughExitAsync(new SemaphoreSlim(1, 1), exit.Open, exit.Close, _ =>
        {
            exit.Events.Add("core");
            return Task.FromResult<string?>("endpoint");
        });
        await found.Should().BeNull();
        await exit.Events.Should().BeEquivalentTo(["open"], CollectionOrdering.Matching);
    }

    [Test]
    public async Task TheExitClosesWhenTheCoreFails()
    {
        var exit = new CountedExit();
        var threw = false;
        try
        {
            await AetherCoreManager.ThroughExitAsync<string>(new SemaphoreSlim(1, 1), exit.Open, exit.Close,
                _ => throw new InvalidOperationException("the core failed"));
        }
        catch (InvalidOperationException)
        {
            threw = true;
        }
        await threw.Should().BeTrue();
        await exit.Events.Should().BeEquivalentTo(["open", "close"], CollectionOrdering.Matching);
    }

    [Test]
    public async Task TheExitClosesWhenTheScanIsCancelled()
    {
        var exit = new CountedExit();
        var running = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var cancellation = new CancellationTokenSource();
        var scan = AetherCoreManager.ThroughExitAsync<string>(new SemaphoreSlim(1, 1), exit.Open, exit.Close, async _ =>
        {
            running.SetResult();
            await Task.Delay(Timeout.Infinite, cancellation.Token);
            return null;
        }, cancellation.Token);
        await running.Task.WaitAsync(Soon);
        cancellation.Cancel();
        var cancelled = false;
        try
        {
            await scan;
        }
        catch (OperationCanceledException)
        {
            cancelled = true;
        }
        await cancelled.Should().BeTrue();
        await exit.Events.Should().BeEquivalentTo(["open", "close"], CollectionOrdering.Matching);
    }

    [Test]
    public async Task TheExitClosesWhenTheCancellationLandsWhileItOpens()
    {
        // The exit opens on a step a cancellation does not stop, so it opens after the scan was cancelled: nothing runs
        // through it, and it is closed all the same.
        var events = new List<string>();
        var opening = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var mayOpen = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var cancellation = new CancellationTokenSource();
        var scan = AetherCoreManager.ThroughExitAsync(new SemaphoreSlim(1, 1), async () =>
        {
            opening.SetResult();
            await mayOpen.Task;
            lock (events)
            {
                events.Add("open");
            }
            return (int?)41234;
        }, () =>
        {
            lock (events)
            {
                events.Add("close");
            }
            return Task.CompletedTask;
        }, _ =>
        {
            lock (events)
            {
                events.Add("core");
            }
            return Task.FromResult<string?>("endpoint");
        }, cancellation.Token);
        await opening.Task.WaitAsync(Soon);
        cancellation.Cancel();
        mayOpen.SetResult();
        try
        {
            await scan;
        }
        catch (OperationCanceledException)
        {
        }
        await events.Should().BeEquivalentTo(["open", "close"], CollectionOrdering.Matching);
    }

    [Test]
    public async Task TheCoresOfAProcessTakeTurnsAtTheExit()
    {
        var turns = new SemaphoreSlim(1, 1);
        var events = new List<string>();
        void Log(string text)
        {
            lock (events)
            {
                events.Add(text);
            }
        }
        var firstRuns = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var firstMayEnd = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var secondOpened = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var first = Task.Run(() => AetherCoreManager.ThroughExitAsync(turns, () =>
        {
            Log("open 1");
            return Task.FromResult<int?>(1);
        }, () =>
        {
            Log("close 1");
            return Task.CompletedTask;
        }, async _ =>
        {
            firstRuns.SetResult();
            await firstMayEnd.Task;
            return (string?)"one";
        }));
        await firstRuns.Task.WaitAsync(Soon);
        var second = Task.Run(() => AetherCoreManager.ThroughExitAsync(turns, () =>
        {
            Log("open 2");
            secondOpened.SetResult();
            return Task.FromResult<int?>(2);
        }, () =>
        {
            Log("close 2");
            return Task.CompletedTask;
        }, _ => Task.FromResult<string?>("two")));
        // While the first core runs, the second waits for its turn.
        await (await Task.WhenAny(secondOpened.Task, Task.Delay(300)) == secondOpened.Task).Should().BeFalse();
        firstMayEnd.SetResult();
        await first.WaitAsync(Soon);
        await second.WaitAsync(Soon);
        await events.Should().BeEquivalentTo(["open 1", "close 1", "open 2", "close 2"], CollectionOrdering.Matching);
    }

    [Test]
    public async Task ACoreOfItsOwnDialsOutThroughItsExitWhichClosesOnceTheCoreIsGone()
    {
        var rig = new Rig(_root);
        var exit = new AetherExit(DialMode: "code-1");

        var result = await rig.Manager.RunStandaloneAsync(
            new AetherStandaloneRun(["--masque", "--no-quick-reconnect", "--upstream", "socks5://127.0.0.1:10822"], AetherRole.Scan) { Exit = exit },
            async (lines, ct) =>
            {
                rig.Core(0).Write("[2026-10-21T10:00:00.000Z INFO  aether::prober] selected MASQUE gateway 162.159.198.1:443");
                return await lines.ReadAsync(ct);
            });

        await result.Outcome.Should().BeEqualTo(AetherRunOutcome.Done);
        await result.Value.Should().BeEqualTo("[2026-10-21T10:00:00.000Z INFO  aether::prober] selected MASQUE gateway 162.159.198.1:443");
        await rig.OpenedFor.Single().Should().BeEqualTo((exit, AetherRole.Scan));
        // An upstream the arguments name, as a configuration exported from a session names the session's Xray, gives way to the exit's.
        await rig.Core(0).Arguments.Should().BeEquivalentTo(
            ["--masque", "--no-quick-reconnect", "--upstream", "socks5://127.0.0.1:41234"], CollectionOrdering.Matching);
        await rig.Core(0).Info.Environment["AETHER_PSIPHON_DIR"].Should().BeEqualTo(Path.Combine(rig.Folders.ConfigDir, "psiphon-probe"));
        // The core and what it started end before the exit closes and the next core may take the port.
        await rig.Events.Should().BeEquivalentTo(["open", "spawn 1", "kill 1", "close"], CollectionOrdering.Matching);
        await rig.Core(0).Disposed.Should().BeTrue();
        await rig.Manager.IsStandaloneRunning.Should().BeFalse();
    }

    [Test]
    public async Task ALatencyTestBringsItsOwnXrayAndOpensNoExit()
    {
        var rig = new Rig(_root);
        string[] arguments = ["--masque", "--bind", "127.0.0.1:10819", "--upstream", "socks5://127.0.0.1:52001"];

        var result = await rig.Manager.RunStandaloneAsync(new AetherStandaloneRun(arguments, AetherRole.Test),
            (_, _) => Task.FromResult<string?>("measured"));

        await result.Outcome.Should().BeEqualTo(AetherRunOutcome.Done);
        await rig.OpenedFor.Count.Should().BeEqualTo(0);
        await rig.Core(0).Arguments.Should().BeEquivalentTo(arguments, CollectionOrdering.Matching);
        await rig.Events.Should().BeEquivalentTo(["spawn 1", "kill 1"], CollectionOrdering.Matching);
    }

    [Test]
    public async Task AnExitThatDoesNotOpenRunsNoCoreOfItsOwn()
    {
        var rig = new Rig(_root, exitPort: null);

        var result = await rig.Manager.RunStandaloneAsync(new AetherStandaloneRun(["--register", "all"], AetherRole.Key) { Exit = new AetherExit(Node: "gone") },
            (_, _) => Task.FromResult<string?>("registered"));

        await result.Outcome.Should().BeEqualTo(AetherRunOutcome.NoExit);
        await rig.Events.Should().BeEquivalentTo(["open"], CollectionOrdering.Matching);
        await rig.Manager.IsStandaloneRunning.Should().BeFalse();
    }

    [Test]
    public async Task ACoreOfItsOwnThatDoesNotStartLeavesTheExitClosed()
    {
        var rig = new Rig(_root) { SpawnFails = true };

        var result = await rig.Manager.RunStandaloneAsync(new AetherStandaloneRun(["--masque"], AetherRole.Scan) { Exit = AetherExit.Plain },
            (_, _) => Task.FromResult<string?>("found"));

        await result.Outcome.Should().BeEqualTo(AetherRunOutcome.NotStarted);
        await rig.Events.Should().BeEquivalentTo(["open", "close"], CollectionOrdering.Matching);
    }

    [Test]
    public async Task AKeyRunWritesTheKeysItRegistersIntoTheFolderItIsGiven()
    {
        var rig = new Rig(_root);
        var renewal = Path.Combine(rig.Folders.ConfigDir, "aether-renewal");

        await rig.Manager.RunStandaloneAsync(
            new AetherStandaloneRun(["--register", "all"], AetherRole.Key) { Exit = AetherExit.Plain, KeysDir = renewal },
            (_, _) => Task.FromResult<string?>(null));

        await rig.Core(0).Info.Environment["AETHER_MASQUE_CONFIG"].Should().BeEqualTo(Path.Combine(renewal, "aether-masque.toml"));
        await rig.Relayed.Count.Should().BeEqualTo(0);
    }

    [Test]
    public async Task ALatencyTestDoesNotWaitBehindAScanOrAKeyRun()
    {
        // Critique 9: PattNG's tests run in a process of their own; here they share the exit with scans and key runs, which
        // may take minutes, so a test finds the exit taken and leaves its row untested.
        var rig = new Rig(_root);
        var scanRuns = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var scanMayEnd = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var scan = rig.Manager.RunStandaloneAsync<string>(new AetherStandaloneRun(["--masque"], AetherRole.Scan) { Exit = AetherExit.Plain },
            async (_, _) =>
            {
                scanRuns.SetResult();
                await scanMayEnd.Task;
                return "found";
            });
        await scanRuns.Task.WaitAsync(Soon);

        var test = await rig.Manager.RunStandaloneAsync(new AetherStandaloneRun(["--masque"], AetherRole.Test), (_, _) => Task.FromResult<string?>("measured"))
            .WaitAsync(TimeSpan.FromMilliseconds(500));

        await test.Outcome.Should().BeEqualTo(AetherRunOutcome.Busy);
        await rig.Cores.Count.Should().BeEqualTo(1);
        scanMayEnd.SetResult();
        await (await scan.WaitAsync(Soon)).Value.Should().BeEqualTo("found");
        // Once the exit is free, a test runs.
        await (await rig.Manager.RunStandaloneAsync(new AetherStandaloneRun(["--masque"], AetherRole.Test), (_, _) => Task.FromResult<string?>("measured"))).Outcome
            .Should().BeEqualTo(AetherRunOutcome.Done);
    }

    [Test]
    public async Task ScansAndKeyRunsTakeTurns()
    {
        var rig = new Rig(_root);
        var scanRuns = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var scanMayEnd = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var scan = rig.Manager.RunStandaloneAsync<string>(new AetherStandaloneRun(["--masque"], AetherRole.Scan) { Exit = AetherExit.Plain },
            async (_, _) =>
            {
                scanRuns.SetResult();
                await scanMayEnd.Task;
                return "found";
            });
        await scanRuns.Task.WaitAsync(Soon);

        var keyRun = rig.Manager.RunStandaloneAsync(new AetherStandaloneRun(["--register", "all"], AetherRole.Key) { Exit = AetherExit.Plain },
            (_, _) => Task.FromResult<string?>("registered"));
        await Task.Delay(300);
        await keyRun.IsCompleted.Should().BeFalse();
        await rig.Cores.Count.Should().BeEqualTo(1);

        scanMayEnd.SetResult();
        await (await keyRun.WaitAsync(Soon)).Outcome.Should().BeEqualTo(AetherRunOutcome.Done);
        await rig.Events.Should().BeEquivalentTo(["open", "spawn 1", "kill 1", "close", "open", "spawn 2", "kill 2", "close"], CollectionOrdering.Matching);
        await scan;
    }

    [Test]
    public async Task ASessionStartCancelsALatencyTestAndWaitsForItsCore()
    {
        var rig = new Rig(_root);
        var testRuns = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var test = rig.Manager.RunStandaloneAsync<string>(new AetherStandaloneRun(["--masque", "--bind", "127.0.0.1:10819"], AetherRole.Test),
            async (_, ct) =>
            {
                testRuns.SetResult();
                await Task.Delay(Timeout.Infinite, ct);
                return "measured";
            });
        await testRuns.Task.WaitAsync(Soon);

        await rig.Manager.CancelProbesAsync(TimeSpan.FromSeconds(5)).WaitAsync(Soon);

        // The test's core, which held the Aether listen port, is gone by the time the session may start.
        await rig.Core(0).Killed.Should().BeTrue();
        await rig.Manager.IsStandaloneRunning.Should().BeFalse();
        var cancelled = false;
        try
        {
            await test;
        }
        catch (OperationCanceledException)
        {
            cancelled = true;
        }
        await cancelled.Should().BeTrue();
    }

    [Test]
    public async Task ASessionStartWaitsForTheCoresOfTestsAndScansButNotForever()
    {
        // PattNG: a scan is not cancelled; the session starts beside it after a short wait.
        var rig = new Rig(_root);
        var scanRuns = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var scanMayEnd = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var scan = rig.Manager.RunStandaloneAsync<string>(new AetherStandaloneRun(["--masque"], AetherRole.Scan) { Exit = AetherExit.Plain },
            async (_, _) =>
            {
                scanRuns.SetResult();
                await scanMayEnd.Task;
                return "found";
            });
        await scanRuns.Task.WaitAsync(Soon);

        var wait = Stopwatch.StartNew();
        await rig.Manager.CancelProbesAsync(TimeSpan.FromMilliseconds(300)).WaitAsync(Soon);

        await (wait.Elapsed >= TimeSpan.FromMilliseconds(250)).Should().BeTrue();
        await rig.Manager.IsStandaloneRunning.Should().BeTrue();
        await rig.Core(0).Killed.Should().BeFalse();
        scanMayEnd.SetResult();
        await (await scan.WaitAsync(Soon)).Value.Should().BeEqualTo("found");

        // Nothing running: nothing to wait for. And the probes' Psiphon datastore is not the session's.
        await rig.Manager.CancelProbesAsync(TimeSpan.FromSeconds(30)).WaitAsync(TimeSpan.FromSeconds(1));
        await AetherCoreManager.PsiphonProbeDir(Path.Combine(_root, "files")).Should().BeEqualTo(Path.Combine(_root, "files", "psiphon-probe"));
        await AetherCoreManager.PsiphonProbeDir(Path.Combine(_root, "files"))
            .Should().NotBeEqualTo(AetherCoreManager.PsiphonStateDir(Path.Combine(_root, "files"), Path.Combine(_root, "files", "aether")));
    }

    [Test]
    public async Task StopAllEndsTheSessionAndEveryCoreOfItsOwn()
    {
        // Before the core's files are replaced, and when PattN exits.
        var rig = new Rig(_root);
        await rig.Manager.StartSessionAsync(Core());
        var scanRuns = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var scan = rig.Manager.RunStandaloneAsync<string>(new AetherStandaloneRun(["--masque"], AetherRole.Scan) { Exit = AetherExit.Plain },
            async (lines, ct) =>
            {
                scanRuns.SetResult();
                await foreach (var _ in lines.ReadAllAsync(ct))
                {
                }
                return null;
            });
        await scanRuns.Task.WaitAsync(Soon);

        await rig.Manager.StopAllAsync().WaitAsync(Soon);

        await rig.Core(0).Killed.Should().BeTrue();
        await rig.Core(1).Killed.Should().BeTrue();
        await rig.Manager.IsRunning.Should().BeFalse();
        await rig.Manager.IsStandaloneRunning.Should().BeFalse();
        // No cancellation its caller asked for: the scan says it was stopped, as PattN exits, and throws nothing.
        await (await scan.WaitAsync(Soon)).Outcome.Should().BeEqualTo(AetherRunOutcome.Stopped);
    }

    /// <summary>A scan that runs until it is cancelled, once it says it runs; the run as <see cref="AetherCoreManager.RunStandaloneAsync{T}" /> returns it.</summary>
    private static (Task<AetherRunResult<string>> Run, Task Runs) ScanUntilCancelled(Rig rig)
    {
        var runs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var run = rig.Manager.RunStandaloneAsync<string>(new AetherStandaloneRun(["--masque", "--scan-core"], AetherRole.Scan) { Exit = AetherExit.Plain },
            async (lines, ct) =>
            {
                runs.SetResult();
                await foreach (var _ in lines.ReadAllAsync(ct))
                {
                }
                return null;
            });
        return (run, runs.Task);
    }

    private static async Task<AetherRunOutcome?> OutcomeOf(Task<AetherRunResult<string>> run)
    {
        try
        {
            return (await run.WaitAsync(Soon)).Outcome;
        }
        catch (OperationCanceledException)
        {
            return null;
        }
    }

    [Test]
    public async Task AKeyRunWaitingForItsTurnGivesUpWhenEveryCoreIsStopped()
    {
        // Every core is meant to be gone once StopAllAsync returns, when PattN exits: a run that was waiting for its turn
        // at the exit does not start once the turn is free.
        var rig = new Rig(_root);
        var (scan, scanRuns) = ScanUntilCancelled(rig);
        await scanRuns.WaitAsync(Soon);
        var keyRun = rig.Manager.RunStandaloneAsync(new AetherStandaloneRun(["--register", "all"], AetherRole.Key) { Exit = AetherExit.Plain },
            (_, _) => Task.FromResult<string?>("registered"));
        await Task.Delay(200);

        await rig.Manager.StopAllAsync().WaitAsync(Soon);

        await (await keyRun.WaitAsync(Soon)).Outcome.Should().BeEqualTo(AetherRunOutcome.Stopped);
        await (await OutcomeOf(scan)).Should().BeEqualTo(AetherRunOutcome.Stopped);
        await rig.Events.Contains("spawn 2").Should().BeFalse();
        await rig.Manager.IsStandaloneRunning.Should().BeFalse();
        // A run asked for afterwards runs: PattN still runs.
        await (await rig.Manager.RunStandaloneAsync(new AetherStandaloneRun(["--masque"], AetherRole.Test), (_, _) => Task.FromResult<string?>("measured"))).Outcome
            .Should().BeEqualTo(AetherRunOutcome.Done);
    }

    [Test]
    public async Task NoCoreStartsWhileItsFilesAreReplaced()
    {
        // Check Update holds the cores while it puts the new programs in place: Windows keeps a running program's file
        // locked. A queued run gives up, a test or a scan asked for meanwhile does not start, and a session start waits.
        var rig = new Rig(_root);
        await rig.Manager.StartSessionAsync(Core());
        var (scan, scanRuns) = ScanUntilCancelled(rig);
        await scanRuns.WaitAsync(Soon);
        var keyRun = rig.Manager.RunStandaloneAsync(new AetherStandaloneRun(["--register", "all"], AetherRole.Key) { Exit = AetherExit.Plain },
            (_, _) => Task.FromResult<string?>("registered"));
        await Task.Delay(200);

        var hold = await rig.Manager.HoldAsync().WaitAsync(Soon);

        await rig.Core(0).Killed.Should().BeTrue();
        await rig.Core(1).Killed.Should().BeTrue();
        await rig.Manager.IsRunning.Should().BeFalse();
        await (await keyRun.WaitAsync(Soon)).Outcome.Should().BeEqualTo(AetherRunOutcome.Stopped);
        await (await OutcomeOf(scan)).Should().BeEqualTo(AetherRunOutcome.Stopped);
        // Told apart from a core that could not start: nothing is wrong with the core but its files being replaced.
        await (await rig.Manager.RunStandaloneAsync(new AetherStandaloneRun(["--masque"], AetherRole.Test), (_, _) => Task.FromResult<string?>("measured"))).Outcome
            .Should().BeEqualTo(AetherRunOutcome.Stopped);
        await (await rig.Manager.RunStandaloneAsync(new AetherStandaloneRun(["--masque"], AetherRole.Scan) { Exit = AetherExit.Plain }, (_, _) => Task.FromResult<string?>("found"))).Outcome
            .Should().BeEqualTo(AetherRunOutcome.Stopped);
        var session = rig.Manager.StartSessionAsync(Core());
        await Task.Delay(300);
        await session.IsCompleted.Should().BeFalse();
        await rig.Cores.Count.Should().BeEqualTo(2);

        await hold.DisposeAsync();
        await hold.DisposeAsync();

        await (await session.WaitAsync(Soon)).Should().BeNull();
        await rig.Cores.Count.Should().BeEqualTo(3);
        await rig.Manager.IsRunning.Should().BeTrue();
        await (await rig.Manager.RunStandaloneAsync(new AetherStandaloneRun(["--masque"], AetherRole.Scan) { Exit = AetherExit.Plain }, (_, _) => Task.FromResult<string?>("found"))).Outcome
            .Should().BeEqualTo(AetherRunOutcome.Done);
    }

    [Test]
    public async Task ALatencyTestDoesNotStartWhileALoadBringsUpASession()
    {
        // The load cancels a latency test's core before the old cores stop; until its session is there, a test that
        // asks would take the listen port the session is about to need (PattNG cancels the test service as a whole).
        var rig = new Rig(_root);

        await rig.Manager.CancelProbesAsync();
        await rig.Manager.SessionStarting.Should().BeTrue();
        var test = await rig.Manager.RunStandaloneAsync(new AetherStandaloneRun(["--masque", "--bind", "127.0.0.1:10819"], AetherRole.Test),
            (_, _) => Task.FromResult<string?>("measured"));
        await test.Outcome.Should().BeEqualTo(AetherRunOutcome.Busy);
        await rig.Cores.Count.Should().BeEqualTo(0);

        // The session is there: the tester decides by the live session from now on.
        await rig.Manager.StartSessionAsync(Core());
        await rig.Manager.SessionStarting.Should().BeFalse();

        // A load that ended without a session lets the tests run again.
        await rig.Manager.StopSessionAsync();
        await rig.Manager.CancelProbesAsync();
        rig.Manager.EndSessionStart();
        await (await rig.Manager.RunStandaloneAsync(new AetherStandaloneRun(["--masque"], AetherRole.Test), (_, _) => Task.FromResult<string?>("measured"))).Outcome
            .Should().BeEqualTo(AetherRunOutcome.Done);
    }

    [Test]
    public async Task ALatencyTestDoesNotStartBesideASession()
    {
        // A test that chose a tunnel of its own before the session started finds the listen port taken: its core would
        // listen on the session's port, and its probe would measure the session's core (PattNG cancels the tests of every
        // start). A scan or a key run starts beside a session all the same.
        var rig = new Rig(_root);
        await (await rig.Manager.StartSessionAsync(Core())).Should().BeNull();

        var test = await rig.Manager.RunStandaloneAsync(new AetherStandaloneRun(["--masque", "--bind", "127.0.0.1:10819"], AetherRole.Test),
            (_, _) => Task.FromResult<string?>("measured"));

        await test.Outcome.Should().BeEqualTo(AetherRunOutcome.Busy);
        await rig.Cores.Count.Should().BeEqualTo(1);
        await (await rig.Manager.RunStandaloneAsync(new AetherStandaloneRun(["--masque"], AetherRole.Scan) { Exit = AetherExit.Plain },
            (_, _) => Task.FromResult<string?>("found"))).Outcome.Should().BeEqualTo(AetherRunOutcome.Done);
        await rig.Manager.StopSessionAsync();
        await (await rig.Manager.RunStandaloneAsync(new AetherStandaloneRun(["--masque"], AetherRole.Test),
            (_, _) => Task.FromResult<string?>("measured"))).Outcome.Should().BeEqualTo(AetherRunOutcome.Done);
    }

    // ---- leftover cores on Linux and macOS (design 2.6.6, PattNG reapStale)

    /// <summary>
    /// A program of the system in the place of the core, running as a leftover core would: the files PattN left of the
    /// cores name it. Killed and waited for at the end, whatever the test did.
    /// </summary>
    private sealed class Leftover : IDisposable
    {
        public Leftover(AetherFolders folders)
        {
            Directory.CreateDirectory(folders.BinDir);
            var system = OperatingSystem.IsWindows() ? Path.Combine(Environment.SystemDirectory, "PING.EXE") : "/bin/sleep";
            File.Copy(system, folders.CoreFile, overwrite: true);
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(folders.CoreFile, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
            var info = new ProcessStartInfo(folders.CoreFile) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true };
            foreach (var argument in OperatingSystem.IsWindows() ? ["-n", "60", "127.0.0.1"] : new[] { "60" })
            {
                info.ArgumentList.Add(argument);
            }
            Process = Process.Start(info)!;
        }

        public Process Process { get; }

        /// <summary>Writes the file of a core of PattN's that names this process.</summary>
        public void NamedBy(string pidFile)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(pidFile)!);
            File.WriteAllText(pidFile, AetherLeftovers.Format(Process.Id, Process.StartTime.ToUniversalTime(), AetherLeftovers.BootTicksOf(Process.Id)));
        }

        public bool Gone()
        {
            Process.Refresh();
            return Process.WaitForExit(5000);
        }

        public void Dispose()
        {
            try
            {
                Process.Kill(entireProcessTree: true);
                Process.WaitForExit(5000);
            }
            catch (InvalidOperationException)
            {
                // Ended already.
            }
            Process.Dispose();
        }
    }

    [Test]
    public async Task ASessionStartKillsATestsCoreAnEarlierPattnLeftBehind()
    {
        // The test's core of a PattN that died holds the listen port the session needs, as a session's core would.
        var rig = new Rig(_root, usesPidFiles: true);
        using var leftover = new Leftover(rig.Folders);
        leftover.NamedBy(rig.Folders.RunPidFile);

        await rig.Manager.StartSessionAsync(Core());

        await leftover.Gone().Should().BeTrue();
        await File.Exists(rig.Folders.RunPidFile).Should().BeFalse();
        // The session's own core is named in its file instead.
        await AetherLeftovers.Parse(File.ReadAllText(rig.Folders.SessionPidFile))!.Pid.Should().BeEqualTo(rig.Core(0).Id);
    }

    [Test]
    public async Task ARunStartKillsASessionsCoreAnEarlierPattnLeftBehind()
    {
        var rig = new Rig(_root, usesPidFiles: true);
        using var leftover = new Leftover(rig.Folders);
        leftover.NamedBy(rig.Folders.SessionPidFile);

        var result = await rig.Manager.RunStandaloneAsync(new AetherStandaloneRun(["--masque"], AetherRole.Test), (_, _) => Task.FromResult<string?>("measured"));

        await result.Outcome.Should().BeEqualTo(AetherRunOutcome.Done);
        await leftover.Gone().Should().BeTrue();
        await File.Exists(rig.Folders.SessionPidFile).Should().BeFalse();
    }

    [Test]
    public async Task ACoreThisPattnRunsIsNoLeftover()
    {
        // A scan beside the session: the session's start leaves the scan's core and its file alone.
        var rig = new Rig(_root, usesPidFiles: true);
        var (scan, scanRuns) = ScanUntilCancelled(rig);
        await scanRuns.WaitAsync(Soon);
        var runFile = File.ReadAllText(rig.Folders.RunPidFile);

        await rig.Manager.StartSessionAsync(Core());

        await rig.Core(0).Killed.Should().BeFalse();
        await File.ReadAllText(rig.Folders.RunPidFile).Should().BeEqualTo(runFile);
        await rig.Manager.StopAllAsync();
        await OutcomeOf(scan);
    }

    // ---- the Psiphon datastores (PattNG psiphonStateDir, clearPsiphonState)

    [Test]
    public async Task ThePsiphonDatastoreLivesBesideTheIdentityDirectoryAndMovesOutOfItOnce()
    {
        await AetherArguments.PsiphonDirEnv.Should().BeEqualTo("AETHER_PSIPHON_DIR");
        var files = Path.Combine(_root, "files");
        var work = Directory.CreateDirectory(Path.Combine(files, "aether")).FullName;

        // Nothing to move: the directory is named, not made; the core makes it.
        var dir = AetherCoreManager.PsiphonStateDir(files, work);
        await dir.Should().BeEqualTo(Path.Combine(files, "psiphon"));
        await Directory.Exists(dir).Should().BeFalse();

        // A datastore the core had put inside the identity directory moves out.
        var inside = Directory.CreateDirectory(Path.Combine(work, "aether.toml-psiphon")).FullName;
        File.WriteAllText(Path.Combine(inside, "datastore"), "servers");
        await AetherCoreManager.PsiphonStateDir(files, work).Should().BeEqualTo(dir);
        await File.ReadAllText(Path.Combine(dir, "datastore")).Should().BeEqualTo("servers");
        await Directory.Exists(inside).Should().BeFalse();

        // Once out, whatever turns up inside later is left alone.
        Directory.CreateDirectory(inside);
        File.WriteAllText(Path.Combine(inside, "datastore"), "stale");
        AetherCoreManager.PsiphonStateDir(files, work);
        await File.ReadAllText(Path.Combine(dir, "datastore")).Should().BeEqualTo("servers");
        await Directory.Exists(inside).Should().BeTrue();
    }

    [Test]
    public async Task ClearingThePsiphonDataRemovesTheDatastoreWhereverItIs()
    {
        var files = Path.Combine(_root, "files");
        var work = Directory.CreateDirectory(Path.Combine(files, "aether")).FullName;

        await AetherCoreManager.ClearPsiphonState(files, work).Should().BeTrue();
        var outside = Directory.CreateDirectory(Path.Combine(files, "psiphon")).FullName;
        File.WriteAllText(Path.Combine(outside, "datastore"), "servers");
        var inside = Directory.CreateDirectory(Path.Combine(work, "aether.toml-psiphon")).FullName;
        File.WriteAllText(Path.Combine(inside, "datastore"), "older servers");
        var probe = Directory.CreateDirectory(AetherCoreManager.PsiphonProbeDir(files)).FullName;
        File.WriteAllText(Path.Combine(probe, "datastore"), "a test's servers");

        await AetherCoreManager.ClearPsiphonState(files, work).Should().BeTrue();
        await Directory.Exists(outside).Should().BeFalse();
        await Directory.Exists(inside).Should().BeFalse();
        await Directory.Exists(probe).Should().BeFalse();
        await Directory.Exists(work).Should().BeTrue();
    }

    [Test]
    public async Task ThePsiphonDataIsNotClearedWhileACoreHoldsIt()
    {
        var rig = new Rig(_root);
        var store = Directory.CreateDirectory(Path.Combine(rig.Folders.ConfigDir, "psiphon")).FullName;
        await rig.Manager.StartSessionAsync(Core());

        await rig.Manager.ClearPsiphonData().Should().BeEqualTo(AetherPsiphonClear.Blocked);
        await Directory.Exists(store).Should().BeTrue();

        await rig.Manager.StopSessionAsync();
        await rig.Manager.ClearPsiphonData().Should().BeEqualTo(AetherPsiphonClear.Cleared);
        await Directory.Exists(store).Should().BeFalse();
        // The countries Psiphon reported go with its datastore.
        await rig.Regions.Last().Count.Should().BeEqualTo(0);
    }
}
