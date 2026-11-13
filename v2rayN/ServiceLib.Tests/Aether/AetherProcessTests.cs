using TUnit.Assertions.Enums;

namespace ServiceLib.Tests.Aether;

/// <summary>
/// PattN (design 2.6.1, 2.6.2, 2.6.6): how a core is started, and the leftover cores of Linux and macOS. No core is run:
/// the start is checked as the description of the process it would be, and what a started process goes through (its
/// output, its stdin, its exit, a kill of its tree) with the system's shell in the core's place.
/// </summary>
public class AetherProcessTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("pattn-aether-process-").FullName;

    public void Dispose()
    {
        Directory.Delete(_root, recursive: true);
    }

    private AetherFolders Folders()
    {
        return new AetherFolders(Path.Combine(_root, "guiConfigs"), Path.Combine(_root, "bin", "aether"));
    }

    private static void Runnable(string file)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        File.WriteAllText(file, "program");
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    [Test]
    public async Task EveryArgumentReachesTheCoreAsOneWordWhateverItHolds()
    {
        var folders = Folders();
        string[] arguments = ["--bind", "127.0.0.1:10819", "--dns", "1.1.1.1, 1.0.0.1", "--exit-loc", "\"DE\"", "--tor-bridge-lines", "obfs4 1.2.3.4:443 X cert=a\\b"];

        var info = AetherProcess.StartInfo(folders, arguments, AetherRole.Session);

        await info.FileName.Should().BeEqualTo(folders.CoreFile);
        await info.ArgumentList.ToList().Should().BeEquivalentTo(arguments, CollectionOrdering.Matching);
        // No string that a shell or the Windows quoting rules would split again.
        await info.Arguments.Should().BeEqualTo(string.Empty);
        await info.UseShellExecute.Should().BeFalse();
        await info.CreateNoWindow.Should().BeTrue();
    }

    [Test]
    public async Task TheCoreGetsAPipeForStdinAndHandsBothOutputsBack()
    {
        // The core asks for its settings when stdin is a terminal; a pipe that is closed at once has nobody to ask.
        var info = AetherProcess.StartInfo(Folders(), ["--masque"], AetherRole.Scan);

        await info.RedirectStandardInput.Should().BeTrue();
        await info.RedirectStandardOutput.Should().BeTrue();
        await info.RedirectStandardError.Should().BeTrue();
        await info.StandardOutputEncoding!.WebName.Should().BeEqualTo("utf-8");
        await info.StandardErrorEncoding!.WebName.Should().BeEqualTo("utf-8");
    }

    [Test]
    public async Task EveryCoreRunsInTheWorkingFolderWithTheKeysInUseAndNoColours()
    {
        var folders = Folders();
        foreach (var role in new[] { AetherRole.Session, AetherRole.Test, AetherRole.Scan, AetherRole.Key })
        {
            var info = AetherProcess.StartInfo(folders, ["--wg"], role);

            await info.WorkingDirectory.Should().BeEqualTo(Path.Combine(_root, "guiConfigs", "aether"));
            await info.Environment["AETHER_CONFIG"].Should().BeEqualTo(Path.Combine(_root, "guiConfigs", "aether", "aether.toml"));
            await info.Environment["AETHER_MASQUE_CONFIG"].Should().BeEqualTo(Path.Combine(_root, "guiConfigs", "aether", "aether-masque.toml"));
            await info.Environment["AETHER_WG_CONFIG"].Should().BeEqualTo(Path.Combine(_root, "guiConfigs", "aether", "aether-wg.toml"));
            await info.Environment["NO_COLOR"].Should().BeEqualTo("1");
        }
    }

    [Test]
    public async Task OnlyTheSessionKeepsItsPsiphonDatastoreTheOthersShareTheProbes()
    {
        var folders = Folders();

        await AetherProcess.StartInfo(folders, [], AetherRole.Session).Environment["AETHER_PSIPHON_DIR"]
            .Should().BeEqualTo(Path.Combine(_root, "guiConfigs", "psiphon"));
        foreach (var role in new[] { AetherRole.Test, AetherRole.Scan, AetherRole.Key })
        {
            await AetherProcess.StartInfo(folders, [], role).Environment["AETHER_PSIPHON_DIR"]
                .Should().BeEqualTo(Path.Combine(_root, "guiConfigs", "psiphon-probe"));
        }
    }

    [Test]
    public async Task AKeyRunRegistersIntoTheFolderItIsGivenAndLeavesTheBasePathAlone()
    {
        var folders = Folders();
        var renewal = Path.Combine(_root, "guiConfigs", "aether-renewal");

        var info = AetherProcess.StartInfo(folders, ["--register", "all"], AetherRole.Key, renewal);

        await info.Environment["AETHER_MASQUE_CONFIG"].Should().BeEqualTo(Path.Combine(renewal, "aether-masque.toml"));
        await info.Environment["AETHER_WG_CONFIG"].Should().BeEqualTo(Path.Combine(renewal, "aether-wg.toml"));
        await info.Environment["AETHER_CONFIG"].Should().BeEqualTo(Path.Combine(_root, "guiConfigs", "aether", "aether.toml"));
    }

    [Test]
    public async Task ThePsiphonClientIsNamedToTheCoreOnlyWhenItIsThere()
    {
        var folders = Folders();

        var without = AetherProcess.StartInfo(folders, [], AetherRole.Session);
        await without.Environment.ContainsKey("AETHER_PSIPHON_BIN").Should().BeFalse();

        Runnable(folders.PsiphonFile);
        var with = AetherProcess.StartInfo(folders, [], AetherRole.Session);
        await with.Environment["AETHER_PSIPHON_BIN"].Should().BeEqualTo(Path.GetFullPath(folders.PsiphonFile));
    }

    [Test]
    public async Task TheAndroidOnlyVariablesOfPattngAreNotSet()
    {
        var info = AetherProcess.StartInfo(Folders(), [], AetherRole.Session);

        // What PattN's own environment holds of the system's, the core inherits as any program does; PattN sets none of
        // them. HOME stays the user's, where the core looks for Tor Browser's transports.
        foreach (var name in new[] { "SSL_CERT_DIR", "PATTNG_AETHER_OWNER", "PATTNG_AETHER_SESSION", "PATTNG_AETHER_EXIT", "HOME", "TMPDIR", "PATH" })
        {
            var given = info.Environment.TryGetValue(name, out var value) ? value : null;
            await given.Should().BeEqualTo(Environment.GetEnvironmentVariable(name)).Because(name);
        }
    }

    // The core takes every setting of a flag from an AETHER_ variable too, and its log filter from RUST_LOG: one a user who
    // also runs the aether command line keeps in the environment would change what the core runs, while PattN works the
    // ports, protected names and readiness out from the arguments alone.
    [Test]
    [NotInParallel("process environment")]
    public async Task TheSettingsOfTheCoreInPattnsOwnEnvironmentAreLeftOut()
    {
        string[] inherited =
        [
            "AETHER_ROUTE_DIRECT", "AETHER_TOR", "AETHER_TLS_VERIFY", "AETHER_HTTP_PROXY", "AETHER_PSIPHON_CONFIG", "AETHER_TOR_PT",
            "AETHER_CONFIG", "AETHER_PSIPHON_BIN", AetherProcess.RustLogEnv,
        ];
        var saved = inherited.ToDictionary(name => name, Environment.GetEnvironmentVariable);
        try
        {
            foreach (var name in inherited)
            {
                Environment.SetEnvironmentVariable(name, name == AetherProcess.RustLogEnv ? "warn" : "0.0.0.0/0");
            }
            var folders = Folders();

            foreach (var role in new[] { AetherRole.Session, AetherRole.Test, AetherRole.Scan, AetherRole.Key })
            {
                var environment = AetherProcess.StartInfo(folders, ["--masque"], role).Environment;

                var coreSettings = environment.Keys.Where(AetherProcess.IsCoreSetting).Order(StringComparer.Ordinal).ToList();
                // PattN's own and nothing else; no Psiphon client is in this bin/aether.
                await coreSettings.Should().BeEquivalentTo(
                    ["AETHER_CONFIG", "AETHER_MASQUE_CONFIG", "AETHER_PSIPHON_DIR", "AETHER_WG_CONFIG"], CollectionOrdering.Matching).Because(role.ToString());
                await environment["AETHER_CONFIG"].Should().BeEqualTo(Path.Combine(_root, "guiConfigs", "aether", "aether.toml"));
                await environment["NO_COLOR"].Should().BeEqualTo("1");
            }
            await AetherProcess.IsCoreSetting("AETHER_TOR").Should().BeTrue();
            await AetherProcess.IsCoreSetting("RUST_LOG").Should().BeTrue();
            await AetherProcess.IsCoreSetting("HOME").Should().BeFalse();
            await AetherProcess.IsCoreSetting("SSL_CERT_DIR").Should().BeFalse();
            await AetherProcess.IsCoreSetting("PATTN_AETHER").Should().BeFalse();
        }
        finally
        {
            foreach (var (name, value) in saved)
            {
                Environment.SetEnvironmentVariable(name, value);
            }
        }
    }

    // ---- leftover cores (design 2.6.6)

    [Test]
    public async Task APidFileNamesTheProcessAndItsStartTime()
    {
        var started = new DateTime(2026, 10, 21, 8, 30, 0, DateTimeKind.Utc);

        var text = AetherLeftovers.Format(4242, started);

        await text.Should().BeEqualTo($"4242 {started.Ticks}");
        await AetherLeftovers.Parse(text).Should().BeEqualTo(new AetherLeftovers.Entry(4242, started.Ticks));
        foreach (var broken in new[] { null, "", "4242", "abc 1", "4242 1 2 3", "4242 1 x", "-1 5", "0 5", "4242 x" })
        {
            await AetherLeftovers.Parse(broken).Should().BeNull().Because(broken ?? "null");
        }
    }

    [Test]
    public async Task OnlyTheCoreTheFileNamesIsKilledNotAProcessThatGotItsIdSince()
    {
        var core = Path.Combine(_root, "bin", "aether", Utils.GetExeName("aether"));
        var entry = new AetherLeftovers.Entry(4242, new DateTime(2026, 10, 21, 8, 30, 0, DateTimeKind.Utc).Ticks);

        // The same program, started at the time written down (to within a second, as the system reports it).
        await AetherLeftovers.IsLeftover(entry, entry.StartTicks, core, core).Should().BeTrue();
        await AetherLeftovers.IsLeftover(entry, entry.StartTicks + TimeSpan.TicksPerMillisecond * 300, core, core).Should().BeTrue();
        // Another program under the same id, or the core started at another time: the id was given out again.
        await AetherLeftovers.IsLeftover(entry, entry.StartTicks, Path.Combine(_root, "bin", "xray", "xray"), core).Should().BeFalse();
        await AetherLeftovers.IsLeftover(entry, entry.StartTicks + TimeSpan.TicksPerMinute, core, core).Should().BeFalse();
        // No such process, or one whose program cannot be read.
        await AetherLeftovers.IsLeftover(entry, null, core, core).Should().BeFalse();
        await AetherLeftovers.IsLeftover(entry, entry.StartTicks, null, core).Should().BeFalse();
    }

    // On Linux and macOS the system names the program of a process with every symbolic link on its way resolved
    // (/proc/[pid]/exe, proc_pidpath): a core reached through a link, as everything under /var is on macOS (/private/var,
    // where the temporary folders are), is still the core the file names.
    [Test]
    public async Task ACoreReachedThroughALinkIsTheProgramTheSystemNames()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }
        var real = Path.Combine(_root, "real");
        var core = Path.Combine(real, "bin", "aether", "aether");
        Runnable(core);
        var link = Path.Combine(_root, "link");
        Directory.CreateSymbolicLink(link, real);
        var relative = Path.Combine(_root, "relative");
        Directory.CreateSymbolicLink(relative, "real");
        var realCore = AetherLeftovers.RealPathOf(core);
        var throughLink = Path.Combine(link, "bin", "aether", "aether");
        var throughRelative = Path.Combine(relative, "bin", "aether", "aether");

        await AetherLeftovers.RealPathOf(throughLink).Should().BeEqualTo(realCore);
        await AetherLeftovers.RealPathOf(throughRelative).Should().BeEqualTo(realCore);
        // A part that is not there ends the resolving, and what follows it stays as it is.
        await AetherLeftovers.RealPathOf(Path.Combine(link, "gone", "aether"))
            .Should().BeEqualTo(Path.Combine(AetherLeftovers.RealPathOf(real), "gone", "aether"));

        // The system names the core by its real path, the file by the path PattN started it from.
        var entry = new AetherLeftovers.Entry(4242, new DateTime(2026, 10, 21, 8, 30, 0, DateTimeKind.Utc).Ticks);
        await AetherLeftovers.IsLeftover(entry, entry.StartTicks, realCore, throughLink).Should().BeTrue();
        await AetherLeftovers.IsLeftover(entry, entry.StartTicks, realCore, throughRelative).Should().BeTrue();
        await AetherLeftovers.IsLeftover(entry, entry.StartTicks, realCore, Path.Combine(link, "bin", "xray", "xray")).Should().BeFalse();
    }

    [Test]
    public async Task APidFileThatNamesNoLivingCoreIsRemoved()
    {
        var pidFile = Path.Combine(_root, "aether.pid");
        // An id no process has: the largest a pid file can name.
        File.WriteAllText(pidFile, AetherLeftovers.Format(int.MaxValue, DateTime.UtcNow));

        AetherLeftovers.Reap(pidFile, Path.Combine(_root, "bin", "aether", "aether"));

        await File.Exists(pidFile).Should().BeFalse();
    }

    // On Linux .NET derives a process's start time from the wall clock, which a clock step (an NTP sync after a start with
    // an unsynced clock, a manual change) moves between two runs of PattN; the kernel's start since boot does not move.
    [Test]
    public async Task OnLinuxALeftoverIsKnownByItsStartSinceBootWhateverTheClockDid()
    {
        var started = new DateTime(2026, 10, 21, 8, 30, 0, DateTimeKind.Utc);
        var text = AetherLeftovers.Format(4242, started, 123456);
        await text.Should().BeEqualTo($"4242 {started.Ticks} 123456");
        var entry = AetherLeftovers.Parse(text)!;
        await entry.Should().BeEqualTo(new AetherLeftovers.Entry(4242, started.Ticks, 123456));
        await AetherLeftovers.Parse("4242 5 x").Should().BeNull();
        await AetherLeftovers.Parse("4242 5 6 7").Should().BeNull();

        var core = Path.Combine(_root, "bin", "aether", "aether");
        var stepped = started.Ticks + TimeSpan.TicksPerSecond * 7;
        // The wall clock stepped by seven seconds: the same start since boot is the same process.
        await AetherLeftovers.IsLeftover(entry, stepped, core, core, liveBootTicks: 123456).Should().BeTrue();
        // Another start since boot is another process, whatever the times say.
        await AetherLeftovers.IsLeftover(entry, started.Ticks, core, core, liveBootTicks: 123457).Should().BeFalse();
        // Where either start since boot is unknown, the start time decides, within a second.
        await AetherLeftovers.IsLeftover(entry, stepped, core, core).Should().BeFalse();
        await AetherLeftovers.IsLeftover(entry with { BootTicks = null }, started.Ticks, core, core, liveBootTicks: 999).Should().BeTrue();
    }

    [Test]
    public async Task TheStartSinceBootIsField22OfTheStatLine()
    {
        // The name of the program, in parentheses, may hold spaces and parentheses of its own.
        const string stat = "4242 (aether (core) x) S 1 4242 4242 0 -1 4194560 1234 0 0 0 10 5 0 0 20 0 9 0 987654 104857600 2560 18446744073709551615";

        await AetherLeftovers.BootTicksOf(stat).Should().BeEqualTo(987654);
        await AetherLeftovers.BootTicksOf("4242 (aether) S 1").Should().BeNull();
        await AetherLeftovers.BootTicksOf("no parenthesis").Should().BeNull();
        await AetherLeftovers.BootTicksOf((string?)null).Should().BeNull();
        if (OperatingSystem.IsLinux())
        {
            await (AetherLeftovers.BootTicksOf(Environment.ProcessId) is not null).Should().BeTrue();
        }
        else
        {
            await AetherLeftovers.BootTicksOf(Environment.ProcessId).Should().BeNull();
        }
    }

    // ---- a real process (no core: a program of the system that writes, reads stdin, or waits)

    /// <summary>A start of the system's shell running <paramref name="script" />, set up as a core is started.</summary>
    private ProcessStartInfo Shell(string script)
    {
        var folders = Folders();
        Directory.CreateDirectory(folders.WorkDir);
        var info = AetherProcess.StartInfo(folders, [], AetherRole.Test);
        info.ArgumentList.Clear();
        if (OperatingSystem.IsWindows())
        {
            info.FileName = Path.Combine(Environment.SystemDirectory, "cmd.exe");
            info.ArgumentList.Add("/d");
            info.ArgumentList.Add("/c");
        }
        else
        {
            info.FileName = "/bin/sh";
            info.ArgumentList.Add("-c");
        }
        info.ArgumentList.Add(script);
        return info;
    }

    private static readonly TimeSpan Soon = TimeSpan.FromSeconds(20);

    [Test]
    public async Task ACoresOutputComesLineByLineFromBothStreamsWithoutColours()
    {
        var lines = new List<string>();
        const string red = "\u001b[31mred\u001b[0m";
        var script = OperatingSystem.IsWindows() ? $"echo {red}& echo plain 1>&2" : $"printf '{red}\\n'; echo plain 1>&2";

        using var process = AetherProcess.Start(Shell(script), line =>
        {
            lock (lines)
            {
                lines.Add(line);
            }
        });

        await (await process.Exited.WaitAsync(Soon)).Should().BeEqualTo(0);
        List<string> seen;
        lock (lines)
        {
            seen = lines.Select(line => line.Trim()).Where(line => line.Length > 0).ToList();
        }
        await seen.Should().BeEquivalentTo(["red", "plain"], CollectionOrdering.Any);
        await seen.Any(line => line.Contains('\u001b')).Should().BeFalse();
    }

    [Test]
    public async Task ACoresStdinIsClosedAtOnce()
    {
        // The core asks for its settings when stdin is a terminal; a program that reads stdin to its end goes on at once.
        var lines = new List<string>();
        var script = OperatingSystem.IsWindows() ? "more & echo after-eof" : "cat; echo after-eof";

        using var process = AetherProcess.Start(Shell(script), line =>
        {
            lock (lines)
            {
                lines.Add(line.Trim());
            }
        });

        await (await process.Exited.WaitAsync(Soon)).Should().BeEqualTo(0);
        List<string> seen;
        lock (lines)
        {
            seen = [.. lines];
        }
        await seen.Should().Contain("after-eof");
    }

    [Test]
    public async Task AnExitOnItsOwnGivesItsCode()
    {
        using var process = AetherProcess.Start(Shell("exit 3"), _ => { });

        await (await process.Exited.WaitAsync(Soon)).Should().BeEqualTo(3);
        await process.HasExited.Should().BeTrue();
    }

    [Test]
    public async Task AKillEndsWhatTheCoreStartedToo()
    {
        // The core's Psiphon client survives a kill of the core alone, holding its listener and its datastore lock.
        var grandchild = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        // A shell that waits for a program it started, which writes its own process id and sleeps.
        var script = OperatingSystem.IsWindows()
            ? "powershell -NoProfile -NonInteractive -Command Write-Output $PID; Start-Sleep -Seconds 60"
            : "sh -c 'echo $$; exec sleep 60'; true";
        using var process = AetherProcess.Start(Shell(script), line =>
        {
            if (int.TryParse(line.Trim(), out var pid))
            {
                grandchild.TrySetResult(pid);
            }
        });
        var pid = await grandchild.Task.WaitAsync(Soon);
        using (var running = Process.GetProcessById(pid))
        {
            await running.HasExited.Should().BeFalse();
        }

        await (await process.KillAsync(TimeSpan.FromSeconds(10))).Should().BeTrue();

        var gone = false;
        var waited = Stopwatch.StartNew();
        while (!gone && waited.Elapsed < TimeSpan.FromSeconds(10))
        {
            try
            {
                using var left = Process.GetProcessById(pid);
                gone = left.HasExited;
            }
            catch (ArgumentException)
            {
                gone = true;
            }
            if (!gone)
            {
                await Task.Delay(100);
            }
        }
        await gone.Should().BeTrue();
        await process.Exited.WaitAsync(Soon);
    }

    // A core of its own is released right after its kill: the wait for its exit reads the exit code before it waits for
    // the last lines, and a code that cannot be read any more is no failure of the wait.
    [Test]
    public async Task AKillAndAReleaseRightAfterItLeaveTheExitWithoutAFault()
    {
        var script = OperatingSystem.IsWindows() ? "ping -n 30 127.0.0.1 >NUL" : "sleep 30";
        for (var attempt = 0; attempt < 10; attempt++)
        {
            var process = AetherProcess.Start(Shell(script), _ => { });

            await process.KillAsync(TimeSpan.FromSeconds(10));
            process.Dispose();

            var exited = await process.Exited.WaitAsync(Soon);
            await process.Exited.IsFaulted.Should().BeFalse().Because($"attempt {attempt}");
            await (exited != 0).Should().BeTrue().Because($"attempt {attempt}");
        }
    }
}
