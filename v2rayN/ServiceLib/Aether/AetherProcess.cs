using System.Globalization;

namespace ServiceLib.Aether;

/// <summary>What an Aether core runs for: its environment and the label of its output depend on it (design 2.6.2, 2.14).</summary>
public enum AetherRole
{
    /// <summary>The core of the running configuration.</summary>
    Session,

    /// <summary>A latency test's own core, on the Aether listen port while no session runs on it.</summary>
    Test,

    /// <summary>A scan for an endpoint.</summary>
    Scan,

    /// <summary>A run that registers new WARP keys.</summary>
    Key,
}

/// <summary>
/// Where the programs of the Aether core and its state are: the folders of <see cref="AetherPaths" /> and
/// <see cref="AetherBinaries" /> in PattN, a test's own folders in tests.
/// </summary>
/// <param name="ConfigDir">guiConfigs, which holds the working folder of the cores and the Psiphon datastores.</param>
/// <param name="BinDir">bin/aether, which holds the core and its helpers.</param>
public sealed record AetherFolders(string ConfigDir, string BinDir)
{
    /// <summary>The folders of this PattN.</summary>
    public static AetherFolders Default()
    {
        // bin/aether by its path alone: AetherBinaries.Folder would create the folder for a PattN that never runs Aether.
        return new AetherFolders(Utils.GetConfigPath(), Path.Combine(Utils.GetBinPath(""), nameof(ECoreType.aether)));
    }

    /// <summary>The working folder of every core, with the keys in use.</summary>
    public string WorkDir => Path.Combine(ConfigDir, AetherPaths.WorkDirName);

    /// <summary>The Psiphon datastore of the session.</summary>
    public string PsiphonStateDir => Path.Combine(ConfigDir, AetherPaths.PsiphonStateDirName);

    /// <summary>The Psiphon datastore of tests, scans and key runs.</summary>
    public string PsiphonProbeDir => Path.Combine(ConfigDir, AetherPaths.PsiphonProbeDirName);

    public string CoreFile => AetherBinaries.FileIn(BinDir, AetherBinaries.CoreName);
    public string PsiphonFile => AetherBinaries.FileIn(BinDir, AetherBinaries.PsiphonName);

    /// <summary>The process of the session core, for leftover cores on Linux and macOS (design 2.6.6).</summary>
    public string SessionPidFile => Path.Combine(WorkDir, AetherPaths.SessionPidFileName);

    /// <summary>The process of the core of a test, a scan or a key run.</summary>
    public string RunPidFile => Path.Combine(WorkDir, AetherPaths.RunPidFileName);
}

/// <summary>A running core as <see cref="AetherCoreManager" /> watches and ends it: an <see cref="AetherProcess" />, or a fake in tests.</summary>
public interface IAetherCoreProcess : IDisposable
{
    int Id { get; }

    /// <summary>When the process started, in UTC.</summary>
    DateTime StartedAt { get; }

    bool HasExited { get; }

    /// <summary>The exit code, once the process has exited and the lines it wrote have been read.</summary>
    Task<int> Exited { get; }

    /// <summary>
    /// Kills the process and every process it started; true when it is gone within <paramref name="wait" />. The core
    /// has no signal handling, and its Psiphon client survives a kill of the core alone, holding its listener and its
    /// datastore lock (PattNG AetherCoreManager.end).
    /// </summary>
    Task<bool> KillAsync(TimeSpan wait);
}

/// <summary>
/// One spawned Aether core (design 2.6.1, PattNG AetherCoreManager.startProcess and end). PattN's
/// <see cref="Services.ProcessService" /> takes one argument string, hands the core the terminal PattN was started from
/// and kills the core without what it started, each of which is wrong for the core, which is why it has a class of its
/// own: its arguments go one by one (no quoting rule can change a word), its stdin is a pipe closed at once (the core asks
/// for its settings only on a terminal), stdout and stderr are read line by line, without colour codes, and a stop kills
/// the whole tree.
/// </summary>
public sealed class AetherProcess : IAetherCoreProcess
{
    /// <summary>
    /// The exit code of a Windows program for which a DLL it needs is missing (STATUS_DLL_NOT_FOUND, 0xC0000135): an
    /// aether-core built before 2.3.2 without the Visual C++ runtime. It prints nothing then (design 2.4.4).
    /// </summary>
    public const int DllNotFoundExitCode = unchecked((int)0xC0000135);

    /// <summary>How long the reading of the core's output may go on once it has exited: a helper it started may hold the pipes.</summary>
    private static readonly TimeSpan OutputDrainWait = TimeSpan.FromSeconds(1);

    private readonly Process _process;
    private readonly Action<string> _onLine;
    private readonly Task _stdout;
    private readonly Task _stderr;

    private AetherProcess(Process process, Action<string> onLine)
    {
        _process = process;
        _onLine = onLine;
        StartedAt = StartTimeOf(process);
        _stdout = Task.Run(() => PumpAsync(process.StandardOutput));
        _stderr = Task.Run(() => PumpAsync(process.StandardError));
        Exited = WaitForExitAsync();
    }

    public int Id => _process.Id;

    public DateTime StartedAt { get; }

    public bool HasExited => _process.HasExited;

    public Task<int> Exited { get; }

    /// <summary>The process itself, for the Windows job object PattN's cores end with.</summary>
    internal Process Process => _process;

    /// <summary>
    /// The variable of the core's environment that overrides its --log-level, the way a Rust program reads its log filter.
    /// </summary>
    public const string RustLogEnv = "RUST_LOG";

    /// <summary>
    /// The way <paramref name="coreFile" /> is started on <paramref name="arguments" /> for <paramref name="role" />
    /// (design 2.6.1, 2.6.2): in the working folder, where the core's relative defaults resolve; with the identity files
    /// of the working folder, or those of <paramref name="keysDir" />, where a renewal gathers its new keys; with the
    /// session's Psiphon datastore or the one of every other core, since the client holds its datastore under a lock and a
    /// second client on the same one gives up after a second; with the Psiphon client named when it is there; and without
    /// colour codes. Nothing else of PattNG's Android environment is set: desktop programs read the system's roots and
    /// resolvers, and HOME stays the user's, where the core looks for Tor Browser's transports. The core takes every
    /// setting a flag gives from an AETHER_ variable as well, and its log filter from RUST_LOG: whatever of them PattN's
    /// own environment holds (a user who runs the aether command line too may keep some) is left out, so that the core
    /// runs as its arguments say, the ports, names and readiness PattN works out from them included.
    /// </summary>
    public static ProcessStartInfo StartInfo(AetherFolders folders, IReadOnlyList<string> arguments, AetherRole role, string? keysDir = null)
    {
        var info = new ProcessStartInfo
        {
            FileName = folders.CoreFile,
            WorkingDirectory = folders.WorkDir,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = new UTF8Encoding(false),
            StandardErrorEncoding = new UTF8Encoding(false),
        };
        foreach (var argument in arguments)
        {
            info.ArgumentList.Add(argument);
        }
        var keys = keysDir ?? folders.WorkDir;
        var environment = info.Environment;
        foreach (var inherited in environment.Keys.Where(IsCoreSetting).ToList())
        {
            environment.Remove(inherited);
        }
        environment["AETHER_CONFIG"] = Path.Combine(folders.WorkDir, AetherPaths.BaseFile);
        environment["AETHER_MASQUE_CONFIG"] = Path.Combine(keys, AetherPaths.MasqueFile);
        environment["AETHER_WG_CONFIG"] = Path.Combine(keys, AetherPaths.WireGuardFile);
        environment[AetherArguments.PsiphonDirEnv] = role == AetherRole.Session ? folders.PsiphonStateDir : folders.PsiphonProbeDir;
        if (AetherBinaries.IsRunnable(folders.PsiphonFile))
        {
            environment[AetherArguments.PsiphonBinEnv] = Path.GetFullPath(folders.PsiphonFile);
        }
        else
        {
            environment.Remove(AetherArguments.PsiphonBinEnv);
        }
        environment["NO_COLOR"] = "1";
        return info;
    }

    /// <summary>
    /// Starts the core <paramref name="startInfo" /> describes; each line it writes, on stdout or stderr, goes to
    /// <paramref name="onLine" /> without colour codes, from a thread of the pool. Throws what
    /// <see cref="System.Diagnostics.Process.Start()" /> throws when it cannot start: a missing file or one that cannot run.
    /// </summary>
    public static AetherProcess Start(ProcessStartInfo startInfo, Action<string> onLine)
    {
        var process = new Process { StartInfo = startInfo };
        try
        {
            process.Start();
        }
        catch
        {
            process.Dispose();
            throw;
        }
        try
        {
            // The core asks for its protocol, transport and scan only when stdin is a terminal; a closed pipe has nobody to ask.
            process.StandardInput.Close();
        }
        catch (IOException)
        {
            // It may be gone already.
        }
        return new AetherProcess(process, onLine);
    }

    public async Task<bool> KillAsync(TimeSpan wait)
    {
        try
        {
            _process.Kill(entireProcessTree: true);
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or NotSupportedException or AggregateException)
        {
            // Exited already, or gone while its tree was walked.
        }
        try
        {
            await _process.WaitForExitAsync().WaitAsync(wait).ConfigureAwait(false);
            return true;
        }
        catch (TimeoutException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return true;
        }
    }

    public void Dispose()
    {
        _process.Dispose();
    }

    /// <summary>
    /// Whether <paramref name="name" />, a variable of PattN's own environment, is one the core reads its settings or its
    /// log filter from (see <see cref="StartInfo" />): a name the system compares without case on Windows.
    /// </summary>
    public static bool IsCoreSetting(string name)
    {
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        return name.StartsWith("AETHER_", comparison) || string.Equals(name, RustLogEnv, comparison);
    }

    private async Task<int> WaitForExitAsync()
    {
        await _process.WaitForExitAsync().ConfigureAwait(false);
        // The exit code is read before the output is waited for: the process may be released meanwhile, by a stop that
        // killed it and does not wait for its last lines.
        int exitCode;
        try
        {
            exitCode = _process.ExitCode;
        }
        catch (InvalidOperationException)
        {
            exitCode = -1;
        }
        // The last lines, the error the core stopped on among them, are read by now, or soon; a helper the core started may
        // hold the pipes open a while longer, which is not waited for.
        await Task.WhenAny(Task.WhenAll(_stdout, _stderr), Task.Delay(OutputDrainWait)).ConfigureAwait(false);
        return exitCode;
    }

    private async Task PumpAsync(StreamReader reader)
    {
        try
        {
            while (await reader.ReadLineAsync().ConfigureAwait(false) is { } line)
            {
                try
                {
                    _onLine(AetherLogLine.StripAnsi(line));
                }
                catch (Exception ex)
                {
                    Logging.SaveLog("AetherCore: a line of the core's output could not be handled", ex);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException)
        {
            // The pipe closed with the process.
        }
    }

    private static DateTime StartTimeOf(Process process)
    {
        try
        {
            return process.StartTime.ToUniversalTime();
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or NotSupportedException)
        {
            return DateTime.UtcNow;
        }
    }
}

/// <summary>
/// Cores PattN left behind on Linux and macOS, where no job object ends them with PattN (design 2.6.6, PattNG reapStale):
/// each core writes a file with its process id and start time, and the next core PattN starts kills a process that still
/// matches a file, unless it is a core PattN runs now.
/// </summary>
public static class AetherLeftovers
{
    /// <summary>
    /// A process as a pid file names it: its id, its start time in UTC ticks, and, on Linux, its start in clock ticks
    /// since boot as the kernel keeps it (<see cref="BootTicksOf(string)" />), which no change of the wall clock moves;
    /// null where it is not known.
    /// </summary>
    public sealed record Entry(int Pid, long StartTicks, long? BootTicks = null);

    /// <summary>The text of a pid file: the process id, its start time in UTC ticks, and its start since boot when known.</summary>
    public static string Format(int pid, DateTime startedAt, long? bootTicks = null)
    {
        var ticks = startedAt.ToUniversalTime().Ticks;
        return bootTicks is { } boot
            ? string.Create(CultureInfo.InvariantCulture, $"{pid} {ticks} {boot}")
            : string.Create(CultureInfo.InvariantCulture, $"{pid} {ticks}");
    }

    /// <summary>The process <paramref name="text" /> names, or null when it names none.</summary>
    public static Entry? Parse(string? text)
    {
        var words = (text ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (words.Length is not (2 or 3)
            || !int.TryParse(words[0], NumberStyles.None, CultureInfo.InvariantCulture, out var pid)
            || pid <= 0
            || !long.TryParse(words[1], NumberStyles.None, CultureInfo.InvariantCulture, out var ticks))
        {
            return null;
        }
        long? boot = null;
        if (words.Length == 3)
        {
            if (!long.TryParse(words[2], NumberStyles.None, CultureInfo.InvariantCulture, out var bootTicks))
            {
                return null;
            }
            boot = bootTicks;
        }
        return new Entry(pid, ticks, boot);
    }

    /// <summary>
    /// The start of a process as its line of /proc/[pid]/stat gives it: field 22, in clock ticks since boot. The name of
    /// the program, field 2, is in parentheses and may hold spaces and parentheses itself, so the fields are counted after
    /// the last ')'. Null when <paramref name="stat" /> holds no such field.
    /// </summary>
    public static long? BootTicksOf(string? stat)
    {
        var end = stat?.LastIndexOf(')') ?? -1;
        if (end < 0)
        {
            return null;
        }
        // The fields after the name start with field 3, the state; field 22 is the 20th of them.
        var fields = stat![(end + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return fields.Length >= 20 && long.TryParse(fields[19], NumberStyles.None, CultureInfo.InvariantCulture, out var ticks)
            ? ticks
            : null;
    }

    /// <summary>The start since boot of the process <paramref name="pid" /> on Linux; null elsewhere, or when it cannot be read.</summary>
    public static long? BootTicksOf(int pid)
    {
        if (!OperatingSystem.IsLinux())
        {
            return null;
        }
        try
        {
            return BootTicksOf(File.ReadAllText($"/proc/{pid}/stat"));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>
    /// Whether the process that runs under the id of <paramref name="entry" /> is the core the file names: it runs
    /// <paramref name="coreFile" /> (on Linux and macOS by its real path, see <see cref="RealPathOf" />), and it started
    /// when the file says, by its start since boot where both are known (on Linux, where .NET derives the start time from
    /// the wall clock, which a clock step moves between two runs of PattN), or else at the time written down, within a
    /// second. A process id the system gave to another program since, or a process whose start or program cannot be read,
    /// is never killed.
    /// </summary>
    /// <param name="liveStartTicks">When the living process with that id started, in UTC ticks; null when none lives.</param>
    /// <param name="livePath">The program of that process; null when it cannot be read.</param>
    /// <param name="liveBootTicks">The start since boot of that process; null where it is not known.</param>
    public static bool IsLeftover(Entry entry, long? liveStartTicks, string? livePath, string coreFile, long? liveBootTicks = null)
    {
        if (liveStartTicks is not { } started || livePath == null)
        {
            return false;
        }
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var sameStart = entry.BootTicks is { } boot && liveBootTicks is { } liveBoot
            ? boot == liveBoot
            : Math.Abs(started - entry.StartTicks) < TimeSpan.TicksPerSecond;
        return sameStart && string.Equals(ProgramPathOf(livePath), ProgramPathOf(coreFile), comparison);
    }

    /// <summary>The path of a program as the system names it for a process that runs it: on Windows in full, elsewhere real.</summary>
    private static string ProgramPathOf(string path)
    {
        return OperatingSystem.IsWindows() ? Path.GetFullPath(path) : RealPathOf(path);
    }

    /// <summary>
    /// <paramref name="path" /> in full with every symbolic link on its way resolved, as Linux (/proc/[pid]/exe) and macOS
    /// (proc_pidpath) name the program a process runs: a core under /var or /tmp on macOS, which link to /private/var and
    /// /private/tmp, runs there as /private/var/… The resolving ends at a part that does not exist or cannot be read; what
    /// follows it is kept as it is.
    /// </summary>
    public static string RealPathOf(string path)
    {
        var full = Path.GetFullPath(path);
        // At most as many links as the systems follow on one path (SYMLOOP_MAX), so that a loop of links ends.
        for (var links = 0; links < 40; links++)
        {
            var root = Path.GetPathRoot(full) ?? string.Empty;
            var parts = full[root.Length..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);
            var resolved = root;
            string? relinked = null;
            for (var i = 0; i < parts.Length; i++)
            {
                var next = Path.Combine(resolved, parts[i]);
                var target = LinkTargetOf(next);
                if (target == null)
                {
                    resolved = next;
                    continue;
                }
                // A target is relative to the folder that holds the link, unless it is a full path itself.
                relinked = Path.GetFullPath(Path.Combine(resolved, target, string.Join(Path.DirectorySeparatorChar, parts[(i + 1)..])));
                break;
            }
            if (relinked == null)
            {
                return resolved;
            }
            full = relinked;
        }
        return full;
    }

    /// <summary>What the symbolic link <paramref name="path" /> points to; null when it is no link, or is not there.</summary>
    private static string? LinkTargetOf(string path)
    {
        try
        {
            return new FileInfo(path).LinkTarget;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>Writes the pid file of <paramref name="process" />.</summary>
    public static void Write(string pidFile, IAetherCoreProcess process)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(pidFile)!);
            File.WriteAllText(pidFile, Format(process.Id, process.StartedAt, BootTicksOf(process.Id)));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Logging.SaveLog("AetherCore: the pid file of the core could not be written", ex);
        }
    }

    /// <summary>Removes the pid file of a core that has ended.</summary>
    public static void Delete(string pidFile)
    {
        try
        {
            File.Delete(pidFile);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Logging.SaveLog("AetherCore: the pid file of the core could not be removed", ex);
        }
    }

    /// <summary>
    /// Kills, with what it started, the core <paramref name="pidFile" /> names when it still runs, and removes the file;
    /// a core <paramref name="isLive" /> says PattN runs now, whose file it is, keeps both. The process id is asked about
    /// once the file was read: a core writes its file after it is known to run.
    /// </summary>
    public static void Reap(string pidFile, string coreFile, Func<int, bool>? isLive = null)
    {
        string text;
        try
        {
            if (!File.Exists(pidFile))
            {
                return;
            }
            text = File.ReadAllText(pidFile);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return;
        }
        var entry = Parse(text);
        if (entry != null && isLive?.Invoke(entry.Pid) == true)
        {
            return;
        }
        if (entry != null)
        {
            try
            {
                using var process = Process.GetProcessById(entry.Pid);
                long? started = process.StartTime.ToUniversalTime().Ticks;
                // On Windows as the process names it, which works right after its start (ProcUtils.WindowsProgramOf)
                var path = OperatingSystem.IsWindows() ? ProcUtils.WindowsProgramOf(entry.Pid) : process.MainModule?.FileName;
                if (IsLeftover(entry, started, path, coreFile, BootTicksOf(entry.Pid)))
                {
                    Logging.SaveLog($"AetherCore: killing a leftover core process, pid={entry.Pid}");
                    process.Kill(entireProcessTree: true);
                    process.WaitForExit(2000);
                }
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or Win32Exception or NotSupportedException)
            {
                // No such process any more, or none this user may read.
            }
        }
        Delete(pidFile);
    }
}
