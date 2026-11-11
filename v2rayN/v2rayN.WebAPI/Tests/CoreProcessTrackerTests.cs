using System.Diagnostics;
using v2rayN.WebAPI.Services;

namespace v2rayN.WebAPI.Tests;

public class CoreProcessTrackerTests
{
    [Test]
    public async Task WebTrackerCapturesNewCoreProcessesAndPrunesExitedIdentities()
    {
        if (!OperatingSystem.IsLinux()) return;

        using var directory = new TemporaryDirectory();
        var executable = CopySleepExecutable(directory.Path);
        var existingProcessIds = CoreProcessTracker.CaptureExistingProcessIds();
        using var process = StartSleepProcess(executable);
        try
        {
            var tracked = CoreProcessTracker.CaptureStartedProcesses(existingProcessIds, [executable]);
            await tracked.Any(identity => identity.ProcessId == process.Id).Should().BeTrue();
            await CoreProcessTracker.GetActiveProcesses(tracked)
                .Any(identity => identity.ProcessId == process.Id)
                .Should().BeTrue();

            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
            await CoreProcessTracker.GetActiveProcesses(tracked).Length.Should().BeEqualTo(0);
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
            }
        }
    }

    [Test]
    public async Task WebTrackerDoesNotClaimProcessesThatPredateItsLaunchSnapshot()
    {
        if (!OperatingSystem.IsLinux()) return;

        using var directory = new TemporaryDirectory();
        var executable = CopySleepExecutable(directory.Path);
        using var process = StartSleepProcess(executable);
        var existingProcessIds = CoreProcessTracker.CaptureExistingProcessIds();
        var tracked = CoreProcessTracker.CaptureStartedProcesses(existingProcessIds, [executable]);

        try
        {
            await tracked.Any(identity => identity.ProcessId == process.Id).Should().BeFalse();
        }
        finally
        {
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
        }
    }

    [Test]
    public async Task WebTrackerRecognizesAnExecutableRunningThroughItsInterpreter()
    {
        if (!OperatingSystem.IsLinux()) return;
        using var directory = new TemporaryDirectory();
        var executable = Path.Combine(directory.Path, "test-core-shim");
        await File.WriteAllTextAsync(executable, "#!/bin/sh\nsleep 60\n");
        File.SetUnixFileMode(executable, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        var existingProcessIds = CoreProcessTracker.CaptureExistingProcessIds();
        using var process = Process.Start(new ProcessStartInfo(executable) { UseShellExecute = false })
            ?? throw new InvalidOperationException("Could not start the Core shim test process.");
        try
        {
            var tracked = CoreProcessTracker.CaptureStartedProcesses(existingProcessIds, [executable]);
            await tracked.Any(identity => identity.ProcessId == process.Id).Should().BeTrue();
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
            }
        }
    }

    [Test]
    public async Task WebTrackerDoesNotClaimSameNamedExecutableFromAnotherPath()
    {
        if (!OperatingSystem.IsLinux()) return;
        using var directory = new TemporaryDirectory();
        var unrelatedExecutable = Path.Combine(directory.Path, "sleep");
        File.Copy("/bin/sleep", unrelatedExecutable);

        var existingProcessIds = CoreProcessTracker.CaptureExistingProcessIds();
        using var process = StartSleepProcess(unrelatedExecutable);
        try
        {
            var tracked = CoreProcessTracker.CaptureStartedProcesses(existingProcessIds, ["/bin/sleep"]);
            await tracked.Any(identity => identity.ProcessId == process.Id).Should().BeFalse();
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
            }
        }
    }

    [Test]
    public async Task LinuxTrackerRequiresTheWebCoreConfigPathWhenProvided()
    {
        if (!OperatingSystem.IsLinux()) return;
        using var directory = new TemporaryDirectory();
        var executable = Path.Combine(directory.Path, "test-core-shim");
        var configPath = Path.Combine(directory.Path, "config.json");
        await File.WriteAllTextAsync(executable, "#!/bin/sh\nsleep 60\n");
        await File.WriteAllTextAsync(configPath, "{}");
        File.SetUnixFileMode(executable, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        var existingProcessIds = CoreProcessTracker.CaptureExistingProcessIds();
        var startInfo = new ProcessStartInfo(executable) { UseShellExecute = false };
        startInfo.ArgumentList.Add(configPath);
        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Could not start the Core shim test process.");
        try
        {
            var tracked = CoreProcessTracker.CaptureStartedProcesses(existingProcessIds, [executable], [configPath]);
            await tracked.Any(identity => identity.ProcessId == process.Id).Should().BeTrue();
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
            }
        }
    }

    [Test]
    public async Task WebTrackerRejectsReusedPidWithDifferentStartTimeOrExecutable()
    {
        if (!OperatingSystem.IsLinux()) return;
        using var directory = new TemporaryDirectory();
        var executable = CopySleepExecutable(directory.Path);
        var existingProcessIds = CoreProcessTracker.CaptureExistingProcessIds();
        using var process = StartSleepProcess(executable);
        try
        {
            var tracked = CoreProcessTracker.CaptureStartedProcesses(existingProcessIds, [executable]);
            var identity = tracked.Single(item => item.ProcessId == process.Id);

            await CoreProcessTracker.GetActiveProcesses([identity with { StartTimeUtcTicks = identity.StartTimeUtcTicks + 1 }])
                .Length.Should().BeEqualTo(0);
            await CoreProcessTracker.GetActiveProcesses([identity with { ExecutablePath = "/tmp/unrelated-core" }])
                .Length.Should().BeEqualTo(0);
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
            }
        }
    }

    // PattN: a Core update tells the configuration's cores that run from the folder it replaces, whatever core the
    // runtime names (V2rayRuntime.IsCoreTypeRunning); the program's path is the one the tracker reads from the process.
    [Test]
    public async Task ACoreIsKnownToRunFromItsOwnFolderOnly()
    {
        using var directory = new TemporaryDirectory();
        var folder = System.IO.Path.Combine(directory.Path, "xray");
        Directory.CreateDirectory(folder);
        var copy = System.IO.Path.Combine(folder, OperatingSystem.IsWindows() ? "p-xray-p.exe" : "sleep-core-test");
        File.Copy(OperatingSystem.IsWindows() ? System.IO.Path.Combine(Environment.SystemDirectory, "PING.EXE") : "/bin/sleep", copy);
        var startInfo = new ProcessStartInfo(copy) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true };
        foreach (var argument in OperatingSystem.IsWindows() ? ["-n", "60", "127.0.0.1"] : new[] { "60" })
        {
            startInfo.ArgumentList.Add(argument);
        }
        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start the test process.");
        try
        {
            var identity = CoreProcessTracker.CaptureProcess(process.Id).Single();

            await CoreProcessTracker.RunsFrom(identity, folder).Should().BeTrue();
            await CoreProcessTracker.RunsFrom(identity, directory.Path).Should().BeFalse();
            await CoreProcessTracker.RunsFrom(identity, System.IO.Path.Combine(directory.Path, "sing_box")).Should().BeFalse();
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
            await process.WaitForExitAsync();
            // Windows may hold the program's file a moment after its process ends.
            for (var tries = 0; File.Exists(copy) && tries < 50; tries++)
            {
                try
                {
                    File.Delete(copy);
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    await Task.Delay(100);
                }
            }
        }
    }

    private static Process StartSleepProcess(string executable = "/bin/sleep")
    {
        var startInfo = new ProcessStartInfo(executable) { UseShellExecute = false };
        startInfo.ArgumentList.Add("60");
        return Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start the test process.");
    }

    private static string CopySleepExecutable(string directory)
    {
        // Multicall implementations dispatch by basename, so preserve the sleep utility name.
        var executable = Path.Combine(directory, "sleep");
        File.Copy("/bin/sleep", executable);
        return executable;
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"v2rayn-WebAPI-core-tracker-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose() => Directory.Delete(Path, recursive: true);
    }
}
