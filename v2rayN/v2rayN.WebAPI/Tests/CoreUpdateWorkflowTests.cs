using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using ServiceLib.Resx;
using v2rayN.WebAPI.Services;

namespace v2rayN.WebAPI.Tests;

public class CoreUpdateWorkflowTests
{
    [Test]
    public async Task CoreVersionCheckAcceptsVPrefixedMihomoVersion()
    {
        var output = "Mihomo Meta v1.19.31 linux amd64 with go1.26.8";

        await CoreExecutableVersionCheck.IsValid(output, "Mihomo").Should().BeTrue();
    }

    [Test]
    public async Task CoreVersionCheckStillRequiresExpectedNameAndSemanticVersion()
    {
        await CoreExecutableVersionCheck.IsValid("Xray 25.9.11", "Mihomo").Should().BeFalse();
        await CoreExecutableVersionCheck.IsValid("Mihomo Meta development build", "Mihomo").Should().BeFalse();
    }

    [Test]
    public async Task XraySingBoxAndMihomoPackagesAreStagedUsingTheirNativeArchiveFormats()
    {
        using var directory = new TemporaryDirectory();

        var xrayArchive = Path.Combine(directory.Path, "xray.zip");
        using (var zip = ZipFile.Open(xrayArchive, ZipArchiveMode.Create))
        {
            await WriteZipFileAsync(zip, "Xray/xray", "xray binary");
            await WriteZipFileAsync(zip, "Xray/geoip.dat", "bundled geo data");
        }
        var xrayStage = Path.Combine(directory.Path, "xray-stage");
        await CoreUpdatePackageStager.ExtractAsync(ECoreType.Xray, xrayArchive, xrayStage, CancellationToken.None);
        await File.Exists(Path.Combine(xrayStage, "xray")).Should().BeTrue();
        await File.Exists(Path.Combine(xrayStage, "geoip.dat")).Should().BeFalse();

        var mihomoArchive = Path.Combine(directory.Path, "mihomo.gz");
        await WriteGzipAsync(mihomoArchive, "mihomo binary");
        var mihomoStage = Path.Combine(directory.Path, "mihomo-stage");
        await CoreUpdatePackageStager.ExtractAsync(ECoreType.mihomo, mihomoArchive, mihomoStage, CancellationToken.None);
        var mihomoExecutable = Utils.GetExeName(CoreInfoManager.Instance.GetCoreInfo(ECoreType.mihomo)!.CoreExes!.First());
        await File.Exists(Path.Combine(mihomoStage, mihomoExecutable)).Should().BeTrue();

        var singBoxArchive = Path.Combine(directory.Path, "sing-box.tar.gz");
        await WriteTarGzipAsync(singBoxArchive, "sing-box-release/sing-box", "sing-box binary");
        var singBoxStage = Path.Combine(directory.Path, "sing-box-stage");
        await CoreUpdatePackageStager.ExtractAsync(ECoreType.sing_box, singBoxArchive, singBoxStage, CancellationToken.None);
        await File.Exists(Path.Combine(singBoxStage, "sing-box")).Should().BeTrue();
    }

    [Test]
    public async Task StagingAndVerificationAlwaysFinishBeforeApplyBegins()
    {
        var sequence = new List<string>();
        var result = await CoreUpdateWorkflow.StageThenApplyAsync(
            () =>
            {
                sequence.Add("checking");
                sequence.Add("downloading");
                sequence.Add("verifying");
                return Task.FromResult("verified-package");
            },
            staged =>
            {
                sequence.Add("stopping-core");
                sequence.Add("installing");
                return Task.FromResult(staged);
            });

        await (result == "verified-package").Should().BeTrue();
        await sequence.SequenceEqual(["checking", "downloading", "verifying", "stopping-core", "installing"]).Should().BeTrue();
    }

    [Test]
    public async Task FailedStagingNeverInvokesApply()
    {
        var applied = false;

        var failed = false;
        try
        {
            await CoreUpdateWorkflow.StageThenApplyAsync<string, bool>(
                () => throw new InvalidDataException("package verification failed"),
                _ =>
                {
                    applied = true;
                    return Task.FromResult(true);
                });
        }
        catch (InvalidDataException)
        {
            failed = true;
        }

        await failed.Should().BeTrue();
        await applied.Should().BeFalse();
    }

    [Test]
    public async Task SelectedBatchStagesEveryNetworkPackageBeforeAnyApply()
    {
        var sequence = new List<string>();
        var results = await CoreUpdateWorkflow.StageAllThenApplyAsync(
            new[] { "Xray", "sing-box", "Mihomo" },
            target =>
            {
                sequence.Add($"stage:{target}");
                return Task.FromResult($"verified:{target}");
            },
            stages =>
            {
                sequence.Add("CoreStop");
                sequence.AddRange(stages.Select(stage => $"apply:{stage}"));
                return Task.FromResult(stages.Count);
            },
            () =>
            {
                sequence.Add("prepare:GeoFiles");
                return Task.CompletedTask;
            });

        await results.Should().BeEqualTo(3);
        await sequence.SequenceEqual(new[]
        {
            "stage:Xray", "stage:sing-box", "stage:Mihomo", "prepare:GeoFiles", "CoreStop",
            "apply:verified:Xray", "apply:verified:sing-box", "apply:verified:Mihomo",
        }).Should().BeTrue();
    }

    [Test]
    public async Task FailedAdditionalNetworkPreparationPreventsEveryCoreApply()
    {
        var applied = false;
        var failed = false;
        try
        {
            await CoreUpdateWorkflow.StageAllThenApplyAsync(
                new[] { "Xray" },
                target => Task.FromResult($"verified:{target}"),
                _ =>
                {
                    applied = true;
                    return Task.FromResult(true);
                },
                () => throw new InvalidDataException("GeoFiles preparation failed."));
        }
        catch (InvalidDataException)
        {
            failed = true;
        }

        await failed.Should().BeTrue();
        await applied.Should().BeFalse();
    }

    [Test]
    public async Task FailedBatchStagingPreventsEveryCoreStopAndInstall()
    {
        var applied = false;
        var failed = false;
        try
        {
            await CoreUpdateWorkflow.StageAllThenApplyAsync(
                new[] { "Xray", "sing-box" },
                target => target == "sing-box"
                    ? throw new InvalidDataException("package verification failed")
                    : Task.FromResult($"verified:{target}"),
                stages =>
                {
                    applied = true;
                    return Task.FromResult(stages.Count);
                });
        }
        catch (InvalidDataException)
        {
            failed = true;
        }

        await failed.Should().BeTrue();
        await applied.Should().BeFalse();
    }

    [Test]
    public async Task SelectedBatchStagesWebWithOtherTargetsAndAppliesItOnlyAfterCoreAndGeo()
    {
        var sequence = new List<string>();
        await CoreUpdateWorkflow.StageAllThenApplyAsync(
            new[] { "Xray", "sing-box" },
            target =>
            {
                sequence.Add($"stage:{target}");
                return Task.FromResult(target);
            },
            stages =>
            {
                sequence.AddRange(stages.Select(stage => $"apply:{stage}"));
                sequence.Add("apply:GeoFiles");
                return Task.FromResult(true);
            },
            () =>
            {
                sequence.Add("prepare:GeoFiles");
                sequence.Add("stage:v2rayN.WebAPI");
                return Task.CompletedTask;
            });
        sequence.Add("apply:v2rayN.WebAPI");

        await sequence.SequenceEqual(new[]
        {
            "stage:Xray", "stage:sing-box", "prepare:GeoFiles", "stage:v2rayN.WebAPI",
            "apply:Xray", "apply:sing-box", "apply:GeoFiles", "apply:v2rayN.WebAPI",
        }).Should().BeTrue();
    }

    [Test]
    public async Task ApplyFailureRestoresThePreviousBinaryBeforeRestartingTheOldCore()
    {
        using var directory = new TemporaryDirectory();
        var install = Path.Combine(directory.Path, "xray");
        var backup = Path.Combine(directory.Path, ".xray-backup");
        Directory.CreateDirectory(install);
        Directory.CreateDirectory(backup);
        await File.WriteAllTextAsync(Path.Combine(install, "xray"), "new-binary");
        await File.WriteAllTextAsync(Path.Combine(backup, "xray"), "old-binary");
        var order = new List<string>();

        var rollback = await CoreUpdateWorkflow.RollBackAndRestoreAsync(
            () =>
            {
                CoreUpdateWorkflow.RestorePreviousDirectory(install, backup, candidateInstalled: true, hadInstalledCore: true);
                order.Add("restore-files");
                return Task.CompletedTask;
            },
            () => { order.Add("initialize-old"); return Task.CompletedTask; },
            wasRunning: true,
            restartPreviousCoreAsync: () => { order.Add("restart-old"); return Task.FromResult(true); });

        await rollback.Completed.Should().BeTrue();
        await (await File.ReadAllTextAsync(Path.Combine(install, "xray"))).Should().BeEqualTo("old-binary");
        await order.SequenceEqual(["restore-files", "initialize-old", "restart-old"]).Should().BeTrue();
    }

    [Test]
    public async Task FailedOldCoreRestartIsReportedAfterItsFilesHaveBeenRestored()
    {
        using var directory = new TemporaryDirectory();
        var install = Path.Combine(directory.Path, "xray");
        var backup = Path.Combine(directory.Path, ".xray-backup");
        Directory.CreateDirectory(install);
        Directory.CreateDirectory(backup);
        await File.WriteAllTextAsync(Path.Combine(install, "xray"), "new-binary");
        await File.WriteAllTextAsync(Path.Combine(backup, "xray"), "old-binary");

        var rollback = await CoreUpdateWorkflow.RollBackAndRestoreAsync(
            () =>
            {
                CoreUpdateWorkflow.RestorePreviousDirectory(install, backup, candidateInstalled: true, hadInstalledCore: true);
                return Task.CompletedTask;
            },
            () => Task.CompletedTask,
            wasRunning: true,
            restartPreviousCoreAsync: () => Task.FromResult(false));

        await rollback.FilesRestored.Should().BeTrue();
        await rollback.Completed.Should().BeFalse();
        await (await File.ReadAllTextAsync(Path.Combine(install, "xray"))).Should().BeEqualTo("old-binary");
    }

    // PattN: Utils.GetBinPath makes the folder of a core whenever it is asked for a path in it, so a request served
    // between the two moves of an update can leave an empty folder where the new or the previous Core goes.
    [Test]
    public async Task TheNewCoreMovesInOverAnEmptyFolderARequestMadeBetweenTheMoves()
    {
        using var directory = new TemporaryDirectory();
        var install = Path.Combine(directory.Path, "xray");
        var candidate = Path.Combine(directory.Path, ".xray-candidate");
        Directory.CreateDirectory(install);
        Directory.CreateDirectory(candidate);
        await File.WriteAllTextAsync(Path.Combine(candidate, "xray"), "new-binary");

        DirectorySwap.MoveIntoPlace(candidate, install);

        await (await File.ReadAllTextAsync(Path.Combine(install, "xray"))).Should().BeEqualTo("new-binary");
        await Directory.Exists(candidate).Should().BeFalse();
    }

    [Test]
    public async Task TheRollbackPutsThePreviousCoreBackOverAnEmptyFolderARequestMade()
    {
        using var directory = new TemporaryDirectory();
        var install = Path.Combine(directory.Path, "xray");
        var backup = Path.Combine(directory.Path, ".xray-backup");
        // The new Core never moved in: the place holds only the empty folder.
        Directory.CreateDirectory(install);
        Directory.CreateDirectory(backup);
        await File.WriteAllTextAsync(Path.Combine(backup, "xray"), "old-binary");

        var rollback = await CoreUpdateWorkflow.RollBackAndRestoreAsync(
            () =>
            {
                CoreUpdateWorkflow.RestorePreviousDirectory(install, backup, candidateInstalled: false, hadInstalledCore: true);
                return Task.CompletedTask;
            },
            () => Task.CompletedTask,
            wasRunning: false,
            restartPreviousCoreAsync: () => Task.FromResult(true));

        await rollback.Completed.Should().BeTrue();
        await (await File.ReadAllTextAsync(Path.Combine(install, "xray"))).Should().BeEqualTo("old-binary");
        await Directory.Exists(backup).Should().BeFalse();
    }

    [Test]
    public async Task ARollbackThatCannotPutThePreviousCoreBackFailsAndKeepsIt()
    {
        using var directory = new TemporaryDirectory();
        var install = Path.Combine(directory.Path, "xray");
        var backup = Path.Combine(directory.Path, ".xray-backup");
        // Something wrote a file where the previous Core goes: it is neither deleted nor reported restored.
        Directory.CreateDirectory(install);
        Directory.CreateDirectory(backup);
        await File.WriteAllTextAsync(Path.Combine(install, "geoip.dat"), "other");
        await File.WriteAllTextAsync(Path.Combine(backup, "xray"), "old-binary");

        IOException? failure = null;
        try
        {
            CoreUpdateWorkflow.RestorePreviousDirectory(install, backup, candidateInstalled: false, hadInstalledCore: true);
        }
        catch (IOException exception)
        {
            failure = exception;
        }

        await failure.Should().NotBeNull();
        await (await File.ReadAllTextAsync(Path.Combine(backup, "xray"))).Should().BeEqualTo("old-binary");
        await (await File.ReadAllTextAsync(Path.Combine(install, "geoip.dat"))).Should().BeEqualTo("other");
    }

    // PattN: what earlier updates left in bin goes: a backup a running program kept from deletion, a candidate, and, only
    // while no update runs, a staged package; nothing else, and no backup that is its core's only copy.
    [Test]
    public async Task LeftoversOfEarlierUpdatesAreRemoved()
    {
        using var directory = new TemporaryDirectory();
        var bin = directory.Path;
        string Folder(string name)
        {
            var path = Path.Combine(bin, name);
            Directory.CreateDirectory(path);
            File.WriteAllText(Path.Combine(path, "xray"), name);
            return path;
        }
        var id = Guid.NewGuid().ToString("N");
        var candidate = Folder($".Xray-candidate-{id}");
        var backup = Folder($".Xray-backup-{id}");
        var package = Folder($".Xray-package-{id}");
        var otherCore = Folder($".sing_box-backup-{id}");
        var notAnUpdates = Folder(".Xray-backup-mine");
        var install = Folder("xray");

        // While updates may run: the core's own candidates and backups, and no package.
        var left = CoreUpdateWorkflow.RemoveLeftovers(bin, [ECoreType.Xray], includePackages: false, _ => true);

        await left.Count.Should().BeEqualTo(0);
        await Directory.Exists(candidate).Should().BeFalse();
        await Directory.Exists(backup).Should().BeFalse();
        await Directory.Exists(package).Should().BeTrue();
        await Directory.Exists(otherCore).Should().BeTrue();

        // At a start: the packages too, of every core asked for.
        CoreUpdateWorkflow.RemoveLeftovers(bin, [ECoreType.Xray, ECoreType.sing_box], includePackages: true, _ => true);

        await Directory.Exists(package).Should().BeFalse();
        await Directory.Exists(otherCore).Should().BeFalse();
        await Directory.Exists(notAnUpdates).Should().BeTrue();
        await Directory.Exists(install).Should().BeTrue();
    }

    [Test]
    public async Task ABackupIsKeptWhileItsCoreIsNotInItsOwnFolder()
    {
        using var directory = new TemporaryDirectory();
        var backup = Path.Combine(directory.Path, $".Xray-backup-{Guid.NewGuid():N}");
        Directory.CreateDirectory(backup);
        await File.WriteAllTextAsync(Path.Combine(backup, "xray"), "old-binary");

        var left = CoreUpdateWorkflow.RemoveLeftovers(directory.Path, [ECoreType.Xray], includePackages: true, _ => false);

        await Directory.Exists(backup).Should().BeTrue();
        await left.Count.Should().BeEqualTo(1);
        await left[0].Should().Contain(backup);
    }

    [Test]
    public async Task OnlyTheExactUpdatedCoreIsStoppedAndRestarted()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var core in new[] { ECoreType.Xray, ECoreType.sing_box, ECoreType.mihomo })
        {
            await CoreUpdateRuntimePolicy.IsTargetRunning(core, core, now).Should().BeTrue();
            await CoreUpdateRuntimePolicy.IsTargetRunning(core, ECoreType.v2fly, now).Should().BeFalse();
            await CoreUpdateRuntimePolicy.IsTargetRunning(core, core, null).Should().BeFalse();
        }
        await CoreUpdatePackageStager.SupportsCore(ECoreType.Xray).Should().BeTrue();
        await CoreUpdatePackageStager.SupportsCore(ECoreType.sing_box).Should().BeTrue();
        await CoreUpdatePackageStager.SupportsCore(ECoreType.mihomo).Should().BeTrue();
        await CoreUpdatePackageStager.SupportsCore(ECoreType.v2rayN).Should().BeFalse();
    }

    [Test]
    public async Task CoreUpdatePreReleaseChoicesMatchDesktopCoreInfoSemantics()
    {
        var manager = CoreInfoManager.Instance;
        await manager.GetCheckPreRelease(ECoreType.Xray, true).Should().BeTrue();
        await manager.GetCheckPreRelease(ECoreType.v2rayN, true).Should().BeTrue();
        await manager.GetCheckPreRelease(ECoreType.mihomo, true).Should().BeFalse();
        await manager.GetCheckPreRelease(ECoreType.sing_box, true).Should().BeFalse();
    }

    [Test]
    public async Task CoreUpdateCheckPreservesServiceLibCurrentVersionSemantics()
    {
        var latest = string.Format(ResUI.IsLatestCore, ECoreType.Xray, "v1.2.3");
        await V2rayRuntime.IsUpToDateResult(ECoreType.Xray, latest).Should().BeTrue();
        await V2rayRuntime.IsUpToDateResult(ECoreType.Xray, "Could not reach release API").Should().BeFalse();
        await V2rayRuntime.IsUpToDateResult(ECoreType.Xray, null).Should().BeFalse();
    }

    private static async Task WriteZipFileAsync(ZipArchive zip, string name, string content)
    {
        await using var stream = zip.CreateEntry(name).Open();
        await stream.WriteAsync(Encoding.UTF8.GetBytes(content));
    }

    private static async Task WriteGzipAsync(string path, string content)
    {
        await using var file = File.Create(path);
        await using var gzip = new GZipStream(file, CompressionLevel.SmallestSize);
        await gzip.WriteAsync(Encoding.UTF8.GetBytes(content));
    }

    private static async Task WriteTarGzipAsync(string path, string entryName, string content)
    {
        await using var file = File.Create(path);
        await using var gzip = new GZipStream(file, CompressionLevel.SmallestSize, leaveOpen: true);
        using var writer = new TarWriter(gzip, TarEntryFormat.Pax, leaveOpen: true);
        var entry = new PaxTarEntry(TarEntryType.RegularFile, entryName)
        {
            DataStream = new MemoryStream(Encoding.UTF8.GetBytes(content)),
        };
        writer.WriteEntry(entry);
        await Task.CompletedTask;
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"v2rayn-WebAPI-core-update-test-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose() => Directory.Delete(Path, recursive: true);
    }
}
