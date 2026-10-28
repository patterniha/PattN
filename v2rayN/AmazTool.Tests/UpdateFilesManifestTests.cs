namespace AmazTool.Tests;

// The clean install: the files the replaced update recorded and the new archive does
// not carry are deleted, and the user's data and the cores are never candidates.
public class UpdateFilesManifestTests
{
    [Test]
    public async Task TheFilesTheNewArchiveDoesNotCarryAreDeleted()
    {
        var previous = Set("PattN.exe", "AmazTool.exe", "libSkiaSharp.dll", "locales/fr.dll");
        var current = Set("PattN.exe", "AmazTool.exe", "libSkiaRenamed.dll");

        await Join(UpdateFilesManifest.FilesToDelete(previous, current, StringComparison.OrdinalIgnoreCase))
            .Should().BeEqualTo("libSkiaSharp.dll|locales/fr.dll");
    }

    [Test]
    public async Task TheUserDataAndTheCoresAreNeverDeleted()
    {
        var previous = Set("bin/xray/xray.exe", "bin/geoip.dat", "bin/srss/geoip-ir.srs",
            "binConfigs/core.json", "guiConfigs/guiNConfig.json", "guiLogs/app.log", "readme.txt");
        var current = Set("PattN.exe");

        await Join(UpdateFilesManifest.FilesToDelete(previous, current, StringComparison.OrdinalIgnoreCase))
            .Should().BeEqualTo("readme.txt");
    }

    [Test]
    public async Task TheExecutablesAreNeverDeleted()
    {
        var previous = Set("PattN.exe", "AmazTool.exe", "readme.txt");
        var current = Set("libSkiaSharp.dll");

        await Join(UpdateFilesManifest.FilesToDelete(previous, current, StringComparison.OrdinalIgnoreCase))
            .Should().BeEqualTo("readme.txt");
    }

    [Test]
    public async Task TheManifestIsNeverItsOwnCandidate()
    {
        var previous = Set(UpdateFilesManifest.FileName, "readme.txt");
        var current = Set();

        await Join(UpdateFilesManifest.FilesToDelete(previous, current, StringComparison.OrdinalIgnoreCase))
            .Should().BeEqualTo("readme.txt");
    }

    [Test]
    public async Task TheComparisonFollowsTheFilesystemOfTheInstallation()
    {
        var previous = Set("Libs/old.dll");
        var sameNameOtherCase = Set("libs/old.dll");

        await Join(UpdateFilesManifest.FilesToDelete(previous, sameNameOtherCase, StringComparison.OrdinalIgnoreCase))
            .Should().BeEqualTo("");
        await Join(UpdateFilesManifest.FilesToDelete(previous, sameNameOtherCase, StringComparison.Ordinal))
            .Should().BeEqualTo("Libs/old.dll");
    }

    [Test]
    public async Task AVersionWithoutAManifestCleansNothing()
    {
        await Join(UpdateFilesManifest.FilesToDelete(null, Set("PattN.exe"), StringComparison.OrdinalIgnoreCase))
            .Should().BeEqualTo("");
        await Join(UpdateFilesManifest.FilesToDelete(Set(), Set("PattN.exe"), StringComparison.OrdinalIgnoreCase))
            .Should().BeEqualTo("");
    }

    [Test]
    public async Task TheEntriesAreOnePerFileWhateverTheArchiveWrote()
    {
        await UpdateFilesManifest.Normalize("bin//xray///xray.exe").Should().BeEqualTo("bin/xray/xray.exe");
        await UpdateFilesManifest.Normalize("/").Should().BeEqualTo("");
    }

    [Test]
    public async Task TheManifestIsAbsentWithoutAFile()
    {
        var directory = NewDirectory();
        try
        {
            await UpdateFilesManifest.Load(directory, StringComparison.OrdinalIgnoreCase).Should().BeNull();
        }
        finally
        {
            Directory.Delete(directory, true);
        }
    }

    [Test]
    public async Task TheManifestCarriesItsFilesToTheNextUpdate()
    {
        var directory = NewDirectory();
        try
        {
            UpdateFilesManifest.Save(directory, ["PattN.exe", "bin/geoip.dat", "AmazTool.exe", "bin//geoip.dat", ""]);

            var files = UpdateFilesManifest.Load(directory, StringComparison.OrdinalIgnoreCase);
            await Join(files).Should().BeEqualTo("AmazTool.exe|PattN.exe|bin/geoip.dat");
        }
        finally
        {
            Directory.Delete(directory, true);
        }
    }

    private static string Join(IEnumerable<string>? files) =>
        string.Join("|", (files ?? []).Order(StringComparer.Ordinal));

    private static HashSet<string> Set(params string[] files) => [.. files];

    private static string NewDirectory()
    {
        var directory = Path.Combine(Path.GetTempPath(), "AmazToolTests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }
}
