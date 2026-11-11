using System.IO.Compression;

namespace ServiceLib.Tests.Aether;

/// <summary>From PattNG PsiphonServerListTest, with a key of its own in place of Psiphon's.</summary>
public class PsiphonServerListTests : IDisposable
{
    private const string Entries = "0 0 0 0 {\"ipAddress\":\"203.0.113.9\"}\n0 0 0 0 {\"ipAddress\":\"203.0.113.10\"}\n";

    private readonly RSA _pair = RSA.Create(2048);
    private readonly string _keyText;

    public PsiphonServerListTests()
    {
        _keyText = Convert.ToBase64String(_pair.ExportSubjectPublicKeyInfo());
    }

    public void Dispose()
    {
        _pair.Dispose();
    }

    private string Sign(string data, RSA? key = null)
    {
        return Convert.ToBase64String((key ?? _pair).SignData(Encoding.UTF8.GetBytes(data), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    private static string DigestOf(string text)
    {
        return Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
    }

    /// <summary>A list the way Psiphon writes one: the package as JSON, compressed.</summary>
    private byte[] Pack(string data = Entries, string? signature = null, string? keyDigest = null)
    {
        var json = $"{{\"data\":{JsonUtils.Serialize(data, false)},\"signingPublicKeyDigest\":\"{keyDigest ?? DigestOf(_keyText)}\",\"signature\":\"{signature ?? Sign(data)}\"}}";
        using var output = new MemoryStream();
        using (var zlib = new ZLibStream(output, CompressionLevel.Optimal))
        {
            zlib.Write(Encoding.UTF8.GetBytes(json));
        }
        return output.ToArray();
    }

    private static string NewFolder(string parent, string name)
    {
        return Directory.CreateDirectory(Path.Combine(parent, name)).FullName;
    }

    private static void SetLastModified(string path, long millis)
    {
        File.SetLastWriteTimeUtc(path, DateTimeOffset.FromUnixTimeMilliseconds(millis).UtcDateTime);
    }

    [Test]
    public async Task AListSignedWithTheKeyUnpacksToItsEntries()
    {
        await PsiphonServerList.Unpack(Pack(), _keyText).Should().BeEqualTo(Entries);
    }

    [Test]
    public async Task AListThatIsNotPsiphonsIsRefused()
    {
        // Entries added after signing.
        Action added = () => PsiphonServerList.Unpack(Pack(data: Entries + "0 0 0 0 {}\n", signature: Sign(Entries)), _keyText);
        await added.Should().Throw<IOException>();
        // Signed with another key that names ours.
        using var other = RSA.Create(2048);
        Action otherKey = () => PsiphonServerList.Unpack(Pack(signature: Sign(Entries, other)), _keyText);
        await otherKey.Should().Throw<IOException>();
        // Naming another key.
        Action namingAnother = () => PsiphonServerList.Unpack(Pack(keyDigest: DigestOf("someone else")), _keyText);
        await namingAnother.Should().Throw<IOException>();
        // Not a list at all, and a list of nothing.
        Action notAList = () => PsiphonServerList.Unpack(Encoding.UTF8.GetBytes("not a list"), _keyText);
        await notAList.Should().Throw<IOException>();
        Action nothing = () => PsiphonServerList.Unpack(Pack(data: "\n"), _keyText);
        await nothing.Should().Throw<IOException>();
    }

    [Test]
    public async Task TheCountriesOnOfferAreReadFromTheEntries()
    {
        static string Entry(string? region)
        {
            var line = "203.0.113.9 22 secret certificate " +
                (region == null ? "{}" : $"{{\"ipAddress\":\"203.0.113.9\",\"region\":\"{region}\"}}");
            return Convert.ToHexStringLower(Encoding.UTF8.GetBytes(line));
        }
        var text = string.Join("\n", Entry("de"), Entry("US"), Entry("DE"), Entry(null), "not hex at all", "", "abc");

        await PsiphonServerList.Regions(text).SequenceEqual(["DE", "US"]).Should().BeTrue();
        await PsiphonServerList.Regions("").Should().BeEmpty();

        // The core's report of what Psiphon can leave from, as it comes through the log.
        await PsiphonServerList.RegionsOf("[2026-09-24T20:43:04.197Z INFO  aether::psiphon] [*] psiphon can leave from: US CA DE")!
            .SequenceEqual(["US", "CA", "DE"]).Should().BeTrue();
        await PsiphonServerList.RegionsOf("[*] psiphon reached a server at 203.0.113.9").Should().BeNull();
        await PsiphonServerList.RegionsOf("psiphon can leave from: usa").Should().BeNull();
    }

    [Test]
    public async Task TheBundledListGoesOverACopyOnlyWhenItWasPublishedLater()
    {
        var folder = Directory.CreateTempSubdirectory("pattn-psiphon-").FullName;
        try
        {
            var copy = Path.Combine(NewFolder(folder, "assets"), AetherPaths.PsiphonServersFileName);
            await PsiphonServerList.BundledListGoesOver(copy, 0L, keptByUser: false).Should().BeTrue();
            await PsiphonServerList.BundledListGoesOver(copy, 0L, keptByUser: true).Should().BeTrue();

            File.WriteAllBytes(copy, Pack());
            SetLastModified(copy, 1_700_000_000_000L);
            // Published after the copy was made: a newer list.
            await PsiphonServerList.BundledListGoesOver(copy, 1_700_000_100_000L, keptByUser: false).Should().BeTrue();
            // Published at or before the copy's time: the copy holds that list already.
            await PsiphonServerList.BundledListGoesOver(copy, 1_700_000_000_000L, keptByUser: false).Should().BeFalse();
            await PsiphonServerList.BundledListGoesOver(copy, 1_600_000_000_000L, keptByUser: false).Should().BeFalse();
            // Without a stamp there is no telling, and the copy stays.
            await PsiphonServerList.BundledListGoesOver(copy, 0L, keptByUser: false).Should().BeFalse();
            // A file the user picked stays whatever the build brings.
            await PsiphonServerList.BundledListGoesOver(copy, 1_700_000_100_000L, keptByUser: true).Should().BeFalse();
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    [Test]
    public async Task ThePublicationStampIsSecondsSinceTheEpochOrNothing()
    {
        await PsiphonServerList.PublishedAt("1790000000\n").Should().BeEqualTo(1_790_000_000_000L);
        await PsiphonServerList.PublishedAt(" 1790000000 ").Should().BeEqualTo(1_790_000_000_000L);
        await PsiphonServerList.PublishedAt(null).Should().BeEqualTo(0L);
        await PsiphonServerList.PublishedAt("").Should().BeEqualTo(0L);
        await PsiphonServerList.PublishedAt("yesterday").Should().BeEqualTo(0L);
        await PsiphonServerList.PublishedAt("-5").Should().BeEqualTo(0L);
    }

    [Test]
    public async Task TheEntriesAreWrittenOncePerVersionOfTheListAndKeptWhenTheNextOneIsBroken()
    {
        var folder = Directory.CreateTempSubdirectory("pattn-psiphon-").FullName;
        try
        {
            var assets = NewFolder(folder, "assets");
            var work = NewFolder(folder, "work");
            await PsiphonServerList.EntriesFile(assets, work, _keyText).Should().BeNull();

            var source = Path.Combine(assets, AetherPaths.PsiphonServersFileName);
            File.WriteAllBytes(source, Pack());
            var first = PsiphonServerList.EntriesFile(assets, work, _keyText)!;
            await File.ReadAllText(first).Should().BeEqualTo(Entries);
            // The same version of the list is not unpacked again.
            File.WriteAllText(first, "left alone");
            await File.ReadAllText(PsiphonServerList.EntriesFile(assets, work, _keyText)!).Should().BeEqualTo("left alone");

            // A new version is.
            var more = Entries + "0 0 0 0 {\"ipAddress\":\"203.0.113.11\"}\n";
            File.WriteAllBytes(source, Pack(data: more));
            File.SetLastWriteTimeUtc(source, File.GetLastWriteTimeUtc(source).AddSeconds(5));
            await File.ReadAllText(PsiphonServerList.EntriesFile(assets, work, _keyText)!).Should().BeEqualTo(more);

            // A broken replacement leaves the last good entries in place, and says why.
            File.WriteAllBytes(source, Encoding.UTF8.GetBytes("garbage"));
            File.SetLastWriteTimeUtc(source, File.GetLastWriteTimeUtc(source).AddSeconds(5));
            var problems = new List<IOException>();
            await File.ReadAllText(PsiphonServerList.EntriesFile(assets, work, _keyText, problems.Add)!).Should().BeEqualTo(more);
            await problems.Should().HaveCount(1);

            // Without the list there is nothing to hand on.
            File.Delete(source);
            await PsiphonServerList.EntriesFile(assets, work, _keyText).Should().BeNull();
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    // PattN: the key the list is checked with is Psiphon's own, the one PattNG and the core carry.
    [Test]
    public async Task TheSigningKeyIsPsiphonsRsaKey()
    {
        using var key = RSA.Create();
        key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(PsiphonServerList.SigningKey), out var read);
        await read.Should().BeEqualTo(Convert.FromBase64String(PsiphonServerList.SigningKey).Length);
        await key.KeySize.Should().BeEqualTo(4096);
        // Psiphon's lists name the key by the digest of its text, as signingPublicKeyDigest: a key that imports but
        // differs in one character would refuse every real list.
        await Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(PsiphonServerList.SigningKey)))
            .Should().BeEqualTo("V92HkhTZqeRRlgmIPuyWpod5nJm7xLz14BXYw6BjaPc=");
    }

    // PattN: the active list is read sharing it with whoever replaces it, as a rename over it always can on Android.
    // Windows refuses to open a file that another handle may delete unless the opening shares deleting as well.
    [Test]
    public async Task TheListIsReadWithoutKeepingItFromBeingReplaced()
    {
        var folder = Directory.CreateTempSubdirectory("pattn-psiphon-").FullName;
        try
        {
            var source = Path.Combine(folder, AetherPaths.PsiphonServersFileName);
            File.WriteAllBytes(source, Pack());
            // A handle that may delete the list, as one that replaces it holds.
            using (new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.DeleteOnClose))
            {
                var problems = new List<IOException>();
                var entries = PsiphonServerList.EntriesFile(folder, folder, _keyText, problems.Add);
                await problems.Should().BeEmpty();
                await (entries == null ? null : File.ReadAllText(entries)).Should().BeEqualTo(Entries);
            }
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    // PattN: a new list takes the place of the active one even while it is being read, as a rename does on Android;
    // File.Move cannot replace a file another handle holds open on Windows, File.Replace can.
    [Test]
    public async Task ANewListTakesThePlaceOfTheOneBeingRead()
    {
        var folder = Directory.CreateTempSubdirectory("pattn-psiphon-").FullName;
        try
        {
            var active = Path.Combine(folder, AetherPaths.PsiphonServersFileName);
            var downloaded = Path.Combine(folder, "download.new");
            // Nothing in place yet: the list moves there.
            File.WriteAllText(downloaded, "first");
            PsiphonServerList.Replace(downloaded, active);
            await File.ReadAllText(active).Should().BeEqualTo("first");
            await File.Exists(downloaded).Should().BeFalse();

            File.WriteAllText(downloaded, "second");
            using (var reading = new FileStream(active, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                PsiphonServerList.Replace(downloaded, active);
                // What was being read is read to its end.
                using var reader = new StreamReader(reading);
                await reader.ReadToEnd().Should().BeEqualTo("first");
            }
            await File.ReadAllText(active).Should().BeEqualTo("second");
            await File.Exists(downloaded).Should().BeFalse();

            // A handle that does not share deleting keeps the list in place on Windows: an IOException, whatever
            // Windows calls it, so that the caller reports it as it reports a failed download.
            if (OperatingSystem.IsWindows())
            {
                File.WriteAllText(downloaded, "third");
                using var holding = new FileStream(active, FileMode.Open, FileAccess.Read, FileShare.Read);
                Action replace = () => PsiphonServerList.Replace(downloaded, active);
                await replace.Should().Throw<IOException>();
            }
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }
}
