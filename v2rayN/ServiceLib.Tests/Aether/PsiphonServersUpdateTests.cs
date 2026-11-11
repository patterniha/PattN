using System.Globalization;
using System.IO.Compression;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace ServiceLib.Tests.Aether;

/// <summary>
/// PattN (design 2.11, critiques 16 and 27): the Psiphon server list at run time: the copy of the list shipped with a
/// release at start, the check of a download, and the update that puts a download in place only once it is Psiphon's
/// signed list. With a key of the test's own in place of Psiphon's; nothing reaches the network (the downloader is a fake,
/// or the HTTP server is the test's own, on the loopback).
/// </summary>
public class PsiphonServersUpdateTests : IDisposable
{
    private readonly RSA _pair = RSA.Create(2048);
    private readonly string _keyText;
    private readonly string _root = Directory.CreateTempSubdirectory("pattn-psiphon-").FullName;

    public PsiphonServersUpdateTests()
    {
        _keyText = Convert.ToBase64String(_pair.ExportSubjectPublicKeyInfo());
    }

    public void Dispose()
    {
        _pair.Dispose();
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
            // The system cleans its temp folder.
        }
    }

    private static string Entries(int count)
    {
        var lines = Enumerable.Range(1, count).Select(index => $"0 0 0 0 {{\"ipAddress\":\"203.0.113.{index}\"}}");
        return string.Join("\n", lines) + "\n";
    }

    /// <summary>A list the way Psiphon writes one, signed with the test's key: the package as JSON, compressed.</summary>
    private byte[] Pack(string data)
    {
        var signature = Convert.ToBase64String(_pair.SignData(Encoding.UTF8.GetBytes(data), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        var digest = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(_keyText)));
        var json = $"{{\"data\":{JsonUtils.Serialize(data, false)},\"signingPublicKeyDigest\":\"{digest}\",\"signature\":\"{signature}\"}}";
        using var output = new MemoryStream();
        using (var zlib = new ZLibStream(output, CompressionLevel.Optimal))
        {
            zlib.Write(Encoding.UTF8.GetBytes(json));
        }
        return output.ToArray();
    }

    private string PathOf(string name)
    {
        return Path.Combine(_root, name);
    }

    private static DateTime Utc(int year, int month, int day)
    {
        return new DateTime(year, month, day, 12, 0, 0, DateTimeKind.Utc);
    }

    // ---- the check of a download

    [Test]
    public async Task ADownloadIsPsiphonsListOnlyWhenSignedWithFiftyEntriesAtLeast()
    {
        await PsiphonServerList.Verify(Pack(Entries(60)), _keyText).Should().BeEqualTo(60);
        await PsiphonServerList.Verify(Pack(Entries(50)), _keyText).Should().BeEqualTo(50);
        Action fortyNine = () => PsiphonServerList.Verify(Pack(Entries(49)), _keyText);
        await fortyNine.Should().Throw<IOException>();
        Action unsigned = () => PsiphonServerList.Verify(Encoding.UTF8.GetBytes("<html>captive portal</html>"), _keyText);
        await unsigned.Should().Throw<IOException>();
        // Blank lines are no entries.
        await PsiphonServerList.EntryCount("a\n\n  \nb\n").Should().BeEqualTo(2);
    }

    // ---- the copy at start (PattNG initAssets)

    [Test]
    public async Task TheBundledListFillsAMissingListWithItsPublicationTime()
    {
        var bundled = PathOf("bin-psiphon_servers.dat");
        var stamp = PathOf("bin-psiphon_servers.stamp");
        var active = Path.Combine(_root, "guiConfigs", "aether", "psiphon_servers.dat");
        File.WriteAllBytes(bundled, [1, 2, 3]);
        var published = new DateTimeOffset(Utc(2026, 9, 1));
        File.WriteAllText(stamp, published.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture) + "\n");

        await PsiphonServerList.InstallBundled(bundled, stamp, active).Should().BeTrue();

        await File.ReadAllBytes(active).SequenceEqual(new byte[] { 1, 2, 3 }).Should().BeTrue();
        await File.GetLastWriteTimeUtc(active).Should().BeEqualTo(published.UtcDateTime);
        // Nothing staged is left beside it.
        await Directory.GetFiles(Path.GetDirectoryName(active)!).Length.Should().BeEqualTo(1);
        // Once in place, the same release puts nothing again.
        await PsiphonServerList.InstallBundled(bundled, stamp, active).Should().BeFalse();
    }

    [Test]
    public async Task TheBundledListGoesOverAnOlderListOnly()
    {
        var bundled = PathOf("bundled.dat");
        var stamp = PathOf("bundled.stamp");
        var active = PathOf("active.dat");
        File.WriteAllBytes(bundled, [9]);
        File.WriteAllBytes(active, [1]);
        File.SetLastWriteTimeUtc(active, Utc(2026, 9, 10));

        // Published before the list in use (a download of the check-update window): it stays.
        File.WriteAllText(stamp, new DateTimeOffset(Utc(2026, 9, 1)).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture));
        await PsiphonServerList.InstallBundled(bundled, stamp, active).Should().BeFalse();
        await File.ReadAllBytes(active).SequenceEqual(new byte[] { 1 }).Should().BeTrue();

        // Without a usable stamp, only a missing list is filled.
        File.WriteAllText(stamp, "not a time");
        await PsiphonServerList.InstallBundled(bundled, stamp, active).Should().BeFalse();
        await PsiphonServerList.InstallBundled(bundled, PathOf("no-stamp"), active).Should().BeFalse();

        // Published later: it goes over the list in use.
        File.WriteAllText(stamp, new DateTimeOffset(Utc(2026, 9, 20)).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture));
        await PsiphonServerList.InstallBundled(bundled, stamp, active).Should().BeTrue();
        await File.ReadAllBytes(active).SequenceEqual(new byte[] { 9 }).Should().BeTrue();
        await File.GetLastWriteTimeUtc(active).Should().BeEqualTo(Utc(2026, 9, 20));

        // A release without a bundled list puts nothing in place.
        await PsiphonServerList.InstallBundled(PathOf("none.dat"), stamp, PathOf("other.dat")).Should().BeFalse();
        await File.Exists(PathOf("other.dat")).Should().BeFalse();
    }

    [Test]
    public async Task AStampPastYear9999IsNoPublicationTimeAndNeverStopsTheStart()
    {
        // Milliseconds written where seconds belong, or any time past the end of year 9999, which no file can be given: no
        // publication time, so only a missing list is filled, and the copy at start never throws (PattNG initAssets).
        await PsiphonServerList.PublishedAt("1760000000000").Should().BeEqualTo(0L);
        await PsiphonServerList.PublishedAt("253402300800").Should().BeEqualTo(0L);
        await PsiphonServerList.PublishedAt("9223372036854775").Should().BeEqualTo(0L);
        await PsiphonServerList.PublishedAt("253402300799").Should().BeEqualTo(253_402_300_799_000L);

        var bundled = PathOf("bundled.dat");
        var stamp = PathOf("bundled.stamp");
        var active = PathOf("active.dat");
        File.WriteAllBytes(bundled, [9]);
        File.WriteAllBytes(active, [1]);
        File.SetLastWriteTimeUtc(active, Utc(2026, 9, 10));
        File.WriteAllText(stamp, "1760000000000\n");

        await PsiphonServerList.InstallBundled(bundled, stamp, active).Should().BeFalse();
        await File.ReadAllBytes(active).SequenceEqual(new byte[] { 1 }).Should().BeTrue();

        var missing = PathOf("missing.dat");
        await PsiphonServerList.InstallBundled(bundled, stamp, missing).Should().BeTrue();
        await File.ReadAllBytes(missing).SequenceEqual(new byte[] { 9 }).Should().BeTrue();
    }

    [Test]
    [NotInParallel]
    public async Task TheBundledListIsTheProgramsOwnWhereverPattnKeepsItsData()
    {
        // Critique 27: in local-application-data mode the bin folder copied at the first start is never refreshed. The mode
        // is switched on here, alone among the tests, and only paths that make no folder are read while it is.
        await AetherPaths.ActivePsiphonServersFile.Should().BeEqualTo(Path.Combine(AetherPaths.WorkDir, Global.PsiphonServersFileName));
        var before = Environment.GetEnvironmentVariable(Global.LocalAppData);
        string bundled;
        string stamp;
        string dataBin;
        Environment.SetEnvironmentVariable(Global.LocalAppData, "1");
        try
        {
            bundled = AetherPaths.BundledPsiphonServersFile;
            stamp = AetherPaths.BundledPsiphonServersStampFile;
            dataBin = Path.Combine(Utils.StartupPath(), "bin");
        }
        finally
        {
            Environment.SetEnvironmentVariable(Global.LocalAppData, before);
        }

        await Path.GetDirectoryName(bundled).Should().BeEqualTo(Utils.GetBaseDirectory("bin"));
        await Path.GetDirectoryName(stamp).Should().BeEqualTo(Utils.GetBaseDirectory("bin"));
        // Not the copy of the bin folder in the local application data, which GetBinPath names in that mode.
        await dataBin.Should().NotBeEqualTo(Utils.GetBaseDirectory("bin"));
        await Path.GetDirectoryName(bundled).Should().NotBeEqualTo(dataBin);
    }

    // ---- the update (UpdateService.UpdatePsiphonServersAsync)

    private sealed class FakeDownload
    {
        public byte[]? Body { get; set; }
        public DateTime? LastModified { get; set; }
        public bool NotModified { get; set; }
        public Exception? Fails { get; set; }
        public DateTime? AskedSince { get; private set; }
        public string? AskedUrl { get; private set; }

        public Task<PsiphonListDownload> Download(string url, string file, DateTime? since, CancellationToken ct)
        {
            AskedUrl = url;
            AskedSince = since;
            if (Fails != null)
            {
                throw Fails;
            }
            if (NotModified)
            {
                return Task.FromResult(new PsiphonListDownload(true));
            }
            File.WriteAllBytes(file, Body!);
            return Task.FromResult(new PsiphonListDownload(false, LastModified));
        }
    }

    private (string Active, string Temp) ListInUse(byte[] bytes, DateTime time)
    {
        var active = Path.Combine(_root, "aether", "psiphon_servers.dat");
        Directory.CreateDirectory(Path.GetDirectoryName(active)!);
        File.WriteAllBytes(active, bytes);
        File.SetLastWriteTimeUtc(active, time);
        return (active, PathOf("download.tmp"));
    }

    private Task<PsiphonServersUpdateResult> Update(FakeDownload download, string active, string temp, DateTime? now = null)
    {
        return PsiphonServersUpdate.RunAsync(download.Download, Global.PsiphonServersUrl, active, temp, () => now ?? Utc(2026, 10, 21), _keyText);
    }

    [Test]
    public async Task ADownloadThatIsNotSignedKeepsTheListInUse()
    {
        var inUse = Pack(Entries(60));
        var (active, temp) = ListInUse(inUse, Utc(2026, 9, 1));
        var download = new FakeDownload { Body = Encoding.UTF8.GetBytes("<html>captive portal</html>"), LastModified = Utc(2026, 10, 1) };

        var result = await Update(download, active, temp);

        await result.Outcome.Should().BeEqualTo(PsiphonServersUpdateOutcome.Invalid);
        await File.ReadAllBytes(active).SequenceEqual(inUse).Should().BeTrue();
        await File.GetLastWriteTimeUtc(active).Should().BeEqualTo(Utc(2026, 9, 1));
        await File.Exists(temp).Should().BeFalse();
        await UpdateService.PsiphonServersMessage(result).Should().BeEqualTo(ResUI.MsgPsiphonServersInvalid);

        // A signed list of too few entries is refused as well.
        download.Body = Pack(Entries(10));
        await (await Update(download, active, temp)).Outcome.Should().BeEqualTo(PsiphonServersUpdateOutcome.Invalid);
        await File.ReadAllBytes(active).SequenceEqual(inUse).Should().BeTrue();
    }

    [Test]
    public async Task ANewerSignedListTakesThePlaceOfTheOneInUseWithItsPublicationTime()
    {
        var (active, temp) = ListInUse(Pack(Entries(55)), Utc(2026, 9, 1));
        var newer = Pack(Entries(70));
        var download = new FakeDownload { Body = newer, LastModified = Utc(2026, 10, 1) };

        var result = await Update(download, active, temp);

        await result.Should().BeEqualTo(new PsiphonServersUpdateResult(PsiphonServersUpdateOutcome.Updated, 70, Utc(2026, 10, 1)));
        await File.ReadAllBytes(active).SequenceEqual(newer).Should().BeTrue();
        await File.GetLastWriteTimeUtc(active).Should().BeEqualTo(Utc(2026, 10, 1));
        await File.Exists(temp).Should().BeFalse();
        // Asked from Psiphon's address, for nothing older than the list in use.
        await download.AskedUrl.Should().BeEqualTo(Global.PsiphonServersUrl);
        await download.AskedSince.Should().BeEqualTo(Utc(2026, 9, 1));
        // The next core start unpacks it: the entries file follows the new list.
        var entries = PsiphonServerList.EntriesFile(Path.GetDirectoryName(active)!, Path.GetDirectoryName(active)!, _keyText);
        await File.ReadAllText(entries!).Should().BeEqualTo(Entries(70));
    }

    [Test]
    public async Task AListPublishedNoLaterThanTheOneInUseLeavesItAsItIs()
    {
        var inUse = Pack(Entries(55));
        var (active, temp) = ListInUse(inUse, Utc(2026, 9, 1));

        var notModified = await Update(new FakeDownload { NotModified = true }, active, temp);
        await notModified.Should().BeEqualTo(new PsiphonServersUpdateResult(PsiphonServersUpdateOutcome.Current, PublishedAtUtc: Utc(2026, 9, 1)));

        var same = await Update(new FakeDownload { Body = Pack(Entries(80)), LastModified = Utc(2026, 9, 1) }, active, temp);
        await same.Outcome.Should().BeEqualTo(PsiphonServersUpdateOutcome.Current);
        await File.ReadAllBytes(active).SequenceEqual(inUse).Should().BeTrue();
        await File.Exists(temp).Should().BeFalse();
    }

    [Test]
    public async Task AListInUseThatIsNotPsiphonsIsReplacedWhateverItsTime()
    {
        // Replaced by hand, or damaged: its time claims a list it is not, which would keep every older signed list out
        // until Psiphon publishes a newer one. PattNG's download always replaces its copy.
        var (active, temp) = ListInUse(Encoding.UTF8.GetBytes("not a list"), Utc(2026, 10, 20));
        var list = Pack(Entries(60));
        var download = new FakeDownload { Body = list, LastModified = Utc(2026, 10, 15) };

        var result = await Update(download, active, temp);

        await result.Should().BeEqualTo(new PsiphonServersUpdateResult(PsiphonServersUpdateOutcome.Updated, 60, Utc(2026, 10, 15)));
        await File.ReadAllBytes(active).SequenceEqual(list).Should().BeTrue();
        // Asked for whatever is there, not for something newer than a time the list in use has no claim to.
        await download.AskedSince.Should().BeNull();

        // A signed list of too few entries is no list either.
        (active, temp) = ListInUse(Pack(Entries(10)), Utc(2026, 10, 20));
        await (await Update(new FakeDownload { Body = list, LastModified = Utc(2026, 10, 15) }, active, temp)).Outcome
            .Should().BeEqualTo(PsiphonServersUpdateOutcome.Updated);
    }

    [Test]
    public async Task AFailedDownloadKeepsTheListInUse()
    {
        var inUse = Pack(Entries(55));
        var (active, temp) = ListInUse(inUse, Utc(2026, 9, 1));

        var result = await Update(new FakeDownload { Fails = new HttpRequestException("no route") }, active, temp);

        await result.Outcome.Should().BeEqualTo(PsiphonServersUpdateOutcome.Failed);
        await result.Reason.Should().BeEqualTo("no route");
        await File.ReadAllBytes(active).SequenceEqual(inUse).Should().BeTrue();
    }

    [Test]
    public async Task AFirstListWithoutAPublicationTimeTakesTheTimeOfTheDownload()
    {
        var active = Path.Combine(_root, "fresh", "psiphon_servers.dat");
        var list = Pack(Entries(51));

        var result = await Update(new FakeDownload { Body = list }, active, PathOf("fresh.tmp"), now: Utc(2026, 10, 21));

        await result.Outcome.Should().BeEqualTo(PsiphonServersUpdateOutcome.Updated);
        await File.ReadAllBytes(active).SequenceEqual(list).Should().BeTrue();
        await File.GetLastWriteTimeUtc(active).Should().BeEqualTo(Utc(2026, 10, 21));
    }

    [Test]
    public async Task TheDownloadTakesLastModifiedAndAsksForNothingOlder()
    {
        var body = Pack(Entries(60));
        var lastModified = Utc(2026, 10, 1);
        using var server = new ListServer(body, lastModified);
        var url = $"http://127.0.0.1:{server.Port}//psiphon/web/list";
        var file = PathOf("download.bin");

        var fetched = await PsiphonServersUpdate.DownloadAsync(null, url, file, null);

        await fetched.Should().BeEqualTo(new PsiphonListDownload(false, lastModified));
        await File.ReadAllBytes(file).SequenceEqual(body).Should().BeTrue();
        await server.Paths.First().Should().BeEqualTo("//psiphon/web/list");

        var again = await PsiphonServersUpdate.DownloadAsync(null, url, PathOf("again.bin"), lastModified);
        await again.NotModified.Should().BeTrue();
        await File.Exists(PathOf("again.bin")).Should().BeFalse();
    }

    [Test]
    public async Task ADownloadWhoseBodyStallsFailsWithinItsLimitAndKeepsTheListInUse()
    {
        // HttpClient's own timeout ends with the headers; a body that stops coming would hold the check-update window,
        // and every row after this one, for good (PattNG's fetch script: curl --max-time).
        var inUse = Pack(Entries(55));
        var (active, temp) = ListInUse(inUse, Utc(2026, 9, 1));
        using var server = new StallingServer();
        var url = $"http://127.0.0.1:{server.Port}/psiphon/web/list";
        var clock = Stopwatch.StartNew();

        var result = await PsiphonServersUpdate.RunAsync(
            (address, file, since, ct) => PsiphonServersUpdate.DownloadAsync(null, address, file, since, ct, limit: TimeSpan.FromSeconds(1)),
            url, active, temp, () => Utc(2026, 10, 21), _keyText).WaitAsync(TimeSpan.FromSeconds(30));

        await result.Outcome.Should().BeEqualTo(PsiphonServersUpdateOutcome.Failed);
        await (clock.Elapsed < TimeSpan.FromSeconds(10)).Should().BeTrue().Because($"took {clock.Elapsed}");
        await File.ReadAllBytes(active).SequenceEqual(inUse).Should().BeTrue();
        await File.Exists(temp).Should().BeFalse();
        await server.BodyStarted.Task.IsCompleted.Should().BeTrue();
    }

    [Test]
    public async Task TheDownloadChecksTheServerAgainstTheRootStoreTheSettingsName()
    {
        // As every other download (DownloaderHelper): with the Chrome or Mozilla roots chosen, the server's chain must end
        // at one of them, not at the system's. Here a root of the test's own signs the server's certificate.
        using var rootKey = RSA.Create(2048);
        var rootRequest = new CertificateRequest("CN=PattN test root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using var root = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        using var serverKey = RSA.Create(2048);
        var serverRequest = new CertificateRequest("CN=127.0.0.1", serverKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        names.AddIpAddress(IPAddress.Loopback);
        serverRequest.CertificateExtensions.Add(names.Build());
        serverRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        using var issued = serverRequest.Create(root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(29), [1, 2, 3, 4]);
        using var withKey = issued.CopyWithPrivateKey(serverKey);
        // SChannel takes a server key only from a key store, not an ephemeral one.
        using var certificate = X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pfx), null);
        var body = Pack(Entries(60));
        using var server = new TlsListServer(certificate, body);
        var url = $"https://127.0.0.1:{server.Port}/psiphon/web/list";
        var policy = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust, RevocationMode = X509RevocationMode.NoCheck };
        policy.CustomTrustStore.Add(root);

        var fetched = await PsiphonServersUpdate.DownloadAsync(null, url, PathOf("tls.bin"), null, chainPolicy: policy);

        await fetched.NotModified.Should().BeFalse();
        await File.ReadAllBytes(PathOf("tls.bin")).SequenceEqual(body).Should().BeTrue();
        // Without that root among those trusted, the same server is refused.
        var refused = false;
        try
        {
            await PsiphonServersUpdate.DownloadAsync(null, url, PathOf("refused.bin"), null);
        }
        catch (HttpRequestException)
        {
            refused = true;
        }
        await refused.Should().BeTrue();
    }

    /// <summary>Sends the headers of a long list and the first bytes of it, then nothing more, without closing.</summary>
    private sealed class StallingServer : IDisposable
    {
        private readonly TcpListener _server = new(IPAddress.Loopback, 0);
        private readonly List<TcpClient> _clients = [];

        public StallingServer()
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
                    lock (_clients)
                    {
                        _clients.Add(client);
                    }
                    try
                    {
                        var stream = client.GetStream();
                        using var reader = new StreamReader(stream, Encoding.ASCII, false, 1024, leaveOpen: true);
                        while (await reader.ReadLineAsync() is { Length: > 0 })
                        {
                        }
                        await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n"));
                        await stream.WriteAsync(new byte[1000]);
                        BodyStarted.TrySetResult();
                    }
                    catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
                    {
                    }
                }
            });
        }

        public int Port => ((IPEndPoint)_server.LocalEndpoint).Port;
        public TaskCompletionSource BodyStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void Dispose()
        {
            _server.Stop();
            lock (_clients)
            {
                _clients.ForEach(client => client.Dispose());
            }
        }
    }

    /// <summary>An HTTPS server of one list, with <paramref name="certificate" />; a client that refuses it gets nothing.</summary>
    private sealed class TlsListServer : IDisposable
    {
        private readonly TcpListener _server = new(IPAddress.Loopback, 0);

        public TlsListServer(X509Certificate2 certificate, byte[] body)
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
                                await using var tls = new SslStream(client.GetStream());
                                await tls.AuthenticateAsServerAsync(certificate);
                                using var reader = new StreamReader(tls, Encoding.ASCII, false, 1024, leaveOpen: true);
                                while (await reader.ReadLineAsync() is { Length: > 0 })
                                {
                                }
                                await tls.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n"));
                                await tls.WriteAsync(body);
                            }
                            catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException or System.Security.Authentication.AuthenticationException)
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

    /// <summary>An HTTP server of one list, with its Last-Modified time; a request with If-Modified-Since gets 304.</summary>
    private sealed class ListServer : IDisposable
    {
        private readonly TcpListener _server = new(IPAddress.Loopback, 0);

        public ListServer(byte[] body, DateTime lastModified)
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
                    using (client)
                    {
                        try
                        {
                            var stream = client.GetStream();
                            using var reader = new StreamReader(stream, Encoding.ASCII, false, 1024, leaveOpen: true);
                            var requestLine = await reader.ReadLineAsync() ?? string.Empty;
                            lock (Paths)
                            {
                                Paths.Add(requestLine.Split(' ').ElementAtOrDefault(1) ?? string.Empty);
                            }
                            var conditional = false;
                            while (await reader.ReadLineAsync() is { Length: > 0 } header)
                            {
                                conditional |= header.StartsWith("If-Modified-Since:", StringComparison.OrdinalIgnoreCase);
                            }
                            var head = conditional
                                ? "HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n"
                                : $"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\nLast-Modified: {lastModified.ToString("R", CultureInfo.InvariantCulture)}\r\nConnection: close\r\n\r\n";
                            await stream.WriteAsync(Encoding.ASCII.GetBytes(head));
                            if (!conditional)
                            {
                                await stream.WriteAsync(body);
                            }
                        }
                        catch (Exception ex) when (ex is IOException or SocketException)
                        {
                        }
                    }
                }
            });
        }

        public int Port => ((IPEndPoint)_server.LocalEndpoint).Port;
        public List<string> Paths { get; } = [];

        public void Dispose()
        {
            _server.Stop();
        }
    }
}
