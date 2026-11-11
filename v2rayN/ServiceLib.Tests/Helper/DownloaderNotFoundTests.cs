using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ServiceLib.Tests.Helper;

public class DownloaderNotFoundTests
{
    [Test]
    public async Task AMissingRuleSetIsSkippedWhileOtherFilesStillDownload()
    {
        await CertPemManager.Instance.Init(new Config { GuiItem = new GUIItem() });
        // A local server with one file and nothing else: what it lacks is answered 404
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var stop = new CancellationTokenSource();
        var serving = Task.Run(async () =>
        {
            while (!stop.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync(stop.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                _ = Task.Run(async () =>
                {
                    using (client)
                    {
                        var stream = client.GetStream();
                        var buffer = new byte[8192];
                        var read = await stream.ReadAsync(buffer);
                        var request = Encoding.ASCII.GetString(buffer, 0, read);
                        var found = request.Split(' ')[1] == "/ok.srs";
                        var body = Encoding.ASCII.GetBytes(found ? "rule-set" : "not found");
                        var head = $"HTTP/1.1 {(found ? "200 OK" : "404 Not Found")}\r\nContent-Type: application/octet-stream\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n";
                        await stream.WriteAsync(Encoding.ASCII.GetBytes(head));
                        if (!request.StartsWith("HEAD ", StringComparison.Ordinal))
                        {
                            await stream.WriteAsync(body);
                        }
                    }
                });
            }
        });

        var dir = Path.Combine(Path.GetTempPath(), $"pattn-404-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            FileDownloadRequest File(string name, bool ignoreNotFound) => new()
            {
                FileUrl = $"http://127.0.0.1:{port}/{name}",
                FilePath = Path.Combine(dir, name),
                IgnoreNotFound = ignoreNotFound,
            };
            List<FileDownloadRequest> requests = [File("missing.srs", true), File("missing.dat", false), File("ok.srs", true)];
            FileDownloadState[] states = [];
            using var helper = new DownloaderHelper();

            await helper.DownloadSmallFilesAsync(requests, s => states = s.ToArray()).WaitAsync(TimeSpan.FromSeconds(60));

            await states.Length.Should().BeEqualTo(3);
            await states[0].Completed.Should().BeTrue();
            await states[0].Error.Should().BeNull();
            await (states[1].Error != null).Should().BeTrue();
            await states[2].Error.Should().BeNull();
            await System.IO.File.ReadAllText(Path.Combine(dir, "ok.srs")).Should().BeEqualTo("rule-set");
        }
        finally
        {
            stop.Cancel();
            listener.Stop();
            await serving;
            Directory.Delete(dir, true);
        }
    }
}
