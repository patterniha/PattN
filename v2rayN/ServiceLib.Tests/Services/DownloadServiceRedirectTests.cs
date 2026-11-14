namespace ServiceLib.Tests.Services;

public class DownloadServiceRedirectTests
{
    [Test]
    public async Task UrlRedirectAsync_ShouldReturnRedirectTargetWithoutFollowingIt()
    {
        await CertPemManager.Instance.Init(new Config { GuiItem = new GUIItem() });
        await using var server = new RedirectHttpServer();
        using var service = new DownloadService
        {
            Handler = HttpClientHelper.CreateSocketsHttpHandler(false),
            DisposeHandler = true,
        };

        var result = await service.UrlRedirectAsync(server.LatestUrl).WaitAsync(TimeSpan.FromSeconds(20));

        await result.Should().BeEqualTo(server.TagUrl);
        await server.TagRequestCount.Should().BeEqualTo(0);
    }

    [Test]
    public async Task UrlRedirectAsync_WithDefaultHandler_ShouldReturnRedirectTargetWithoutFollowingIt()
    {
        await CertPemManager.Instance.Init(new Config { GuiItem = new GUIItem() });
        await using var server = new RedirectHttpServer();
        using var service = new DownloadService();

        var result = await service.UrlRedirectAsync(server.LatestUrl).WaitAsync(TimeSpan.FromSeconds(20));

        await result.Should().BeEqualTo(server.TagUrl);
        await server.TagRequestCount.Should().BeEqualTo(0);
    }

    [Test]
    public async Task UrlRedirectAsync_WhenNoRedirect_ShouldReturnNull()
    {
        await CertPemManager.Instance.Init(new Config { GuiItem = new GUIItem() });
        await using var server = new RedirectHttpServer();
        using var service = new DownloadService
        {
            Handler = HttpClientHelper.CreateSocketsHttpHandler(false),
            DisposeHandler = true,
        };

        var result = await service.UrlRedirectAsync(server.TagUrl).WaitAsync(TimeSpan.FromSeconds(20));

        await result.Should().BeNull();
    }

    private sealed class RedirectHttpServer : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _cancellation = new();
        private readonly Task _serverTask;
        private int _tagRequestCount;

        public string LatestUrl { get; }
        public string TagUrl { get; }
        public int TagRequestCount => _tagRequestCount;

        public RedirectHttpServer()
        {
            _listener.Start();
            var baseUrl = $"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}";
            LatestUrl = $"{baseUrl}/releases/latest";
            TagUrl = $"{baseUrl}/releases/tag/v1.2.3";
            _serverTask = ServeAsync();
        }

        private async Task ServeAsync()
        {
            var cancellationToken = _cancellation.Token;
            while (!cancellationToken.IsCancellationRequested)
            {
                using var client = await _listener.AcceptTcpClientAsync(cancellationToken);
                await using var stream = client.GetStream();
                using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
                var requestLine = await reader.ReadLineAsync(cancellationToken);
                if (requestLine == null)
                {
                    continue;
                }
                while (await reader.ReadLineAsync(cancellationToken) is { Length: > 0 })
                {
                }

                string response;
                if (requestLine.StartsWith("GET /releases/latest"))
                {
                    response = $"HTTP/1.1 302 Found\r\nLocation: {TagUrl}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                }
                else
                {
                    Interlocked.Increment(ref _tagRequestCount);
                    const string body = "tag-page";
                    response = $"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n{body}";
                }
                await stream.WriteAsync(Encoding.ASCII.GetBytes(response), cancellationToken);
            }
        }

        public async ValueTask DisposeAsync()
        {
            await _cancellation.CancelAsync();
            try
            {
                await _serverTask;
            }
            catch (OperationCanceledException)
            {
            }
            finally
            {
                _listener.Stop();
                _cancellation.Dispose();
            }
        }
    }
}
