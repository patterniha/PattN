namespace ServiceLib.Handler;

public static class ConnectionHandler
{
    private static readonly string _tag = "ConnectionHandler";

    /// <summary>
    /// Runs ping and IP checks.
    /// </summary>
    public static async Task<AvailabilityCheckResult> RunAvailabilityCheck()
    {
        var time = await GetRealPingTimeInfo();
        var ip = time > 0 ? await GetIPInfo() : Global.None;

        return new AvailabilityCheckResult(time, ip);
    }

    /// <summary>
    /// Gets IP information using the default local proxy.
    /// </summary>
    private static async Task<string?> GetIPInfo()
    {
        using var downloadHandle = new DownloadService
        {
            Handler = HttpClientHelper.CreateSocketsHttpHandler(true, new()),
            DisposeHandler = true,
        };
        var ipInfo = await GetIPInfo(downloadHandle);
        return ipInfo?.ToString() ?? Global.None;
    }

    /// <summary>
    /// Measures real ping time using configured test URL.
    /// </summary>
    private static async Task<int> GetRealPingTimeInfo()
    {
        var responseTime = -1;
        try
        {
            for (var i = 0; i < 2; i++)
            {
                responseTime = await GetRealPingTime(true);
                if (responseTime > 0)
                {
                    break;
                }
                await Task.Delay(500);
            }
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
            return -1;
        }
        return responseTime;
    }

    /// <summary>
    /// Measures response time by sending HTTP requests through proxy.
    /// </summary>
    public static async Task<int> GetRealPingTime(bool useProxy, CancellationToken cancellationToken = default)
    {
        var responseTime = -1;
        try
        {
            using var client = HttpClientHelper.Instance.GetHttpClient(useProxy);
            responseTime = await GetRealPingTime(client, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            // Ignore
        }
        return responseTime;
    }

    public static async Task<int> GetRealPingTime(HttpClient client, CancellationToken cancellationToken = default)
    {
        var url = AppManager.Instance.Config.SpeedTestItem.SpeedPingTestUrl;
        var responseTime = -1;
        try
        {
            using var timeoutCts = new CancellationTokenSource();
            timeoutCts.CancelAfter(Global.LocalFetch);
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);
            var linkedToken = linkedCts.Token;

            List<int> oneTime = [];
            for (var i = 0; i < 2; i++)
            {
                var timer = Stopwatch.StartNew();
                await client.GetAsync(url, linkedToken).ConfigureAwait(false);
                timer.Stop();
                oneTime.Add((int)timer.Elapsed.TotalMilliseconds);
                await Task.Delay(100, linkedToken);
            }
            responseTime = oneTime.Where(x => x > 0).OrderBy(x => x).FirstOrDefault();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            // Ignore
        }
        return responseTime;
    }

    /// <summary>
    /// PattN: the real ping of a profile that runs on an Aether core, within <paramref name="timeout" />, what is left of
    /// its test's budget (design 2.12.2, PattNG AetherDelayTester.requestDelay): the best of up to two requests for
    /// <paramref name="url" /> through <paramref name="webProxy" />, the second on the connection of the first, each given
    /// what is left, none started with less than a second left (<see cref="AetherDelayTester.BestOfAttemptsAsync" />).
    /// Only an answer of 200 or 204 counts. -1 when none was answered in time; a cancellation of
    /// <paramref name="cancellationToken" /> throws <see cref="OperationCanceledException" />.
    /// </summary>
    public static async Task<int> GetRealPingTime(IWebProxy? webProxy, string? url, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https"))
        {
            return -1;
        }
        var budget = Stopwatch.StartNew();
        using var client = new HttpClient(new SocketsHttpHandler
        {
            Proxy = webProxy,
            UseProxy = webProxy != null,
            // The SOCKS handshake is part of the connect; the time left bounds it as it bounds the request.
            ConnectTimeout = timeout > TimeSpan.Zero ? timeout : TimeSpan.FromMilliseconds(1),
        })
        {
            Timeout = Timeout.InfiniteTimeSpan,
        };
        return await AetherDelayTester.BestOfAttemptsAsync(
            () => timeout - budget.Elapsed,
            async (left, ct) =>
            {
                using var attempt = CancellationTokenSource.CreateLinkedTokenSource(ct);
                attempt.CancelAfter(left);
                var timer = Stopwatch.StartNew();
                try
                {
                    using var response = await client.GetAsync(uri, attempt.Token).ConfigureAwait(false);
                    // At least 1 ms: 0 is what a test left untested stores.
                    return response.StatusCode is HttpStatusCode.OK or HttpStatusCode.NoContent
                        ? Math.Max(1, (int)timer.ElapsedMilliseconds)
                        : -1;
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    // Not answered within what was left.
                    return -1;
                }
                catch (Exception ex) when (ex is HttpRequestException or IOException or SocketException)
                {
                    return -1;
                }
            },
            cancellationToken).ConfigureAwait(false);
    }

    public static async Task<IpInfoResult?> GetIPInfo(DownloadService downloadHandle, CancellationToken cancellationToken = default)
    {
        try
        {
            var url = AppManager.Instance.Config.SpeedTestItem.IPAPIUrl;
            if (url.IsNullOrEmpty())
            {
                return null;
            }

            var result = await downloadHandle.TryDownloadString(url, cancellationToken);
            if (result == null)
            {
                return null;
            }

            var ipInfo = JsonUtils.Deserialize<IPAPIInfo>(result);
            if (ipInfo == null)
            {
                return null;
            }

            var ip = ipInfo.ip ?? ipInfo.clientIp ?? ipInfo.ip_addr ?? ipInfo.query;
            var country = ipInfo.country_code ?? ipInfo.country ?? ipInfo.countryCode ?? ipInfo.location?.country_code ?? "unknown";

            return new IpInfoResult(country, ip);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }
}
