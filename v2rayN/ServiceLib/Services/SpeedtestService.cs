using ServiceLib.UdpTest;

namespace ServiceLib.Services;

public class SpeedtestService(Config config, Func<SpeedTestResult, Task> updateFunc)
{
    private static readonly string _tag = "SpeedtestService";
    private readonly Config? _config = config;
    private readonly Func<SpeedTestResult, Task>? _updateFunc = updateFunc;
    private readonly Lock _runLock = new();
    private readonly List<CancellationTokenSource> _runCtsList = [];
    private readonly int _speedTestPageSize = config.SpeedTestItem.SpeedTestPageSize ?? Global.SpeedTestPageSize;
    private readonly TimeSpan _delayInterval = TimeSpan.FromSeconds(config.SpeedTestItem.SpeedTestDelayInterval ?? 1);

    public Task RunLoop(ESpeedActionType actionType, List<ProfileItem> selecteds, CancellationToken ct = default)
    {
        CancellationTokenSource runCts;

        lock (_runLock)
        {
            runCts = CancellationTokenSource.CreateLinkedTokenSource(ct);

            _runCtsList.Add(runCts);
        }

        return RunLoopAsync(actionType, selecteds, runCts);
    }

    public void ExitLoop()
    {
        var counter = 0;
        List<CancellationTokenSource> listToCancel;

        lock (_runLock)
        {
            listToCancel = _runCtsList.ToList();
            counter = listToCancel.Count;
        }

        foreach (var cts in listToCancel)
        {
            try
            {
                cts.Cancel();
            }
            catch (ObjectDisposedException)
            {
                // Ignored
            }
        }

        if (counter > 0)
        {
            _ = UpdateFunc("", ResUI.SpeedtestingStop);
        }
    }

    private async Task RunLoopAsync(ESpeedActionType actionType, List<ProfileItem> selecteds, CancellationTokenSource runCts)
    {
        try
        {
            await RunAsync(actionType, selecteds, runCts.Token);
        }
        catch (OperationCanceledException) when (runCts.IsCancellationRequested)
        {
            // Ignored
        }
        finally
        {
            try
            {
                await ProfileExManager.Instance.SaveTo();
            }
            finally
            {
                await UpdateFunc("", ResUI.SpeedtestingCompleted);
            }

            lock (_runLock)
            {
                _runCtsList.Remove(runCts);
            }

            runCts.Dispose();
        }
    }

    private async Task RunAsync(ESpeedActionType actionType, List<ProfileItem> selecteds, CancellationToken ct = default)
    {
        var lstSelected = await GetClearItem(actionType, selecteds);
        var completedIds = new ConcurrentDictionary<string, byte>();
        // PattN: what needs an Aether core leaves the batch, and is tested one at a time after the rest (design 2.12.1)
        List<ServerTestItem> lstAether = [];

        try
        {
            // PattN: inside the try, so that a failed lookup of the stored profiles is logged and shown as the run's failure
            lstAether = await AetherCandidates().TakeAsync(actionType, lstSelected);
            switch (actionType)
            {
                case ESpeedActionType.Tcping:
                    await RunTcpingAsync(lstSelected, completedIds, ct);
                    break;

                case ESpeedActionType.Realping:
                    await RunRealPingBatchAsync(lstSelected, completedIds, 0, ct);
                    break;

                case ESpeedActionType.UdpTest:
                    await RunUdpTestBatchAsync(lstSelected, completedIds, 0, ct);
                    break;

                case ESpeedActionType.Speedtest:
                    await RunMixedTestAsync(lstSelected, completedIds, 1, true, ct);
                    break;

                case ESpeedActionType.Mixedtest:
                    await RunMixedTestAsync(lstSelected, completedIds, _config.SpeedTestItem.MixedConcurrencyCount, true,
                        ct);
                    break;
            }
            // PattN
            await RunAetherTestsAsync(actionType, lstAether, completedIds, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            _ = UpdateFunc("", ResUI.SpeedtestingStop);
            await SetTestResultAsync(lstSelected.Where(it => !completedIds.ContainsKey(it.IndexId)).ToList(),
                actionType, ResUI.SpeedtestingSkip).ConfigureAwait(false);
            // PattN: and those that need an Aether core
            await SetTestResultAsync(lstAether.Where(it => !completedIds.ContainsKey(it.IndexId)).ToList(),
                actionType, ResUI.SpeedtestingSkip).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
            _ = UpdateFunc("", ex.Message);
        }
    }

    private async Task<List<ServerTestItem>> GetClearItem(ESpeedActionType actionType, List<ProfileItem> selecteds)
    {
        var lstSelected = new List<ServerTestItem>(selecteds.Count);
        var ids = selecteds.Where(it => !it.IndexId.IsNullOrEmpty()
            && it.ConfigType != EConfigType.Custom
            // PattN: an Aether profile left to the scanner has no port and is tested all the same (critique 21)
            && (it.ConfigType.IsComplexType() || it.Port > 0 || it.ConfigType == EConfigType.Aether))
            .Select(it => it.IndexId)
            .ToList();
        var profileMap = await AppManager.Instance.GetProfileItemsByIndexIdsAsMap(ids);
        for (var i = 0; i < selecteds.Count; i++)
        {
            var it = selecteds[i];
            if (it.ConfigType == EConfigType.Custom)
            {
                continue;
            }

            // PattN: but an Aether profile left to the scanner (critique 21)
            if (!it.ConfigType.IsComplexType() && it.Port <= 0 && it.ConfigType != EConfigType.Aether)
            {
                continue;
            }

            var profile = profileMap.GetValueOrDefault(it.IndexId, it);
            lstSelected.Add(new ServerTestItem()
            {
                IndexId = it.IndexId,
                Address = it.Address,
                Port = it.Port,
                ConfigType = it.ConfigType,
                QueueNum = i,
                Profile = profile,
                CoreType = AppManager.Instance.GetCoreType(profile, it.ConfigType),
            });
        }

        //clear test result
        await SetTestResultAsync(lstSelected, actionType, ResUI.Speedtesting).ConfigureAwait(false);

        if (lstSelected.Count > 1 && (actionType == ESpeedActionType.Speedtest || actionType == ESpeedActionType.Mixedtest))
        {
            NoticeManager.Instance.Enqueue(ResUI.SpeedtestingPressEscToExit);
        }

        return lstSelected;
    }

    private async Task SetTestResultAsync(List<ServerTestItem> lstSelected, ESpeedActionType actionType, string message)
    {
        foreach (var it in lstSelected)
        {
            switch (actionType)
            {
                case ESpeedActionType.Tcping:
                case ESpeedActionType.Realping:
                case ESpeedActionType.UdpTest:
                    await UpdateFunc(it.IndexId, message, "");
                    break;

                case ESpeedActionType.Speedtest:
                    // A skipped or failed test must not leave the last speed behind for sorting.
                    ProfileExManager.Instance.SetTestSpeed(it.IndexId, 0);
                    await UpdateFunc(it.IndexId, "", message);
                    break;

                case ESpeedActionType.Mixedtest:
                    ProfileExManager.Instance.SetTestSpeed(it.IndexId, 0);
                    await UpdateFunc(it.IndexId, message, message);
                    break;
            }
        }
    }

    private async Task RunTcpingAsync(List<ServerTestItem> selecteds,
        ConcurrentDictionary<string, byte> completedIds, CancellationToken ct = default)
    {
        var pageSize = Math.Min(selecteds.Count, _speedTestPageSize);
        var lstBatch = GetTestBatchItem(selecteds, pageSize);

        foreach (var lst in lstBatch)
        {
            ct.ThrowIfCancellationRequested();

            var parallelOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = lst.Count,
                CancellationToken = ct,
            };

            await Parallel.ForEachAsync(lst, parallelOptions, async (item, innerCt) =>
            {
                try
                {
                    var responseTime = await GetTcpingTime(item.Address, item.Port, innerCt);

                    ProfileExManager.Instance.SetTestDelay(item.IndexId, responseTime);
                    await UpdateFunc(item.IndexId, responseTime.ToString());
                    completedIds.TryAdd(item.IndexId, 0);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    Logging.SaveLog(_tag, ex);
                }
            });

            await Task.Delay(_delayInterval, ct);
        }
    }

    private async Task RunRealPingBatchAsync(List<ServerTestItem> lstSelected,
        ConcurrentDictionary<string, byte> completedIds, int pageSize = 0, CancellationToken ct = default)
    {
        if (pageSize <= 0)
        {
            pageSize = Math.Min(lstSelected.Count, _speedTestPageSize);
        }
        var lstTest = GetTestBatchItem(lstSelected, pageSize);

        List<ServerTestItem> lstFailed = [];
        foreach (var lst in lstTest)
        {
            var ret = await RunRealPingAsync(lst, completedIds, ct);
            if (ret == false)
            {
                lstFailed.AddRange(lst);
            }
            await Task.Delay(_delayInterval, ct);
        }

        //Retest the failed part
        var pageSizeNext = pageSize / 2;
        if (lstFailed.Count > 0 && pageSizeNext > 0)
        {
            ct.ThrowIfCancellationRequested();

            await UpdateFunc("", string.Format(ResUI.SpeedtestingTestFailedPart, lstFailed.Count));

            if (pageSizeNext > _config.SpeedTestItem.MixedConcurrencyCount)
            {
                await RunRealPingBatchAsync(lstFailed, completedIds, pageSizeNext, ct);
            }
            else
            {
                await RunMixedTestAsync(lstSelected, completedIds, _config.SpeedTestItem.MixedConcurrencyCount, false, ct);
            }
        }
    }

    private async Task<bool> RunRealPingAsync(List<ServerTestItem> selecteds,
        ConcurrentDictionary<string, byte> completedIds, CancellationToken ct = default)
    {
        ProcessService processService = null;
        try
        {
            processService = await CoreManager.Instance.LoadCoreConfigSpeedtest(selecteds);
            if (processService is null)
            {
                return false;
            }
            await Task.Delay(1000, ct);

            var parallelOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = selecteds.Count,
                CancellationToken = ct,
            };

            await Parallel.ForEachAsync(selecteds, parallelOptions, async (it, innerCt) =>
            {
                if (!it.AllowTest)
                {
                    await UpdateFunc(it.IndexId, ResUI.SpeedtestingSkip);
                    completedIds.TryAdd(it.IndexId, 0);
                    return;
                }

                try
                {
                    await DoRealPing(it, completedIds, innerCt);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    Logging.SaveLog(_tag, ex);
                }
            });
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
        }
        finally
        {
            if (processService != null)
            {
                await processService?.StopAsync();
            }
        }
        return true;
    }

    private async Task RunUdpTestBatchAsync(List<ServerTestItem> lstSelected,
        ConcurrentDictionary<string, byte> completedIds, int pageSize = 0, CancellationToken ct = default)
    {
        if (pageSize <= 0)
        {
            pageSize = Math.Min(lstSelected.Count, _speedTestPageSize);
        }
        var lstTest = GetTestBatchItem(lstSelected, pageSize);

        List<ServerTestItem> lstFailed = [];
        foreach (var lst in lstTest)
        {
            var ret = await RunUdpTestAsync(lst, completedIds, ct);
            if (ret == false)
            {
                lstFailed.AddRange(lst);
            }
            await Task.Delay(_delayInterval, ct);
        }

        //Retest the failed part
        if (lstFailed.Count > 0)
        {
            ct.ThrowIfCancellationRequested();

            await UpdateFunc("", string.Format(ResUI.SpeedtestingTestFailedPart, lstFailed.Count));

            await RunUdpTestAsync(lstFailed, completedIds, ct);
        }
    }

    private async Task<bool> RunUdpTestAsync(List<ServerTestItem> selecteds,
        ConcurrentDictionary<string, byte> completedIds, CancellationToken ct = default)
    {
        ProcessService processService = null;
        try
        {
            processService = await CoreManager.Instance.LoadCoreConfigSpeedtest(selecteds);
            if (processService is null)
            {
                return false;
            }
            await Task.Delay(1000, ct);

            var parallelOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = selecteds.Count,
                CancellationToken = ct,
            };

            await Parallel.ForEachAsync(selecteds, parallelOptions, async (it, innerCt) =>
            {
                if (!it.AllowTest)
                {
                    await UpdateFunc(it.IndexId, ResUI.SpeedtestingSkip);
                    completedIds.TryAdd(it.IndexId, 0);
                    return;
                }

                try
                {
                    await DoUdpTest(it, completedIds, innerCt);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    Logging.SaveLog(_tag, ex);
                }
            });
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
        }
        finally
        {
            if (processService != null)
            {
                await processService?.StopAsync();
            }
        }
        return true;
    }

    private async Task RunMixedTestAsync(List<ServerTestItem> selecteds,
        ConcurrentDictionary<string, byte> completedIds, int concurrencyCount, bool blSpeedTest,
        CancellationToken ct = default)
    {
        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = concurrencyCount,
            CancellationToken = ct,
        };

        await Parallel.ForEachAsync(selecteds, parallelOptions, async (it, innerCt) =>
        {
            innerCt.ThrowIfCancellationRequested();

            ProcessService processService = null;
            try
            {
                processService = await CoreManager.Instance.LoadCoreConfigSpeedtest(it);
                if (processService is null)
                {
                    await UpdateFunc(it.IndexId, "", ResUI.FailedToRunCore);
                    return;
                }

                await Task.Delay(1000, innerCt);

                var delay = await DoRealPing(it, completedIds, innerCt);
                if (blSpeedTest)
                {
                    if (delay > 0)
                    {
                        await DoSpeedTest(it, completedIds, innerCt);
                    }
                    else
                    {
                        await UpdateFunc(it.IndexId, "", ResUI.SpeedtestingSkip);
                    }
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                Logging.SaveLog(_tag, ex);
            }
            finally
            {
                if (processService != null)
                {
                    await processService.StopAsync();
                }
            }
        });
    }

    private async Task<int> DoRealPing(ServerTestItem it,
        ConcurrentDictionary<string, byte> completedIds, CancellationToken ct = default)
    {
        var responseTime = -1;
        try
        {
            using var handler = HttpClientHelper.CreateProxySocketsHttpHandler(it.Port, new());
            handler.ConnectTimeout = Global.LocalFetch;
            using var client = new HttpClient(handler, false);
            responseTime = await ConnectionHandler.GetRealPingTime(client, ct);

            ProfileExManager.Instance.SetTestDelay(it.IndexId, responseTime);
            await UpdateFunc(it.IndexId, responseTime.ToString());

            if (!_config.UiItem.HideColumnIpInfo && responseTime > 0)
            {
                using var downloadHandle = new DownloadService
                {
                    Handler = handler,
                    DisposeHandler = false,
                };
                var ipInfo = await ConnectionHandler.GetIPInfo(downloadHandle, ct);
                var ipStr = ipInfo?.ToString() ?? Global.None;
                ProfileExManager.Instance.SetTestIpInfo(it.IndexId, ipStr);
                await UpdateIpInfoFunc(it.IndexId, ipStr);
            }
            else
            {
                await UpdateIpInfoFunc(it.IndexId, ResUI.SpeedtestingSkip);
            }

            completedIds.TryAdd(it.IndexId, 0);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            // Ignore
        }
        return responseTime;
    }

    private async Task DoSpeedTest(ServerTestItem it,
        ConcurrentDictionary<string, byte> completedIds, CancellationToken ct = default)
    {
        await UpdateFunc(it.IndexId, "", ResUI.Speedtesting);

        var handler = HttpClientHelper.CreateProxySocketsHttpHandler(it.Port, new());
        var url = _config.SpeedTestItem.SpeedTestUrl;
        var timeout = _config.SpeedTestItem.SpeedTestTimeout;
        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(timeout));
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);
        var linkedCt = linkedCts.Token;
        using var downloadHandle = new DownloadService
        {
            Handler = handler,
            DisposeHandler = true,
        };
        await downloadHandle.DownloadDataAsync(url, async (success, msg) =>
        {
            decimal.TryParse(msg, out var dec);
            if (dec > 0)
            {
                ProfileExManager.Instance.SetTestSpeed(it.IndexId, dec);
            }
            await UpdateFunc(it.IndexId, "", msg);
        }, linkedCt);
        completedIds.TryAdd(it.IndexId, 0);
    }

    private async Task<int> DoUdpTest(ServerTestItem it,
        ConcurrentDictionary<string, byte> completedIds, CancellationToken ct = default)
    {
        var responseTime = -1;
        try
        {
            var udpService = UdpTestService.CreateFromTarget(_config?.SpeedTestItem.UdpTestTarget, out var udpTestUrl);
            responseTime = (int)(await udpService.SendUdpRequestAsync(udpTestUrl, it.Port, ct)).TotalMilliseconds;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            // Ignore
        }

        ProfileExManager.Instance.SetTestDelay(it.IndexId, responseTime);
        await UpdateFunc(it.IndexId, responseTime.ToString());
        completedIds.TryAdd(it.IndexId, 0);
        return responseTime;
    }

    private async Task<int> GetTcpingTime(string? url, int port, CancellationToken ct = default)
    {
        var responseTime = -1;

        if (url.IsNullOrEmpty() || port <= 0)
        {
            return responseTime;
        }

        if (!IPAddress.TryParse(url, out var ipAddress))
        {
            var ipHostInfo = await Dns.GetHostEntryAsync(url, ct);
            ipAddress = ipHostInfo.AddressList.First();
        }

        IPEndPoint endPoint = new(ipAddress, port);
        using Socket clientSocket = new(endPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

        var timer = Stopwatch.StartNew();
        try
        {
            using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);
            await clientSocket.ConnectAsync(endPoint, linkedCts.Token).ConfigureAwait(false);
            responseTime = (int)timer.ElapsedMilliseconds;
        }
        catch
        {
            // Ignore
        }
        finally
        {
            timer.Stop();
        }
        return responseTime;
    }

    private List<List<ServerTestItem>> GetTestBatchItem(List<ServerTestItem> lstSelected, int pageSize)
    {
        List<List<ServerTestItem>> lstTest = [];
        if (lstSelected.Count == 0)
        {
            return lstTest;
        }

        pageSize = Math.Max(pageSize, 1);
        var lst1 = lstSelected.Where(t => t.CoreType == ECoreType.Xray).ToList();
        var lst2 = lstSelected.Where(t => t.CoreType == ECoreType.sing_box).ToList();

        for (var num = 0; num < (int)Math.Ceiling(lst1.Count * 1.0 / pageSize); num++)
        {
            lstTest.Add(lst1.Skip(num * pageSize).Take(pageSize).ToList());
        }
        for (var num = 0; num < (int)Math.Ceiling(lst2.Count * 1.0 / pageSize); num++)
        {
            lstTest.Add(lst2.Skip(num * pageSize).Take(pageSize).ToList());
        }

        return lstTest;
    }

    private async Task UpdateFunc(string indexId, string delay, string speed = "")
    {
        await _updateFunc?.Invoke(new() { IndexId = indexId, Delay = delay, Speed = speed });
        if (indexId.IsNotEmpty() && speed.IsNotEmpty())
        {
            ProfileExManager.Instance.SetTestMessage(indexId, speed);
        }
    }

    private async Task UpdateIpInfoFunc(string indexId, string ip)
    {
        await _updateFunc?.Invoke(new() { IndexId = indexId, IpInfo = ip });
    }

    #region PattN: Aether

    private readonly AetherDelayTester? _aetherTester;

    /// <summary>PattN: what tests the profiles that need an Aether core; PattN's own unless a test gives one on fakes.</summary>
    public AetherDelayTester AetherTester
    {
        get => _aetherTester ?? AetherDelayTester.Default;
        init => _aetherTester = value;
    }

    /// <summary>PattN: which profiles of a run need an Aether core; told from PattN's own database unless a test gives fakes.</summary>
    public Func<AetherTestCandidates> AetherCandidates { get; init; } = AetherTestCandidates.FromDatabase;

    /// <summary>
    /// PattN (design 2.12.1): the tests of <paramref name="items" />, which need an Aether core, one at a time: every
    /// core listens on the one Aether listen port, so a batch, one Xray for many profiles, cannot give each its own core
    /// (<see cref="AetherDelayTester" />). A TCP ping probes the edge of an Aether profile instead; no UDP test is made.
    /// </summary>
    private async Task RunAetherTestsAsync(ESpeedActionType actionType, List<ServerTestItem> items,
        ConcurrentDictionary<string, byte> completedIds, CancellationToken ct = default)
    {
        if (items.Count == 0)
        {
            return;
        }
        foreach (var it in items)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                switch (actionType)
                {
                    case ESpeedActionType.Tcping:
                        await DoAetherReachability(it, completedIds, ct);
                        break;

                    case ESpeedActionType.Realping:
                        await DoAetherTest(it, false, completedIds, ct);
                        break;

                    case ESpeedActionType.Speedtest:
                    case ESpeedActionType.Mixedtest:
                        await DoAetherTest(it, true, completedIds, ct);
                        break;

                    default:
                        await UpdateFunc(it.IndexId, ResUI.SpeedtestingSkip);
                        completedIds.TryAdd(it.IndexId, 0);
                        break;
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                Logging.SaveLog(_tag, ex);
                // Not left showing that it is being tested.
                await UpdateFunc(it.IndexId, ResUI.SpeedtestingSkip);
                completedIds.TryAdd(it.IndexId, 0);
            }
        }
    }

    /// <summary>
    /// PattN: the latency test of <paramref name="it" /> through the tunnel it needs, and, with
    /// <paramref name="withSpeedTest" />, its download speed through the same tunnel before it is torn down. Whatever ends
    /// the test, its row shows what came of it: the delay it measured, or else what the tester gave, an untested row with
    /// its reason (critique 24); and a speed test that did not finish, because a session start ended the test, is skipped.
    /// </summary>
    private async Task DoAetherTest(ServerTestItem it, bool withSpeedTest,
        ConcurrentDictionary<string, byte> completedIds, CancellationToken ct = default)
    {
        var delayShown = false;
        var speedDone = false;
        var result = await AetherTester.MeasureAsync(it.Profile, async (port, left, token) =>
        {
            var webProxy = new WebProxy($"socks5://{Global.Loopback}:{port}");
            var delay = await ConnectionHandler.GetRealPingTime(webProxy, _config.SpeedTestItem.SpeedPingTestUrl, left(), token);
            await ShowAetherDelay(it, new AetherTestResult(delay));
            delayShown = true;
            try
            {
                await ShowAetherIpInfo(it, delay, webProxy, token);
                if (withSpeedTest)
                {
                    if (delay > 0)
                    {
                        it.Port = port;
                        await DoSpeedTest(it, completedIds, token);
                    }
                    else
                    {
                        await UpdateFunc(it.IndexId, "", ResUI.SpeedtestingSkip);
                    }
                    speedDone = true;
                }
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                // As RunMixedTestAsync: the speed test's own timeout, or an IP lookup that failed, keeps the delay shown.
                Logging.SaveLog(_tag, ex);
                speedDone = true;
            }
            return delay;
        }, ct);
        if (!delayShown)
        {
            await ShowAetherDelay(it, result);
            await ShowAetherIpInfo(it, result.Delay, null, ct);
        }
        if (withSpeedTest && !speedDone)
        {
            await UpdateFunc(it.IndexId, "", ResUI.SpeedtestingSkip);
        }
        completedIds.TryAdd(it.IndexId, 0);
    }

    /// <summary>PattN: the TCP ping of an Aether profile: a connection to its edge, which a profile left to the scanner has not.</summary>
    private async Task DoAetherReachability(ServerTestItem it, ConcurrentDictionary<string, byte> completedIds,
        CancellationToken ct = default)
    {
        var delay = await AetherDelayTester.ReachabilityAsync(it.Profile, ct);
        await ShowAetherDelay(it, delay == AetherDelayTester.Untested
            ? AetherTestResult.Untested(ResUI.SpeedtestingSkip)
            : new AetherTestResult(delay));
        completedIds.TryAdd(it.IndexId, 0);
    }

    /// <summary>
    /// PattN: stores and shows what an Aether test gave. An untested row shows why, never "0" (critique 24); 0 is stored,
    /// which the list shows as nothing once it reads the results again.
    /// </summary>
    private async Task ShowAetherDelay(ServerTestItem it, AetherTestResult result)
    {
        ProfileExManager.Instance.SetTestDelay(it.IndexId, result.Delay);
        await UpdateFunc(it.IndexId, result.IsUntested ? result.Reason ?? ResUI.SpeedtestingSkip : result.Delay.ToString());
    }

    /// <summary>PattN: the IP information of a profile that answered, through the tunnel it was measured through, as <see cref="DoRealPing" /> gets it.</summary>
    private async Task ShowAetherIpInfo(ServerTestItem it, int delay, IWebProxy? webProxy, CancellationToken ct = default)
    {
        if (webProxy != null && !_config.UiItem.HideColumnIpInfo && delay > 0)
        {
            using var downloadHandle = new DownloadService
            {
                Handler = HttpClientHelper.CreateProxySocketsHttpHandler(webProxy, new()),
                DisposeHandler = true,
            };
            var ipInfo = await ConnectionHandler.GetIPInfo(downloadHandle, ct);
            var ipStr = ipInfo?.ToString() ?? Global.None;
            ProfileExManager.Instance.SetTestIpInfo(it.IndexId, ipStr);
            await UpdateIpInfoFunc(it.IndexId, ipStr);
        }
        else
        {
            await UpdateIpInfoFunc(it.IndexId, ResUI.SpeedtestingSkip);
        }
    }

    #endregion PattN: Aether
}
