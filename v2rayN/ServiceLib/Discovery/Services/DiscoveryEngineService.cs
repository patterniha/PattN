using System.Threading.Channels;
using ServiceLib.Discovery.Protocol;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Persistent NDJSON client for the bundled pattn-discovery helper. Stdout is protocol-only; stderr is drained
/// independently so helper diagnostics can never corrupt response framing.
/// </summary>
public sealed class DiscoveryEngineService : IAsyncDisposable, IDiscoveryEndpointProbeClient, IDiscoveryDnsDiagnosticClient
{
    public const int ProtocolVersion = 1;

    private readonly string _executablePath;
    private readonly SemaphoreSlim _startLock = new(1, 1);
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly ConcurrentDictionary<string, TaskCompletionSource<DiscoveryRpcResponse>> _pending = new();
    private readonly ConcurrentDictionary<string, Channel<DiscoveryRpcResponse>> _streams = new();
    private readonly CancellationTokenSource _disposeCts = new();

    private Process? _process;
    private Task? _stdoutLoop;
    private Task? _stderrLoop;
    private int _disposeState;

    public DiscoveryEngineService(string? executablePath = null)
    {
        _executablePath = executablePath ?? GetDefaultExecutablePath();
    }

    public bool IsRunning
    {
        get
        {
            var process = Volatile.Read(ref _process);
            return process is not null && !process.HasExited;
        }
    }

    public static string GetDefaultExecutablePath()
        => Utils.GetBinPath(Utils.GetExeName("pattn-discovery"), "pattn-discovery");

    public async Task<DiscoveryEngineVersion> GetVersionAsync(CancellationToken cancellationToken = default)
        => await InvokeAsync<DiscoveryEngineVersion>("engine.version", null, cancellationToken);

    public async Task<DiscoveryCapabilities> GetCapabilitiesAsync(CancellationToken cancellationToken = default)
        => await InvokeAsync<DiscoveryCapabilities>("engine.capabilities", null, cancellationToken);

    public async Task<DiscoveryTargetInspection> InspectTargetsAsync(
        IEnumerable<string> targets,
        CancellationToken cancellationToken = default)
        => await InvokeAsync<DiscoveryTargetInspection>(
            "targets.inspect",
            new { targets = targets.Where(x => !string.IsNullOrWhiteSpace(x)).ToArray() },
            cancellationToken);

    public async Task<DiscoveryTargetNormalizeResponse> NormalizeTargetsAsync(
        DiscoveryTargetNormalizeRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.Source.Id))
        {
            throw new ArgumentException("Target source ID is required.", nameof(request));
        }
        if (string.IsNullOrWhiteSpace(request.Source.Kind))
        {
            throw new ArgumentException("Target source kind is required.", nameof(request));
        }
        return await InvokeAsync<DiscoveryTargetNormalizeResponse>("targets.normalize", request, cancellationToken);
    }

    public async Task<DiscoveryEndpointProbeResponse> ProbeEndpointsAsync(
        DiscoveryEndpointProbeRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Port is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "Endpoint probe port must be between 1 and 65535.");
        }
        if (request.Addresses.Count == 0)
        {
            return new DiscoveryEndpointProbeResponse();
        }

        return await InvokeAsync<DiscoveryEndpointProbeResponse>("endpoint.probe", request, cancellationToken);
    }

    public async Task<DiscoveryDnsTraceResult> TraceDnsAsync(
        DiscoveryDeepDnsRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.Domain))
        {
            throw new ArgumentException("DNS trace domain is required.", nameof(request));
        }
        if (request.QueryType is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "DNS query type must be between 1 and 65535.");
        }
        return await InvokeAsync<DiscoveryDnsTraceResult>("dns.trace", request, cancellationToken);
    }

    public async Task<DiscoveryDnsAuthorityComparison> CompareDnsAuthoritiesAsync(
        DiscoveryDeepDnsRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.Domain))
        {
            throw new ArgumentException("DNS authority comparison domain is required.", nameof(request));
        }
        if (request.QueryType is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "DNS query type must be between 1 and 65535.");
        }
        return await InvokeAsync<DiscoveryDnsAuthorityComparison>("dns.authority.compare", request, cancellationToken);
    }

    public async Task<DiscoveryDnssecChainResult> ValidateDnssecChainAsync(
        DiscoveryDeepDnsRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.Domain))
        {
            throw new ArgumentException("DNSSEC chain target zone is required.", nameof(request));
        }
        return await InvokeAsync<DiscoveryDnssecChainResult>("dns.dnssec.chain", request, cancellationToken);
    }

    public async Task<DiscoveryDnssecDomainValidation> ValidateDnssecAsync(
        DiscoveryDeepDnsRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.Domain))
        {
            throw new ArgumentException("DNSSEC validation domain is required.", nameof(request));
        }
        if (request.QueryType is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "DNS query type must be between 1 and 65535.");
        }
        return await InvokeAsync<DiscoveryDnssecDomainValidation>("dns.dnssec.validate", request, cancellationToken);
    }

    public async Task<DiscoveryDnssecInspection> InspectDnssecAsync(
        DiscoveryDeepDnsRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.Domain))
        {
            throw new ArgumentException("DNSSEC inspection domain is required.", nameof(request));
        }
        return await InvokeAsync<DiscoveryDnssecInspection>("dns.dnssec.inspect", request, cancellationToken);
    }

    public async Task<DiscoveryDnsTrustAnchorAudit> AuditDnsTrustAnchorsAsync(
        int maxAgeDays = 90,
        CancellationToken cancellationToken = default)
    {
        if (maxAgeDays is < 1 or > 3650)
        {
            throw new ArgumentOutOfRangeException(nameof(maxAgeDays), "Trust-anchor freshness window must be between 1 and 3650 days.");
        }
        return await InvokeAsync<DiscoveryDnsTrustAnchorAudit>(
            "dns.trust-anchor.audit",
            new { maxAgeDays },
            cancellationToken);
    }

    public async Task<DiscoveryDnsRepairInspection> InspectDnsRepairAsync(
        DiscoveryDeepDnsRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.Domain))
        {
            throw new ArgumentException("DNS repair inspection domain is required.", nameof(request));
        }
        return await InvokeAsync<DiscoveryDnsRepairInspection>("dns.repair.inspect", request, cancellationToken);
    }

    public async Task<DiscoveryResolverCatalogAudit> AuditResolverCatalogAsync(
        int maxAgeDays = 90,
        CancellationToken cancellationToken = default)
    {
        if (maxAgeDays is < 1 or > 3650)
        {
            throw new ArgumentOutOfRangeException(nameof(maxAgeDays), "Catalog freshness window must be between 1 and 3650 days.");
        }
        return await InvokeAsync<DiscoveryResolverCatalogAudit>(
            "dns.resolver.catalog.audit",
            new { maxAgeDays },
            cancellationToken);
    }

    public Task<DiscoveryResolverCatalog> GetResolverCatalogAsync(
        CancellationToken cancellationToken = default)
        => InvokeAsync<DiscoveryResolverCatalog>("dns.resolver.catalog", new { }, cancellationToken);

    public async Task<DiscoveryDnsConsensusComparison> CompareDnsConsensusAsync(
        DiscoveryDnsConsensusRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.Domain))
        {
            throw new ArgumentException("DNS consensus domain is required.", nameof(request));
        }
        if (request.QueryType is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "DNS query type must be between 1 and 65535.");
        }
        foreach (var resolver in request.TrustedResolvers.Concat(request.CandidateResolvers))
        {
            if (string.IsNullOrWhiteSpace(resolver.Address))
            {
                throw new ArgumentException("Resolver address is required.", nameof(request));
            }
            if (resolver.Port is < 1 or > 65535)
            {
                throw new ArgumentOutOfRangeException(nameof(request), "Resolver port must be between 1 and 65535.");
            }
            if (request.CheckDepth && !string.IsNullOrWhiteSpace(resolver.ServerName) && resolver.DotPort is < 1 or > 65535)
            {
                throw new ArgumentOutOfRangeException(nameof(request), "Resolver DoT port must be between 1 and 65535.");
            }
        }
        if (request.CheckDepth && (request.DepthAttempts is < 1 or > 7 ||
            request.DepthMinSuccesses is < 1 || request.DepthMinSuccesses > request.DepthAttempts))
        {
            throw new ArgumentOutOfRangeException(nameof(request), "Depth quorum must satisfy 1 <= minimum successes <= attempts <= 7.");
        }
        return await InvokeAsync<DiscoveryDnsConsensusComparison>("dns.consensus.compare", request, cancellationToken);
    }

    public async Task<DiscoveryResolverProfileResult> ProfileResolverAsync(
        DiscoveryResolverProfileRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.Address))
        {
            throw new ArgumentException("Resolver address is required.", nameof(request));
        }
        if (request.Port is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "Resolver port must be between 1 and 65535.");
        }
        if (string.IsNullOrWhiteSpace(request.Domain))
        {
            throw new ArgumentException("Resolver profile domain is required.", nameof(request));
        }
        if (request.CheckDot && string.IsNullOrWhiteSpace(request.ServerName))
        {
            throw new ArgumentException("DoT server name is required when DoT profiling is enabled.", nameof(request));
        }
        if (request.CheckDot && request.DotPort is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "DoT port must be between 1 and 65535.");
        }
        if (request.CheckDoh && string.IsNullOrWhiteSpace(request.DohUrl))
        {
            throw new ArgumentException("DoH URL is required when DoH profiling is enabled.", nameof(request));
        }
        if (request.Attempts is < 1 or > 7)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "Resolver profile attempts must be between 1 and 7.");
        }
        if (request.MinSuccesses is < 1 || request.MinSuccesses > request.Attempts)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "Resolver profile minimum successes must be between 1 and Attempts.");
        }
        return await InvokeAsync<DiscoveryResolverProfileResult>("dns.resolver.profile", request, cancellationToken);
    }

    public async Task<DiscoveryResolverQualification> QualifyResolverAsync(
        DiscoveryResolverQualificationRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.Address))
        {
            throw new ArgumentException("Resolver address is required.", nameof(request));
        }
        if (request.Port is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "Resolver port must be between 1 and 65535.");
        }
        if (string.IsNullOrWhiteSpace(request.Domain))
        {
            throw new ArgumentException("Qualification domain is required.", nameof(request));
        }
        if (request.CheckDepth && !string.IsNullOrWhiteSpace(request.ServerName) && request.DotPort is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "DoT port must be between 1 and 65535.");
        }
        if (request.CheckDepth && (request.DepthAttempts is < 1 or > 7 ||
            request.DepthMinSuccesses is < 1 || request.DepthMinSuccesses > request.DepthAttempts))
        {
            throw new ArgumentOutOfRangeException(nameof(request), "Depth quorum must satisfy 1 <= minimum successes <= attempts <= 7.");
        }
        return await InvokeAsync<DiscoveryResolverQualification>("dns.resolver.qualify", request, cancellationToken);
    }

    public async IAsyncEnumerable<DiscoveryTcpScanEvent> ScanTcpAsync(
        DiscoveryTcpScanRequest request,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Targets.Count == 0)
        {
            yield break;
        }
        if (request.Ports.Count == 0 || request.Ports.Any(x => x is < 1 or > 65535))
        {
            throw new ArgumentOutOfRangeException(nameof(request), "TCP scan ports must be between 1 and 65535.");
        }

        await foreach (var response in InvokeStreamAsync("scan.tcp", request, cancellationToken).WithCancellation(cancellationToken))
        {
            yield return response.Event switch
            {
                "started" => new DiscoveryTcpScanEvent { Event = response.Event, Started = DeserializeData<DiscoveryTcpScanStarted>(response) },
                "result" => new DiscoveryTcpScanEvent { Event = response.Event, Result = DeserializeData<DiscoveryTcpScanResult>(response) },
                "progress" => new DiscoveryTcpScanEvent { Event = response.Event, Progress = DeserializeData<DiscoveryTcpScanProgress>(response) },
                "completed" or "cancelled" => new DiscoveryTcpScanEvent { Event = response.Event, Summary = DeserializeData<DiscoveryTcpScanSummary>(response) },
                _ => new DiscoveryTcpScanEvent { Event = response.Event },
            };
        }
    }

    public async IAsyncEnumerable<DiscoveryResolverEvent> DiscoverResolversAsync(
        DiscoveryResolverRequest request,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Targets.Count == 0)
        {
            yield break;
        }
        if (request.Port is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "DNS resolver port must be between 1 and 65535.");
        }
        if (string.IsNullOrWhiteSpace(request.Domain))
        {
            throw new ArgumentException("DNS discovery domain is required.", nameof(request));
        }

        await foreach (var response in InvokeStreamAsync("dns.resolver.discover", request, cancellationToken).WithCancellation(cancellationToken))
        {
            yield return response.Event switch
            {
                "started" => new DiscoveryResolverEvent { Event = response.Event, Started = DeserializeData<DiscoveryResolverStarted>(response) },
                "result" => new DiscoveryResolverEvent { Event = response.Event, Result = DeserializeData<DiscoveryResolverResult>(response) },
                "progress" => new DiscoveryResolverEvent { Event = response.Event, Progress = DeserializeData<DiscoveryResolverProgress>(response) },
                "completed" or "cancelled" => new DiscoveryResolverEvent { Event = response.Event, Summary = DeserializeData<DiscoveryResolverSummary>(response) },
                _ => new DiscoveryResolverEvent { Event = response.Event },
            };
        }
    }

    public Task<DiscoveryScanControl> PauseScanAsync(string scanId, CancellationToken cancellationToken = default)
        => InvokeAsync<DiscoveryScanControl>("scan.pause", new { scanId }, cancellationToken);

    public Task<DiscoveryScanControl> ResumeScanAsync(string scanId, CancellationToken cancellationToken = default)
        => InvokeAsync<DiscoveryScanControl>("scan.resume", new { scanId }, cancellationToken);

    public Task<DiscoveryScanControl> CancelScanAsync(string scanId, CancellationToken cancellationToken = default)
        => InvokeAsync<DiscoveryScanControl>("scan.cancel", new { scanId }, cancellationToken);

    public async Task<T> InvokeAsync<T>(string method, object? parameters, CancellationToken cancellationToken = default)
    {
        await EnsureStartedAsync(cancellationToken);
        var process = _process ?? throw new InvalidOperationException("pattn-discovery did not start.");
        var id = Guid.NewGuid().ToString("N");
        var completion = new TaskCompletionSource<DiscoveryRpcResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_pending.TryAdd(id, completion))
        {
            throw new InvalidOperationException("Could not reserve discovery request id.");
        }

        var requestSent = false;
        try
        {
            var request = new DiscoveryRpcRequest { Id = id, Method = method, Params = parameters };
            await SendRequestAsync(process, request, cancellationToken);
            requestSent = true;

            using var registration = cancellationToken.Register(() => completion.TrySetCanceled(cancellationToken));
            DiscoveryRpcResponse response;
            try
            {
                response = await completion.Task;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                if (requestSent && IsRunning)
                {
                    await TryCancelUnaryRequestAsync(id, process);
                }
                throw;
            }
            if (response.Error is not null)
            {
                throw new DiscoveryRpcException(response.Error.Code, response.Error.Message);
            }
            if (response.Version != ProtocolVersion)
            {
                throw new DiscoveryRpcException("protocol_version_mismatch", $"Expected {ProtocolVersion}, received {response.Version}.");
            }
            return response.Data.Deserialize<T>()
                ?? throw new DiscoveryRpcException("invalid_response", $"Method '{method}' returned no data.");
        }
        finally
        {
            _pending.TryRemove(id, out _);
        }
    }

    private async IAsyncEnumerable<DiscoveryRpcResponse> InvokeStreamAsync(
        string method,
        object? parameters,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        await EnsureStartedAsync(cancellationToken);
        var process = _process ?? throw new InvalidOperationException("pattn-discovery did not start.");
        var id = Guid.NewGuid().ToString("N");
        var channel = Channel.CreateBounded<DiscoveryRpcResponse>(new BoundedChannelOptions(256)
        {
            SingleReader = true,
            SingleWriter = true,
            FullMode = BoundedChannelFullMode.Wait,
        });
        if (!_streams.TryAdd(id, channel))
        {
            throw new InvalidOperationException("Could not reserve discovery stream id.");
        }

        var request = new DiscoveryRpcRequest { Id = id, Method = method, Params = parameters };
        var requestSent = false;
        var terminalReceived = false;
        string? scanId = null;
        try
        {
            await SendRequestAsync(process, request, cancellationToken);
            requestSent = true;
            await foreach (var response in channel.Reader.ReadAllAsync(cancellationToken))
            {
                if (response.Error is not null)
                {
                    throw new DiscoveryRpcException(response.Error.Code, response.Error.Message);
                }
                if (response.Version != ProtocolVersion)
                {
                    throw new DiscoveryRpcException("protocol_version_mismatch", $"Expected {ProtocolVersion}, received {response.Version}.");
                }
                if (response.Event.Equals("started", StringComparison.OrdinalIgnoreCase)
                    && response.Data.ValueKind == JsonValueKind.Object
                    && response.Data.TryGetProperty("scanId", out var scanIdElement)
                    && scanIdElement.ValueKind == JsonValueKind.String)
                {
                    scanId = scanIdElement.GetString();
                }
                if (response.Event.Equals("completed", StringComparison.OrdinalIgnoreCase)
                    || response.Event.Equals("cancelled", StringComparison.OrdinalIgnoreCase))
                {
                    terminalReceived = true;
                }
                yield return response;
            }
        }
        finally
        {
            _streams.TryRemove(id, out _);
            channel.Writer.TryComplete();
            if (requestSent && !terminalReceived && IsRunning)
            {
                await TryCancelStreamingRequestAsync(scanId.NullIfEmpty() ?? id, process);
            }
        }
    }

    public async Task StopAsync()
    {
        await _startLock.WaitAsync();
        try
        {
            var process = Interlocked.Exchange(ref _process, null);
            if (process is null)
            {
                return;
            }

            var stdoutLoop = _stdoutLoop;
            var stderrLoop = _stderrLoop;
            try
            {
                if (!process.HasExited)
                {
                    process.StandardInput.Close();
                    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                    try
                    {
                        await process.WaitForExitAsync(timeout.Token);
                    }
                    catch (OperationCanceledException)
                    {
                        if (!process.HasExited)
                        {
                            process.Kill(true);
                            await process.WaitForExitAsync();
                        }
                    }
                }

                // The process owns the redirected streams. Let both drain through EOF before disposal so a
                // normal stop cannot race the readers into ObjectDisposedException or strand buffered output.
                var drains = new[] { stdoutLoop, stderrLoop }
                    .Where(x => x is not null)
                    .Cast<Task>()
                    .ToArray();
                if (drains.Length > 0)
                {
                    await Task.WhenAll(drains);
                }
            }
            finally
            {
                if (ReferenceEquals(_stdoutLoop, stdoutLoop))
                {
                    _stdoutLoop = null;
                }
                if (ReferenceEquals(_stderrLoop, stderrLoop))
                {
                    _stderrLoop = null;
                }
                process.Dispose();
                FailAllPending(new IOException("pattn-discovery stopped."));
            }
        }
        finally
        {
            _startLock.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposeState, 1) != 0)
        {
            return;
        }

        _disposeCts.Cancel();
        await StopAsync();
        _disposeCts.Dispose();
        _startLock.Dispose();
        _writeLock.Dispose();
    }

    private async Task EnsureStartedAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (IsRunning)
        {
            return;
        }

        await _startLock.WaitAsync(cancellationToken);
        try
        {
            ThrowIfDisposed();
            if (IsRunning)
            {
                return;
            }

            var staleProcess = _process;
            var staleStdout = _stdoutLoop;
            if (staleProcess is not null)
            {
                if (staleStdout is not null)
                {
                    try
                    {
                        await staleStdout;
                    }
                    catch
                    {
                        // ReadStdoutAsync converts terminal failures into pending-request failures.
                    }
                }

                if (ReferenceEquals(_process, staleProcess))
                {
                    Interlocked.CompareExchange(ref _process, null, staleProcess);
                    FailAllPending(new IOException("Previous pattn-discovery process exited before restart."));
                    staleProcess.Dispose();
                }
            }

            if (!File.Exists(_executablePath))
            {
                throw new FileNotFoundException("Bundled pattn-discovery helper was not found.", _executablePath);
            }

            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = _executablePath,
                    WorkingDirectory = Path.GetDirectoryName(_executablePath) ?? Utils.StartupPath(),
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                },
                EnableRaisingEvents = false,
            };
            if (!process.Start())
            {
                process.Dispose();
                throw new InvalidOperationException("Failed to start pattn-discovery.");
            }

            Interlocked.Exchange(ref _process, process);
            _stdoutLoop = ReadStdoutAsync(process, _disposeCts.Token);
            _stderrLoop = DrainStderrAsync(process, _disposeCts.Token);
        }
        finally
        {
            _startLock.Release();
        }
    }

    private async Task ReadStdoutAsync(Process process, CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var line = await process.StandardOutput.ReadLineAsync(cancellationToken);
                if (line is null)
                {
                    break;
                }
                DiscoveryRpcResponse? response;
                try
                {
                    response = JsonSerializer.Deserialize<DiscoveryRpcResponse>(line);
                }
                catch (JsonException ex)
                {
                    // Malformed protocol stdout makes this helper generation unusable. Scope the failure to
                    // the generation that produced it so a late line from an old process cannot poison a
                    // replacement process's pending requests.
                    FailAllPendingIfCurrent(
                        process,
                        new DiscoveryRpcException("invalid_json_from_engine", ex.Message));
                    return;
                }
                if (response is null || response.Id.IsNullOrEmpty())
                {
                    continue;
                }
                if (_streams.TryGetValue(response.Id, out var stream))
                {
                    // Never await a bounded stream write from the one stdout reader. A stalled consumer must
                    // not head-of-line block unrelated unary RPCs, scan control, or other streams. Keep the
                    // per-stream memory bound: if its buffer is full, fail that stream explicitly and ask the
                    // owning helper generation to cancel the producer.
                    if (!stream.Writer.TryWrite(response))
                    {
                        if (!stream.Reader.Completion.IsCompleted
                            && _streams.TryRemove(response.Id, out var stalled))
                        {
                            stalled.Writer.TryComplete(
                                new DiscoveryRpcException(
                                    "stream_backpressure_exceeded",
                                    "Discovery stream consumer did not keep up with the bounded response buffer."));
                            _ = TryCancelStreamingRequestAsync(response.Id, process);
                        }
                        continue;
                    }
                    if (response.Error is not null
                        || response.Event.Equals("completed", StringComparison.OrdinalIgnoreCase)
                        || response.Event.Equals("cancelled", StringComparison.OrdinalIgnoreCase))
                    {
                        stream.Writer.TryComplete();
                    }
                    continue;
                }
                if (_pending.TryGetValue(response.Id, out var completion))
                {
                    if (response.Event.IsNullOrEmpty() || response.Error is not null)
                    {
                        completion.TrySetResult(response);
                    }
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            FailAllPendingIfCurrent(process, ex);
            return;
        }

        if (!cancellationToken.IsCancellationRequested)
        {
            var exitMessage = process.HasExited
                ? $"pattn-discovery exited with code {process.ExitCode}."
                : "pattn-discovery stdout closed unexpectedly.";
            FailAllPendingIfCurrent(process, new IOException(exitMessage));
        }
    }

    private static async Task DrainStderrAsync(Process process, CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var line = await process.StandardError.ReadLineAsync(cancellationToken);
                if (line is null)
                {
                    break;
                }
                if (!string.IsNullOrWhiteSpace(line))
                {
                    Logging.SaveLog($"pattn-discovery: {line}");
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            Logging.SaveLog("pattn-discovery stderr", ex);
        }
    }

    private async Task SendRequestAsync(Process process, DiscoveryRpcRequest request, CancellationToken cancellationToken)
    {
        var json = JsonSerializer.Serialize(request);
        await _writeLock.WaitAsync(cancellationToken);
        try
        {
            await process.StandardInput.WriteLineAsync(json.AsMemory(), cancellationToken);
            await process.StandardInput.FlushAsync(cancellationToken);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private async Task TryCancelUnaryRequestAsync(string requestId, Process? expectedProcess = null)
    {
        var process = Volatile.Read(ref _process);
        if (process is null
            || process.HasExited
            || (expectedProcess is not null && !ReferenceEquals(process, expectedProcess)))
        {
            return;
        }
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            await SendRequestAsync(process, new DiscoveryRpcRequest
            {
                Id = Guid.NewGuid().ToString("N"),
                Method = "request.cancel",
                Params = new { requestId },
            }, timeout.Token);
        }
        catch (Exception ex)
        {
            Logging.SaveLog("pattn-discovery unary cancellation", ex);
        }
    }

    private async Task TryCancelStreamingRequestAsync(string scanId, Process? expectedProcess = null)
    {
        var process = Volatile.Read(ref _process);
        if (process is null
            || process.HasExited
            || (expectedProcess is not null && !ReferenceEquals(process, expectedProcess)))
        {
            return;
        }
        try
        {
            // Cancellation is best-effort cleanup. Never let an unresponsive helper
            // pipe or a blocked write lock turn caller cancellation into an unbounded wait.
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            await SendRequestAsync(process, new DiscoveryRpcRequest
            {
                Id = Guid.NewGuid().ToString("N"),
                Method = "scan.cancel",
                Params = new { scanId },
            }, timeout.Token);
        }
        catch (Exception ex)
        {
            Logging.SaveLog("pattn-discovery stream cancellation", ex);
        }
    }

    private static T DeserializeData<T>(DiscoveryRpcResponse response)
        => response.Data.Deserialize<T>()
           ?? throw new DiscoveryRpcException("invalid_response", $"Event '{response.Event}' returned no data.");

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposeState) != 0)
        {
            throw new ObjectDisposedException(nameof(DiscoveryEngineService));
        }
    }

    private void FailAllPendingIfCurrent(Process process, Exception error)
    {
        if (!ReferenceEquals(Interlocked.CompareExchange(ref _process, null, process), process))
        {
            return;
        }

        try
        {
            FailAllPending(error);
            if (!process.HasExited)
            {
                process.Kill(true);
            }
        }
        catch (Exception ex)
        {
            Logging.SaveLog("pattn-discovery terminal cleanup", ex);
        }
        finally
        {
            process.Dispose();
        }
    }

    private void FailAllPending(Exception error)
    {
        foreach (var completion in _pending.Values)
        {
            completion.TrySetException(error);
        }
        foreach (var stream in _streams.Values)
        {
            stream.Writer.TryComplete(error);
        }
    }
}
