using ServiceLib.Reviver.Models;

namespace ServiceLib.Reviver.Validation;

/// <summary>
/// Validates an in-memory repair candidate through PattN's real temporary speed-test core path. Nothing is
/// persisted. A candidate is considered revived only after repeated application-level requests traverse the
/// generated local SOCKS inbound successfully.
/// </summary>
public sealed class CoreBackedRepairValidator(RepairPolicy? policy = null) : IRepairCandidateValidator
{
    private readonly RepairPolicy _policy = policy ?? new RepairPolicy();

    public async Task<RepairValidationEvidence> ValidateAsync(
        RepairCandidate candidate,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        var profile = JsonUtils.DeepCopy(candidate.Profile)
            ?? throw new InvalidOperationException("Could not clone repair candidate for validation.");

        var testItem = new ServerTestItem
        {
            IndexId = profile.IndexId,
            Address = profile.Address,
            ConfigType = profile.ConfigType,
            QueueNum = 0,
            Profile = profile,
            CoreType = profile.CoreType ?? ECoreType.Xray,
            AllowTest = true,
        };

        ProcessService? process = null;
        var accumulator = new RepairValidationAccumulator();
        try
        {
            process = await CoreManager.Instance.LoadCoreConfigSpeedtest(testItem);
            if (process is null)
            {
                accumulator.AddFailure(ERepairFailureClass.CoreStartupFailure);
                return accumulator.Build();
            }

            if (!await WaitForPortAsync(testItem.Port, cancellationToken))
            {
                accumulator.AddFailure(ERepairFailureClass.CoreStartupFailure);
                return accumulator.Build();
            }

            var proxy = new WebProxy($"socks5://{Global.Loopback}:{testItem.Port}");
            for (var attempt = 0; attempt < _policy.RuntimeAttempts; attempt++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var latency = await ConnectionHandler.GetRealPingTime(proxy, cancellationToken);
                if (latency > 0)
                {
                    accumulator.AddSuccess(latency);
                }
                else
                {
                    accumulator.AddFailure(ERepairFailureClass.ApplicationProbeFailure);
                }

                var evidence = accumulator.Build();
                var remaining = _policy.RuntimeAttempts - evidence.Attempts;
                if (evidence.Successes >= _policy.MinimumRuntimeSuccesses
                    || evidence.Successes + remaining < _policy.MinimumRuntimeSuccesses)
                {
                    break;
                }
            }

            return accumulator.Build();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            Logging.SaveLog(nameof(CoreBackedRepairValidator), ex);
            accumulator.AddFailure(ERepairFailureClass.CoreStartupFailure);
            return accumulator.Build();
        }
        finally
        {
            if (process is not null)
            {
                await process.StopAsync();
                process.Dispose();
            }
        }
    }

    private static async Task<bool> WaitForPortAsync(int port, CancellationToken cancellationToken)
    {
        if (port <= 0)
        {
            return false;
        }

        var deadline = DateTime.UtcNow.AddSeconds(3);
        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var client = new TcpClient();
            using var attemptCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            attemptCts.CancelAfter(TimeSpan.FromMilliseconds(200));
            try
            {
                await client.ConnectAsync(Global.Loopback, port, attemptCts.Token);
                return true;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                await Task.Delay(100, cancellationToken);
            }
        }
        return false;
    }
}
