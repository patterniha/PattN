using ServiceLib.Reviver.Models;

namespace ServiceLib.Reviver.Validation;

public sealed class RepairValidationAccumulator
{
    private readonly List<int> _latencies = [];
    private readonly List<ERepairFailureClass> _failures = [];
    private int _consecutive;

    public int Attempts { get; private set; }
    public int Successes { get; private set; }
    public int ConsecutiveSuccesses { get; private set; }

    public void AddSuccess(int latencyMs)
    {
        Attempts++;
        Successes++;
        _consecutive++;
        ConsecutiveSuccesses = Math.Max(ConsecutiveSuccesses, _consecutive);
        if (latencyMs > 0)
        {
            _latencies.Add(latencyMs);
        }
    }

    public void AddFailure(ERepairFailureClass failure)
    {
        Attempts++;
        _consecutive = 0;
        _failures.Add(failure);
    }

    public RepairValidationEvidence Build()
    {
        double? median = null;
        if (_latencies.Count > 0)
        {
            var ordered = _latencies.OrderBy(x => x).ToArray();
            var middle = ordered.Length / 2;
            median = ordered.Length % 2 == 1
                ? ordered[middle]
                : (ordered[middle - 1] + ordered[middle]) / 2.0;
        }

        return new RepairValidationEvidence
        {
            Attempts = Attempts,
            Successes = Successes,
            ConsecutiveSuccesses = ConsecutiveSuccesses,
            MedianLatencyMs = median,
            LossRate = Attempts == 0 ? null : (Attempts - Successes) / (double)Attempts,
            Failures = _failures.ToArray(),
        };
    }
}
