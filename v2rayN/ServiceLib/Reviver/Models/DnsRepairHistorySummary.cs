namespace ServiceLib.Reviver.Models;

public sealed record DnsRepairFamilyHistory
{
    public required string Family { get; init; }
    public int Samples { get; init; }
    public int RuntimeQuorumPasses { get; init; }
    public double PassRate => Samples <= 0 ? 0.5d : (double)RuntimeQuorumPasses / Samples;
    public double? MedianLatencyMs { get; init; }
}

/// <summary>
/// Historical family pass rates intentionally use only single-family Use/Force validations.
/// Dual-stack *v4v6/*v6v4 outcomes are retained in persistent history but cannot prove which family carried traffic.
/// </summary>
public sealed record DnsRepairHistorySummary
{
    public required string Host { get; init; }
    public DnsRepairFamilyHistory IPv4 { get; init; } = new() { Family = "ipv4" };
    public DnsRepairFamilyHistory IPv6 { get; init; } = new() { Family = "ipv6" };
    public int TotalSamples => IPv4.Samples + IPv6.Samples;

    public string? PreferredFamily(int minimumSamplesPerFamily = 3, double minimumPassRateDelta = 0.20d)
    {
        if (IPv4.Samples < minimumSamplesPerFamily || IPv6.Samples < minimumSamplesPerFamily)
        {
            return null;
        }

        var delta = IPv4.PassRate - IPv6.PassRate;
        const double epsilon = 1e-9;
        if (Math.Abs(delta) <= minimumPassRateDelta + epsilon)
        {
            return null;
        }
        return delta > 0 ? "ipv4" : "ipv6";
    }
}
