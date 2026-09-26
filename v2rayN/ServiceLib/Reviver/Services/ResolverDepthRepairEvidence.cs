using ServiceLib.Discovery.Protocol;
using ServiceLib.Reviver.Models;

namespace ServiceLib.Reviver.Services;

/// <summary>
/// Converts resolver-depth observations into explainable Reviver evidence without making DNS diagnostics
/// authoritative over real proxy-core validation.
/// </summary>
public static class ResolverDepthRepairEvidence
{
    public const string EvidenceKind = "discovery.dns.depth";

    public static RepairEvidence Create(
        DiscoveryResolverProfileResult profile,
        string source = "pattn-discovery")
    {
        ArgumentNullException.ThrowIfNull(profile);

        var data = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["quality"] = profile.Quality.NullIfEmpty() ?? "unknown",
            ["status"] = profile.Status.NullIfEmpty() ?? "unknown",
            ["reliabilityFloor"] = profile.ReliabilityFloor.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture),
            ["quorumTransportCount"] = profile.QuorumTransportCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["ednsCompatible"] = profile.EdnsCompatible ? "true" : "false",
            ["ednsDowngrade"] = profile.EdnsDowngrade ? "true" : "false",
            ["encryptedDnsAvailable"] = profile.EncryptedDnsAvailable ? "true" : "false",
            ["interceptionSuspected"] = profile.InterceptionSuspected ? "true" : "false",
        };

        if (profile.ClassicEncryptedAgree is not null)
        {
            data["classicEncryptedAgree"] = profile.ClassicEncryptedAgree.Value ? "true" : "false";
        }
        if (profile.UdpAndTcpAgree is not null)
        {
            data["udpTcpAgree"] = profile.UdpAndTcpAgree.Value ? "true" : "false";
        }
        if (profile.QualityReasons.Count > 0)
        {
            data["qualityReasons"] = string.Join(",", profile.QualityReasons);
        }
        if (profile.InterceptionReasons.Count > 0)
        {
            data["interceptionReasons"] = string.Join(",", profile.InterceptionReasons);
        }
        AddProbe(data, "udp", profile.Udp);
        AddProbe(data, "tcp", profile.Tcp);
        AddProbe(data, "dot", profile.Dot);
        AddProbe(data, "doh", profile.Doh);

        return new RepairEvidence
        {
            Kind = EvidenceKind,
            Source = source,
            Summary = BuildSummary(profile),
            Data = data,
        };
    }

    private static void AddProbe(
        IDictionary<string, string> data,
        string prefix,
        DiscoveryResolverProfileProbe? probe)
    {
        if (probe is null)
        {
            return;
        }

        data[$"{prefix}.attempts"] = probe.Attempts.ToString(System.Globalization.CultureInfo.InvariantCulture);
        data[$"{prefix}.successes"] = probe.Successes.ToString(System.Globalization.CultureInfo.InvariantCulture);
        data[$"{prefix}.quorumMet"] = probe.QuorumMet ? "true" : "false";
        data[$"{prefix}.reliability"] = probe.Reliability.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture);
        if (probe.MedianLatencyMs > 0)
        {
            data[$"{prefix}.medianLatencyMs"] = probe.MedianLatencyMs.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture);
        }
        if (!probe.Alpn.IsNullOrEmpty())
        {
            data[$"{prefix}.alpn"] = probe.Alpn;
        }
        if (!probe.HttpVersion.IsNullOrEmpty())
        {
            data[$"{prefix}.httpVersion"] = probe.HttpVersion;
        }
    }

    private static string BuildSummary(DiscoveryResolverProfileResult profile)
    {
        var quality = profile.Quality.NullIfEmpty() ?? "unknown";
        if (profile.InterceptionSuspected)
        {
            return $"Resolver depth profile is {quality}; classic/encrypted DNS divergence requires caution.";
        }
        return $"Resolver depth profile is {quality} with {profile.QuorumTransportCount} transport(s) meeting quorum.";
    }
}
