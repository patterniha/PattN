using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ServiceLib.Discovery.Services;
using ServiceLib.Models.Entities;
using ServiceLib.Reviver.Models;

namespace ServiceLib.Reviver.Support;

public sealed record ReviverSupportBundle
{
    public int Version { get; init; } = 1;
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
    public string Tokenization { get; init; } = "hmac-sha256/bundle-local/v1";
    public required ReviverSupportProfile Profile { get; init; }
    public required string FailureClass { get; init; }
    public bool Healthy { get; init; }
    public IReadOnlyList<string> InvariantViolationCodes { get; init; } = [];
    public int CoreValidationErrorCount { get; init; }
    public IReadOnlyList<string> ResolvedAddressTokens { get; init; } = [];
    public ReviverSupportValidation? BaselineValidation { get; init; }
    public IReadOnlyList<ReviverSupportEvidence> Evidence { get; init; } = [];
    public IReadOnlyList<ReviverSupportCandidate> Candidates { get; init; } = [];
}

public sealed record ReviverSupportProfile
{
    public required string ConfigType { get; init; }
    public string? CoreType { get; init; }
    public int ConfigVersion { get; init; }
    public int Port { get; init; }
    public required string Network { get; init; }
    public required string StreamSecurity { get; init; }
    public bool AllowInsecure { get; init; }
    public string? Alpn { get; init; }
    public string? Fingerprint { get; init; }
    public string? DialMode { get; init; }
    public string? TargetStrategy { get; init; }
    public bool IsSubscriptionOwned { get; init; }
    public bool? MuxEnabled { get; init; }
    public string? AddressToken { get; init; }
    public string? SniToken { get; init; }
    public string? HttpHostToken { get; init; }
    public string? TransportPathToken { get; init; }
    public int? TransportPathLength { get; init; }
    public string? GrpcAuthorityToken { get; init; }
    public string? GrpcServiceToken { get; init; }
    public string? RawHeaderType { get; init; }
    public string? XhttpMode { get; init; }
    public string? GrpcMode { get; init; }
    public string? KcpHeaderType { get; init; }
    public int? KcpMtu { get; init; }
    public string? Flow { get; init; }
    public string? VmessSecurity { get; init; }
    public string? ShadowsocksMethod { get; init; }
    public string? CongestionControl { get; init; }
    public bool CertificatePresent { get; init; }
    public bool EchConfigPresent { get; init; }
}

public sealed record ReviverSupportValidation
{
    public int Attempts { get; init; }
    public int Successes { get; init; }
    public int ConsecutiveSuccesses { get; init; }
    public double? MedianLatencyMs { get; init; }
    public double? LossRate { get; init; }
    public double? ThroughputMbps { get; init; }
    public IReadOnlyList<string> Failures { get; init; } = [];
}

public sealed record ReviverSupportEvidence
{
    public required string Kind { get; init; }
    public DateTimeOffset ObservedAt { get; init; }
    public string? SourceToken { get; init; }
    public IReadOnlyDictionary<string, string> Data { get; init; } = new Dictionary<string, string>();
}

public sealed record ReviverSupportMutation
{
    public required string Kind { get; init; }
    public required string Field { get; init; }
    public required string Confidence { get; init; }
    public string? From { get; init; }
    public string? To { get; init; }
}

public sealed record ReviverSupportCandidate
{
    public required string State { get; init; }
    public required string FailureClassAddressed { get; init; }
    public double? Score { get; init; }
    public ReviverSupportValidation? Validation { get; init; }
    public IReadOnlyList<ReviverSupportMutation> Mutations { get; init; } = [];
    public IReadOnlyList<ReviverSupportEvidence> Evidence { get; init; } = [];
}

public sealed class ReviverSupportBundleBuilder
{
    private static readonly HashSet<string> SafeMutationFields = new(StringComparer.OrdinalIgnoreCase)
    {
        "port", "network", "streamsecurity", "coretype", "targetstrategy", "dialmode",
        "alpn", "fingerprint", "muxenabled"
    };

    private static readonly HashSet<string> SafeEvidenceKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "address", "attempts", "consecutiveSuccesses", "latencyMs", "lossRate",
        "qualified", "reliability", "status", "successes", "throughputMbps"
    };

    private static readonly HashSet<string> KnownSafeProtocolValues = new(StringComparer.OrdinalIgnoreCase)
    {
        "none", "tcp", "udp", "kcp", "ws", "grpc", "http", "https", "httpupgrade", "splithttp", "xhttp",
        "tls", "reality", "h2", "h3", "http/1.1",
        "chrome", "firefox", "safari", "ios", "android", "edge", "qq", "360", "random", "randomized",
        "auto", "asis", "useip", "useipv4", "useipv6", "preferipv4", "preferipv6",
        "gun", "multi", "packet-up", "stream-up",
        "xtls-rprx-vision", "aes-128-gcm", "chacha20-poly1305", "zero",
        "bbr", "cubic"
    };

    private readonly byte[] _salt;

    public ReviverSupportBundleBuilder()
        : this(RandomNumberGenerator.GetBytes(32))
    {
    }

    internal ReviverSupportBundleBuilder(byte[] bundleSalt)
    {
        ArgumentNullException.ThrowIfNull(bundleSalt);
        _salt = bundleSalt.ToArray();
        if (_salt.Length < 16)
        {
            throw new ArgumentException("Support-bundle tokenization salt must be at least 16 bytes.", nameof(bundleSalt));
        }
    }

    public ReviverSupportBundle Build(RepairRunResult run)
    {
        ArgumentNullException.ThrowIfNull(run);
        var profile = run.Session.Original.CreateWorkingCopy();
        var transport = profile.GetTransportExtra();
        var protocol = profile.GetProtocolExtra();

        return new ReviverSupportBundle
        {
            Profile = new ReviverSupportProfile
            {
                ConfigType = profile.ConfigType.ToString(),
                CoreType = profile.CoreType?.ToString(),
                ConfigVersion = profile.ConfigVersion,
                Port = profile.Port,
                Network = SafeStructured(profile.Network),
                StreamSecurity = SafeStructured(profile.StreamSecurity),
                AllowInsecure = profile.GetAllowInsecure(),
                Alpn = SafeOptional(profile.Alpn),
                Fingerprint = SafeOptional(profile.Fingerprint),
                DialMode = SafeOptional(profile.DialMode),
                TargetStrategy = SafeOptional(profile.TargetStrategy),
                IsSubscriptionOwned = profile.IsSub,
                MuxEnabled = profile.MuxEnabled,
                AddressToken = TokenizeOptional(profile.Address),
                SniToken = TokenizeOptional(profile.Sni),
                HttpHostToken = TokenizeOptional(transport.Host),
                TransportPathToken = TokenizeOptional(transport.Path),
                TransportPathLength = string.IsNullOrEmpty(transport.Path) ? null : transport.Path.Length,
                GrpcAuthorityToken = TokenizeOptional(transport.GrpcAuthority),
                GrpcServiceToken = TokenizeOptional(transport.GrpcServiceName),
                RawHeaderType = SafeOptional(transport.RawHeaderType),
                XhttpMode = SafeOptional(transport.XhttpMode),
                GrpcMode = SafeOptional(transport.GrpcMode),
                KcpHeaderType = SafeOptional(transport.KcpHeaderType),
                KcpMtu = transport.KcpMtu,
                Flow = SafeOptional(protocol.Flow),
                VmessSecurity = SafeOptional(protocol.VmessSecurity),
                ShadowsocksMethod = SafeOptional(protocol.SsMethod),
                CongestionControl = SafeOptional(protocol.CongestionControl),
                CertificatePresent = !string.IsNullOrWhiteSpace(profile.Cert) || !string.IsNullOrWhiteSpace(profile.CertSha),
                EchConfigPresent = !string.IsNullOrWhiteSpace(profile.EchConfigList),
            },
            FailureClass = run.Diagnosis.FailureClass.ToString(),
            Healthy = run.Diagnosis.IsHealthy,
            InvariantViolationCodes = run.Diagnosis.InvariantViolations.Select(x => SafeToken(x.Code)).ToArray(),
            CoreValidationErrorCount = run.Diagnosis.CoreValidationErrors.Count,
            ResolvedAddressTokens = run.Diagnosis.ResolvedAddresses.Select(Tokenize).Distinct(StringComparer.Ordinal).ToArray(),
            BaselineValidation = ProjectValidation(run.Diagnosis.RuntimeValidation ?? run.Session.BaselineValidation),
            Evidence = ProjectEvidence(run.Diagnosis.Evidence),
            Candidates = run.PlannedCandidates.Select(ProjectCandidate).ToArray(),
        };
    }

    public string Serialize(RepairRunResult run)
        => JsonSerializer.Serialize(Build(run), new JsonSerializerOptions { WriteIndented = true });

    public async Task ExportAsync(string destinationPath, RepairRunResult run, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(destinationPath))
        {
            throw new ArgumentException("Support-bundle destination path is required.", nameof(destinationPath));
        }

        var bytes = Encoding.UTF8.GetBytes(Serialize(run) + Environment.NewLine);
        await DurableAtomicFile.WriteAsync(destinationPath, bytes, cancellationToken: cancellationToken);
    }

    private ReviverSupportCandidate ProjectCandidate(RepairCandidate candidate)
        => new()
        {
            State = candidate.State.ToString(),
            FailureClassAddressed = candidate.FailureClassAddressed.ToString(),
            Score = candidate.Score,
            Validation = ProjectValidation(candidate.Validation),
            Mutations = candidate.Mutations.Select(ProjectMutation).ToArray(),
            Evidence = ProjectEvidence(candidate.Evidence),
        };

    private ReviverSupportMutation ProjectMutation(RepairMutation mutation)
        => new()
        {
            Kind = mutation.Kind.ToString(),
            Field = SafeToken(mutation.Field),
            Confidence = mutation.Confidence.ToString(),
            From = SanitizeMutationValue(mutation.Field, mutation.From),
            To = SanitizeMutationValue(mutation.Field, mutation.To),
        };

    private IReadOnlyList<ReviverSupportEvidence> ProjectEvidence(IEnumerable<RepairEvidence> evidence)
        => evidence.Select(item => new ReviverSupportEvidence
        {
            Kind = SafeToken(item.Kind),
            ObservedAt = item.ObservedAt,
            SourceToken = TokenizeOptional(item.Source),
            Data = item.Data.ToDictionary(
                pair => SanitizeEvidenceKey(pair.Key),
                pair => SanitizeEvidenceValue(pair.Key, pair.Value),
                StringComparer.Ordinal),
        }).ToArray();

    private static ReviverSupportValidation? ProjectValidation(RepairValidationEvidence? value)
        => value is null ? null : new ReviverSupportValidation
        {
            Attempts = value.Attempts,
            Successes = value.Successes,
            ConsecutiveSuccesses = value.ConsecutiveSuccesses,
            MedianLatencyMs = value.MedianLatencyMs,
            LossRate = value.LossRate,
            ThroughputMbps = value.ThroughputMbps,
            Failures = value.Failures.Select(x => x.ToString()).ToArray(),
        };

    private string? SanitizeMutationValue(string field, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }
        return SafeMutationFields.Contains(field.Trim()) ? SafeOptional(value) : Tokenize(value);
    }

    private string SanitizeEvidenceKey(string key)
    {
        var trimmed = key.Trim();
        if (SafeEvidenceKeys.Contains(trimmed))
        {
            return SafeToken(trimmed);
        }

        // Evidence producers are extensible. A future producer must not be able
        // to leak user-controlled material merely by placing it in a dictionary key.
        return "key:" + Tokenize(trimmed).AsSpan(4).ToString();
    }

    private string SanitizeEvidenceValue(string key, string value)
    {
        _ = key;
        var trimmed = value.Trim();
        if (bool.TryParse(trimmed, out _)
            || double.TryParse(trimmed, NumberStyles.Float, CultureInfo.InvariantCulture, out _))
        {
            return trimmed;
        }

        // Evidence dictionaries are extensible and may accidentally place a host,
        // URI, token, or user-controlled string under an apparently harmless key.
        // Preserve only scalar numeric/bool values verbatim; tokenize all text.
        return Tokenize(trimmed);
    }

    private string? TokenizeOptional(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : Tokenize(value);

    private string Tokenize(string value)
    {
        var hash = HMACSHA256.HashData(_salt, Encoding.UTF8.GetBytes(value.Trim()));
        return "tok:" + Convert.ToHexString(hash.AsSpan(0, 12)).ToLowerInvariant();
    }

    private static string SafeToken(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : new string(value.Trim().Take(64)
                .Select(ch => char.IsLetterOrDigit(ch) || ch is '-' or '_' or '.' or ':' ? ch : '_')
                .ToArray());

    private string SafeStructured(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var trimmed = value.Trim();
        return KnownSafeProtocolValues.Contains(trimmed)
            ? SafeToken(trimmed)
            : Tokenize(trimmed);
    }

    private string? SafeOptional(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : SafeStructured(value);
}
