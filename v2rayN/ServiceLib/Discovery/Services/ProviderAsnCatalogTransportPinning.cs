using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ServiceLib.Discovery.Models;

namespace ServiceLib.Discovery.Services;

public static class ProviderAsnCatalogTransportPinning
{
    public const int MaximumPins = 8;

    public static IReadOnlyList<string> NormalizePins(IEnumerable<string>? pins)
    {
        if (pins is null)
        {
            return [];
        }

        var values = pins
            .Select(x => (x ?? string.Empty).Trim().ToLowerInvariant())
            .Where(x => !x.IsNullOrEmpty())
            .Distinct(StringComparer.Ordinal)
            .OrderBy(x => x, StringComparer.Ordinal)
            .ToArray();

        if (values.Length > MaximumPins)
        {
            throw new ArgumentOutOfRangeException(nameof(pins), $"At most {MaximumPins} TLS SPKI pins may be configured.");
        }

        foreach (var pin in values)
        {
            if (pin.Length != 64 || !pin.All(Uri.IsHexDigit))
            {
                throw new ArgumentException("TLS SPKI pins must be 64-character SHA-256 hex digests.", nameof(pins));
            }
        }
        return values;
    }

    public static string ComputeSpkiSha256(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var spki = certificate.PublicKey.ExportSubjectPublicKeyInfo();
        return Convert.ToHexString(SHA256.HashData(spki)).ToLowerInvariant();
    }

    public static bool Matches(X509Certificate2 certificate, IReadOnlyList<string> normalizedPins)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(normalizedPins);
        if (normalizedPins.Count == 0)
        {
            return true;
        }

        var actual = ComputeSpkiSha256(certificate);
        return normalizedPins.Contains(actual, StringComparer.Ordinal);
    }

    public static bool IsCertificateAccepted(
        X509Certificate2? certificate,
        SslPolicyErrors policyErrors,
        IEnumerable<string>? pins)
    {
        if (policyErrors != SslPolicyErrors.None || certificate is null)
        {
            return false;
        }

        var normalized = NormalizePins(pins);
        return Matches(certificate, normalized);
    }

    public static IReadOnlyList<string> ParseEditorText(string? text)
    {
        if (text.IsNullOrEmpty())
        {
            return [];
        }

        return NormalizePins(
            text!
                .Split(
                    ['\r', '\n', ',', ';', ' ', '\t'],
                    StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
    }

    public static string FormatEditorText(IEnumerable<string>? pins)
        => string.Join(Environment.NewLine, NormalizePins(pins));

    public static ProviderAsnCatalogTlsPinSetDiff Diff(
        IEnumerable<string>? existing,
        IEnumerable<string>? proposed)
    {
        var before = NormalizePins(existing);
        var after = NormalizePins(proposed);
        var beforeSet = before.ToHashSet(StringComparer.Ordinal);
        var afterSet = after.ToHashSet(StringComparer.Ordinal);

        return new ProviderAsnCatalogTlsPinSetDiff
        {
            Existing = before,
            Proposed = after,
            Added = after.Where(x => !beforeSet.Contains(x)).ToArray(),
            Removed = before.Where(x => !afterSet.Contains(x)).ToArray(),
            Unchanged = before.Where(afterSet.Contains).ToArray(),
        };
    }

    public static string SerializePins(IEnumerable<string>? pins)
        => JsonUtils.Serialize(NormalizePins(pins), false);

    public static IReadOnlyList<string> DeserializePins(string? json)
    {
        if (json.IsNullOrEmpty())
        {
            return [];
        }

        try
        {
            return NormalizePins(JsonUtils.DeserializeStrict<List<string>>(json!));
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException)
        {
            throw new InvalidOperationException("Stored TLS SPKI pin list is invalid JSON.", ex);
        }
    }
}
