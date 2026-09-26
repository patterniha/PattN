using ServiceLib.Discovery.Models;
using ServiceLib.Models.Entities;

namespace ServiceLib.Discovery.Services;

public sealed class EndpointHistoryQueryService : IEndpointHistoryQueryService
{
    public async Task<EndpointHistoryDetail> GetAsync(
        DiscoveryCandidateRequest request,
        string address,
        TimeSpan? maxAge = null,
        int maxPoints = 50,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        var logicalHost = NormalizeHost(request.LogicalHost);
        var httpHost = NormalizeHost(string.IsNullOrWhiteSpace(request.HttpHost) ? request.LogicalHost : request.HttpHost);
        address = NormalizeAddress(address);
        if (logicalHost.IsNullOrEmpty())
        {
            throw new ArgumentException("Endpoint history requires a logical host.", nameof(request));
        }
        if (request.OriginalPort is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "Endpoint history port must be between 1 and 65535.");
        }
        if (!IPAddress.TryParse(address, out _))
        {
            throw new ArgumentException("Endpoint history requires a literal IP address.", nameof(address));
        }
        if (maxPoints is < 1 or > 500)
        {
            throw new ArgumentOutOfRangeException(nameof(maxPoints), "Endpoint history point limit must be between 1 and 500.");
        }

        var age = maxAge ?? TimeSpan.FromDays(30);
        if (age <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(maxAge));
        }

        var network = NormalizeToken(request.Network);
        var security = NormalizeToken(request.StreamSecurity);
        var cutoff = DateTimeOffset.UtcNow.Subtract(age).ToUnixTimeMilliseconds();

        var rows = await SQLiteHelper.Instance.TableAsync<EndpointObservationHistoryItem>()
            .Where(x => x.LogicalHost == logicalHost
                        && x.HttpHost == httpHost
                        && x.Port == request.OriginalPort
                        && x.Network == network
                        && x.StreamSecurity == security
                        && x.Address == address
                        && x.ObservedAtUnixMs >= cutoff)
            .ToListAsync();

        return BuildDetail(
            logicalHost,
            request.OriginalPort,
            network,
            security,
            address,
            rows,
            DateTimeOffset.UtcNow,
            maxPoints);
    }

    public static EndpointHistoryDetail BuildDetail(
        string logicalHost,
        int port,
        string network,
        string streamSecurity,
        string address,
        IReadOnlyList<EndpointObservationHistoryItem> rows,
        DateTimeOffset now,
        int maxPoints = 50)
    {
        ArgumentNullException.ThrowIfNull(rows);
        if (maxPoints is < 1 or > 500)
        {
            throw new ArgumentOutOfRangeException(nameof(maxPoints));
        }

        var ordered = rows
            .OrderByDescending(x => x.ObservedAtUnixMs)
            .Take(maxPoints)
            .ToArray();

        var points = ordered
            .Select(x => new EndpointHistoryPoint
            {
                ObservedAt = DateTimeOffset.FromUnixTimeMilliseconds(x.ObservedAtUnixMs),
                Qualified = x.Qualified,
                Attempts = x.Attempts,
                Successes = x.Successes,
                ConsecutiveSuccesses = x.ConsecutiveSuccesses,
                Reliability = Math.Clamp(x.Reliability, 0d, 1d),
                MedianLatencyMs = x.MedianLatencyMs,
                Source = x.Source,
                Provider = x.Provider,
                Asn = x.Asn,
                Pop = x.Pop,
                Errors = JsonUtils.Deserialize<List<string>>(x.ErrorsJson) ?? [],
            })
            .ToArray();

        EndpointHistorySummary? summary = ordered.Length == 0
            ? null
            : SqliteEndpointHistoryStore.Summarize(ordered, now);

        return new EndpointHistoryDetail
        {
            LogicalHost = logicalHost,
            Port = port,
            Network = network,
            StreamSecurity = streamSecurity,
            Address = address,
            Points = points,
            Summary = summary,
        };
    }

    private static string NormalizeHost(string? value)
        => (value ?? string.Empty).Trim().Trim('[', ']').TrimEnd('.').ToLowerInvariant();

    private static string NormalizeAddress(string? value)
        => DiscoveryEndpointAddress.NormalizeIfLiteral(value);

    private static string NormalizeToken(string? value)
        => (value ?? string.Empty).Trim().ToLowerInvariant();
}
