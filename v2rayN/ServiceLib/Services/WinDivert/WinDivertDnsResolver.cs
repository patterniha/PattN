using System.Net;
using System.Net.Http.Headers;

namespace ServiceLib.Services.WinDivert;

/// <summary>
/// Resolves dns queries with "dns over https" through the local proxy inbound.
/// <para>
/// The queries are sent to the dns-over-https server through the running core, so the
/// resolution is not poisoned and does not leak the requested domains.
/// </para>
/// </summary>
public class WinDivertDnsResolver : IDisposable
{
    private const string DefaultPrimaryDoh = "https://1.1.1.1/dns-query";
    private const string DefaultFallbackDoh = "https://8.8.8.8/dns-query";

    private readonly string _primaryDohUrl;
    private readonly string _fallbackDohUrl;
    private HttpClient? _httpClient;
    private int _proxyPort;

    public WinDivertDnsResolver(string? dohUrl)
    {
        // Prefer direct IP addresses to avoid chicken-and-egg bootstrap DNS lookups
        _primaryDohUrl = string.IsNullOrWhiteSpace(dohUrl) || dohUrl.Contains("cloudflare-dns.com")
            ? DefaultPrimaryDoh
            : dohUrl;
        _fallbackDohUrl = DefaultFallbackDoh;
    }

    /// <summary>
    /// Sends the raw dns query to the dns-over-https server and returns the raw dns answer.
    /// </summary>
    /// <param name="query">Raw dns query (wire format).</param>
    /// <param name="socksPort">Local socks/mixed port of the running core.</param>
    /// <param name="token">Cancellation token.</param>
    /// <returns>The raw dns response or null when the query could not be answered.</returns>
    public async Task<byte[]?> ResolveAsync(byte[] query, int socksPort, CancellationToken token)
    {
        if (query.Length < 12)
        {
            return null;
        }

        // Try primary DoH first (e.g. 1.1.1.1)
        var result = await QueryDohAsync(_primaryDohUrl, query, socksPort, token);
        if (result != null)
        {
            return result;
        }

        // Fallback to secondary DoH (e.g. 8.8.8.8) if primary fails
        if (!string.Equals(_primaryDohUrl, _fallbackDohUrl, StringComparison.OrdinalIgnoreCase))
        {
            result = await QueryDohAsync(_fallbackDohUrl, query, socksPort, token);
            if (result != null)
            {
                return result;
            }
        }

        return null;
    }

    private async Task<byte[]?> QueryDohAsync(string url, byte[] query, int socksPort, CancellationToken token)
    {
        try
        {
            var client = GetClient(socksPort);
            using var content = new ByteArrayContent(query);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
            cts.CancelAfter(TimeSpan.FromSeconds(5));

            using var response = await client.PostAsync(url, content, cts.Token);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            var bytes = await response.Content.ReadAsByteArrayAsync(cts.Token);
            if (bytes.Length < 12)
            {
                return null;
            }

            // Some resolvers answer with a zeroed transaction id, restore the original one.
            bytes[0] = query[0];
            bytes[1] = query[1];

            return bytes;
        }
        catch (Exception ex)
        {
            Logging.SaveLog("WinDivertDnsResolver", ex);
            return null;
        }
    }

    private HttpClient GetClient(int socksPort)
    {
        if (_httpClient != null && _proxyPort == socksPort)
        {
            return _httpClient;
        }

        _httpClient?.Dispose();

        var handler = new SocketsHttpHandler
        {
            UseProxy = true,
            Proxy = new WebProxy(new Uri($"socks5://{IPAddress.Loopback}:{socksPort}")),
            ConnectTimeout = TimeSpan.FromSeconds(4),
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        };

        _httpClient = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(7),
        };
        _proxyPort = socksPort;

        return _httpClient;
    }

    public void Dispose()
    {
        _httpClient?.Dispose();
        _httpClient = null;
    }
}
