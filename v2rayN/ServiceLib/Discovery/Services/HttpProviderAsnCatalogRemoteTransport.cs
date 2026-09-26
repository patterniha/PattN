using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using ServiceLib.Discovery.Models;

namespace ServiceLib.Discovery.Services;

public sealed class HttpProviderAsnCatalogRemoteTransport : IProviderAsnCatalogRemoteTransport
{
    private const int MaximumRedirects = 5;
    private static readonly HttpClient SharedClient = CreateDefaultClient();
    private readonly HttpClient _client;

    public HttpProviderAsnCatalogRemoteTransport()
    {
        _client = SharedClient;
    }

    /// <summary>
    /// Test-only transport seam. Production callers cannot replace the restricted
    /// SocketsHttpHandler and therefore cannot bypass destination classification,
    /// direct-connect/no-proxy policy, TLS hostname validation, or redirect policy.
    /// </summary>
    internal HttpProviderAsnCatalogRemoteTransport(HttpClient client)
    {
        ArgumentNullException.ThrowIfNull(client);
        _client = client;
    }

    public async Task<ProviderAsnCatalogRemoteTransportResponse> FetchAsync(
        ProviderAsnCatalogRemoteTransportRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateHttps(request.Uri);
        if (request.MaximumBytes is < 1 or > ProviderAsnEndpointCatalogDocument.MaximumDocumentBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(request.MaximumBytes));
        }

        var pins = ProviderAsnCatalogTransportPinning.NormalizePins(request.TlsSpkiPinsSha256);
        using var pinnedClient = pins.Count > 0 ? CreatePinnedClient(pins) : null;
        var client = pinnedClient ?? _client;

        using var response = await SendWithRedirectPolicyAsync(client, request, cancellationToken);
        var finalUri = response.RequestMessage?.RequestUri ?? request.Uri;
        ValidateHttps(finalUri);
        EnsureSameAuthority(request.Uri, finalUri);

        if (response.StatusCode == HttpStatusCode.NotModified)
        {
            return new ProviderAsnCatalogRemoteTransportResponse
            {
                StatusCode = (int)response.StatusCode,
                FinalUri = finalUri,
                ETag = response.Headers.ETag?.ToString() ?? request.ETag,
                LastModified = response.Content.Headers.LastModified ?? request.LastModified,
            };
        }

        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"Provider catalog fetch failed with HTTP {(int)response.StatusCode} {response.ReasonPhrase}.",
                null,
                response.StatusCode);
        }

        if (response.Content.Headers.ContentLength is long length
            && length > request.MaximumBytes)
        {
            throw new InvalidOperationException(
                $"Provider catalog response exceeds the {request.MaximumBytes}-byte limit.");
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var memory = new MemoryStream();
        var buffer = new byte[64 * 1024];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken);
            if (read == 0)
            {
                break;
            }
            if (memory.Length + read > request.MaximumBytes)
            {
                throw new InvalidOperationException(
                    $"Provider catalog response exceeds the {request.MaximumBytes}-byte limit.");
            }
            await memory.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }

        return new ProviderAsnCatalogRemoteTransportResponse
        {
            StatusCode = (int)response.StatusCode,
            FinalUri = finalUri,
            Bytes = memory.ToArray(),
            ETag = response.Headers.ETag?.ToString() ?? string.Empty,
            LastModified = response.Content.Headers.LastModified,
        };
    }

    private static async Task<HttpResponseMessage> SendWithRedirectPolicyAsync(
        HttpClient client,
        ProviderAsnCatalogRemoteTransportRequest request,
        CancellationToken cancellationToken)
    {
        var currentUri = request.Uri;
        for (var redirects = 0; ; redirects++)
        {
            using var message = CreateRequestMessage(request, currentUri);
            var response = await client.SendAsync(
                message,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken);

            var effectiveUri = response.RequestMessage?.RequestUri ?? currentUri;
            try
            {
                ValidateHttps(effectiveUri);
                EnsureSameAuthority(request.Uri, effectiveUri);
            }
            catch
            {
                response.Dispose();
                throw;
            }

            if (!IsRedirect(response.StatusCode))
            {
                return response;
            }

            if (redirects >= MaximumRedirects)
            {
                response.Dispose();
                throw new InvalidOperationException(
                    $"Provider catalog remote fetch exceeded {MaximumRedirects} redirects.");
            }

            var location = response.Headers.Location;
            if (location is null)
            {
                response.Dispose();
                throw new InvalidOperationException(
                    "Provider catalog remote fetch returned a redirect without a Location header.");
            }

            var nextUri = location.IsAbsoluteUri
                ? location
                : new Uri(effectiveUri, location);
            try
            {
                ValidateHttps(nextUri);
                EnsureSameAuthority(request.Uri, nextUri);
            }
            catch
            {
                response.Dispose();
                throw;
            }

            response.Dispose();
            currentUri = nextUri;
        }
    }

    private static HttpRequestMessage CreateRequestMessage(
        ProviderAsnCatalogRemoteTransportRequest request,
        Uri uri)
    {
        var message = new HttpRequestMessage(HttpMethod.Get, uri);
        if (!request.Conditional)
        {
            return message;
        }

        if (!request.ETag.IsNullOrEmpty())
        {
            message.Headers.TryAddWithoutValidation("If-None-Match", request.ETag);
        }
        if (request.LastModified is not null)
        {
            message.Headers.IfModifiedSince = request.LastModified;
        }
        return message;
    }

    private static bool IsRedirect(HttpStatusCode statusCode)
        => statusCode is HttpStatusCode.MovedPermanently
            or HttpStatusCode.Found
            or HttpStatusCode.SeeOther
            or HttpStatusCode.TemporaryRedirect
            or HttpStatusCode.PermanentRedirect;

    private static HttpClient CreateDefaultClient()
        => new(CreateRestrictedHandler(), disposeHandler: true);

    private static HttpClient CreatePinnedClient(IReadOnlyList<string> pins)
        => new(CreateRestrictedHandler(pins), disposeHandler: true);

    private static SocketsHttpHandler CreateRestrictedHandler(IReadOnlyList<string>? pins = null)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            // A remote catalog is a reviewed HTTPS trust source, not a generic
            // user-browsing request. Ambient OS/user proxies would introduce a
            // second destination and certificate authority that is not represented
            // by the catalog's source/pin provenance, so production fetches go direct.
            UseProxy = false,
            ConnectCallback = ConnectPublicEndpointAsync,
        };

        if (pins is not null && pins.Count > 0)
        {
            handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
                IsPinnedCertificateAccepted(certificate, errors, pins);
        }
        return handler;
    }

    internal static async ValueTask<Stream> ConnectPublicEndpointAsync(
        SocketsHttpConnectionContext context,
        CancellationToken cancellationToken)
    {
        var endpoint = context.DnsEndPoint;
        var addresses = await ProviderAsnCatalogRemoteDestinationPolicy.ResolveAllowedAsync(
            endpoint.Host,
            cancellationToken);

        Exception? lastError = null;
        foreach (var address in addresses)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Socket? socket = null;
            try
            {
                socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
                {
                    NoDelay = true,
                };
                await socket.ConnectAsync(
                    new IPEndPoint(address, endpoint.Port),
                    cancellationToken);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                socket?.Dispose();
                throw;
            }
            catch (Exception ex)
            {
                socket?.Dispose();
                lastError = ex;
            }
        }

        throw new HttpRequestException(
            $"Could not connect to an allowed public address for remote catalog host '{endpoint.Host}'.",
            lastError);
    }

    private static bool IsPinnedCertificateAccepted(
        X509Certificate? certificate,
        SslPolicyErrors errors,
        IReadOnlyList<string> pins)
    {
        if (certificate is null)
        {
            return false;
        }
        if (certificate is X509Certificate2 certificate2)
        {
            return ProviderAsnCatalogTransportPinning.IsCertificateAccepted(certificate2, errors, pins);
        }

        using var copy = new X509Certificate2(certificate);
        return ProviderAsnCatalogTransportPinning.IsCertificateAccepted(copy, errors, pins);
    }

    private static void EnsureSameAuthority(Uri configured, Uri actual)
    {
        if (!string.Equals(configured.IdnHost, actual.IdnHost, StringComparison.OrdinalIgnoreCase)
            || configured.Port != actual.Port)
        {
            throw new InvalidOperationException(
                $"Provider catalog remote fetch refused a cross-authority redirect from '{configured.Authority}' to '{actual.Authority}'. " +
                "Configure the destination authority explicitly so its TLS/pinning/provenance policy is reviewable.");
        }
    }

    private static void ValidateHttps(Uri uri)
    {
        if (!uri.IsAbsoluteUri || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Provider catalog remote fetch requires HTTPS.");
        }
    }
}
