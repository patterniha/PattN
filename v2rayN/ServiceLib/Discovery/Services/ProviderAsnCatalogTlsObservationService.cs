using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using ServiceLib.Discovery.Models;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Performs an explicit ordinary HTTPS connection and reports the leaf certificate SPKI SHA-256.
/// Normal platform TLS validation remains authoritative. Observation uses the same public-destination,
/// direct-connect/no-proxy and same-authority redirect boundaries as production remote-catalog fetches;
/// it never accepts an invalid certificate and never mutates the configured trusted pin set.
/// </summary>
public sealed class ProviderAsnCatalogTlsObservationService
{
    private const int MaximumRedirects = 5;
    private readonly TimeSpan _timeout;

    public ProviderAsnCatalogTlsObservationService(TimeSpan? timeout = null)
    {
        _timeout = timeout ?? TimeSpan.FromSeconds(15);
        if (_timeout <= TimeSpan.Zero || _timeout > TimeSpan.FromMinutes(2))
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }
    }

    public async Task<ProviderAsnCatalogTlsObservation> ObserveAsync(
        string uriText,
        CancellationToken cancellationToken = default)
    {
        var uri = ValidateHttpsUri(uriText);
        ProviderAsnCatalogTlsObservation? observed = null;

        using var handler = CreateRestrictedHandler(certificate =>
        {
            observed = CreateObservation(
                uri,
                uri,
                0,
                certificate,
                DateTimeOffset.UtcNow);
        });
        using var client = new HttpClient(handler, disposeHandler: true)
        {
            Timeout = _timeout,
        };

        var currentUri = uri;
        for (var redirects = 0; ; redirects++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, currentUri);
            using var response = await client.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken);

            var effectiveUri = response.RequestMessage?.RequestUri ?? currentUri;
            ValidateHttpsUri(effectiveUri.AbsoluteUri);
            EnsureSameAuthority(uri, effectiveUri);

            if (!IsRedirect(response.StatusCode))
            {
                if (observed is null)
                {
                    throw new InvalidOperationException(
                        "HTTPS completed without observable validated certificate evidence.");
                }

                return observed with
                {
                    FinalUri = effectiveUri.AbsoluteUri,
                    Host = effectiveUri.Host,
                    HttpStatusCode = (int)response.StatusCode,
                };
            }

            if (redirects >= MaximumRedirects)
            {
                throw new InvalidOperationException(
                    $"TLS observation exceeded {MaximumRedirects} redirects.");
            }

            var location = response.Headers.Location
                ?? throw new InvalidOperationException(
                    "TLS observation received a redirect without a Location header.");
            var nextUri = location.IsAbsoluteUri
                ? location
                : new Uri(effectiveUri, location);

            ValidateHttpsUri(nextUri.AbsoluteUri);
            EnsureSameAuthority(uri, nextUri);
            currentUri = nextUri;
        }
    }

    internal static SocketsHttpHandler CreateRestrictedHandler(
        Action<X509Certificate2> observeValidatedCertificate)
    {
        ArgumentNullException.ThrowIfNull(observeValidatedCertificate);
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            ConnectCallback = HttpProviderAsnCatalogRemoteTransport.ConnectPublicEndpointAsync,
        };
        handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
        {
            if (errors != SslPolicyErrors.None || certificate is null)
            {
                return false;
            }

            if (certificate is X509Certificate2 certificate2)
            {
                observeValidatedCertificate(certificate2);
            }
            else
            {
                using var copy = new X509Certificate2(certificate);
                observeValidatedCertificate(copy);
            }
            return true;
        };
        return handler;
    }

    public static bool CanUseObservedPinForSource(
        ProviderAsnCatalogTlsObservation observation,
        string sourceUriText,
        out string reason)
    {
        ArgumentNullException.ThrowIfNull(observation);
        Uri sourceUri;
        try
        {
            sourceUri = ValidateHttpsUri(sourceUriText);
        }
        catch (Exception ex)
        {
            reason = ex.Message;
            return false;
        }

        if (!Uri.TryCreate(observation.RequestedUri, UriKind.Absolute, out var requested)
            || !Uri.TryCreate(observation.FinalUri, UriKind.Absolute, out var final))
        {
            reason = "Observed TLS evidence contains invalid request/final URI metadata.";
            return false;
        }

        if (!SameAuthority(sourceUri, requested))
        {
            reason = "The remote catalog HTTPS authority changed after this SPKI was observed. Inspect again.";
            return false;
        }
        if (!SameAuthority(requested, final))
        {
            reason =
                "The HTTPS request followed a cross-host/port redirect. A single final-server pin is not sufficient for transport pinning of every TLS hop; use a stable direct HTTPS source or enter reviewed pins manually.";
            return false;
        }

        reason = string.Empty;
        return true;
    }

    public static ProviderAsnCatalogTlsObservation CreateObservation(
        Uri requestedUri,
        Uri certificateUri,
        int httpStatusCode,
        X509Certificate2 certificate,
        DateTimeOffset observedAt)
    {
        ArgumentNullException.ThrowIfNull(requestedUri);
        ArgumentNullException.ThrowIfNull(certificateUri);
        ArgumentNullException.ThrowIfNull(certificate);
        if (!string.Equals(requestedUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(certificateUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("TLS observation URIs must use HTTPS.");
        }

        return new ProviderAsnCatalogTlsObservation
        {
            RequestedUri = requestedUri.AbsoluteUri,
            FinalUri = certificateUri.AbsoluteUri,
            HttpStatusCode = httpStatusCode,
            Host = certificateUri.Host,
            SpkiSha256 = ProviderAsnCatalogTransportPinning.ComputeSpkiSha256(certificate),
            Subject = certificate.Subject,
            Issuer = certificate.Issuer,
            NotBefore = new DateTimeOffset(certificate.NotBefore.ToUniversalTime()),
            NotAfter = new DateTimeOffset(certificate.NotAfter.ToUniversalTime()),
            ObservedAt = observedAt,
        };
    }

    private static bool IsRedirect(HttpStatusCode statusCode)
        => statusCode is HttpStatusCode.MovedPermanently
            or HttpStatusCode.Found
            or HttpStatusCode.SeeOther
            or HttpStatusCode.TemporaryRedirect
            or HttpStatusCode.PermanentRedirect;

    private static void EnsureSameAuthority(Uri configured, Uri actual)
    {
        if (!SameAuthority(configured, actual))
        {
            throw new InvalidOperationException(
                $"TLS observation refused a cross-authority redirect from '{configured.Authority}' to '{actual.Authority}'.");
        }
    }

    private static bool SameAuthority(Uri left, Uri right)
        => string.Equals(left.Scheme, right.Scheme, StringComparison.OrdinalIgnoreCase)
           && string.Equals(left.IdnHost, right.IdnHost, StringComparison.OrdinalIgnoreCase)
           && left.Port == right.Port;

    private static Uri ValidateHttpsUri(string value)
    {
        if (!Uri.TryCreate(value?.Trim(), UriKind.Absolute, out var uri)
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || uri.Host.IsNullOrEmpty()
            || !uri.UserInfo.IsNullOrEmpty()
            || !uri.Fragment.IsNullOrEmpty())
        {
            throw new ArgumentException(
                "TLS observation requires an absolute HTTPS URI without credentials or fragments.",
                nameof(value));
        }
        return uri;
    }
}
