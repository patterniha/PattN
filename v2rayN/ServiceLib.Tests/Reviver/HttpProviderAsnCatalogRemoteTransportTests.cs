using System.Net;
using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;

namespace ServiceLib.Tests.Reviver;

public class HttpProviderAsnCatalogRemoteTransportTests
{
    [Test]
    public async Task ProductionTransport_ShouldExposeOnlyRestrictedPublicConstructor()
    {
        var publicConstructors = typeof(HttpProviderAsnCatalogRemoteTransport)
            .GetConstructors(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance);

        await publicConstructors.Length.Should().BeEqualTo(1);
        await publicConstructors[0].GetParameters().Length.Should().BeEqualTo(0);
    }

    [Test]
    public async Task Fetch_ShouldFollowBoundedSameAuthorityHttpsRedirect()
    {
        var handler = new RecordingHandler((request, call) =>
        {
            if (call == 1)
            {
                var redirect = new HttpResponseMessage(HttpStatusCode.Found)
                {
                    RequestMessage = request,
                };
                redirect.Headers.Location = new Uri("/catalog-v2.json", UriKind.Relative);
                return redirect;
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                RequestMessage = request,
                Content = new ByteArrayContent([1, 2, 3]),
            };
        });
        using var client = new HttpClient(handler);
        var transport = new HttpProviderAsnCatalogRemoteTransport(client);

        var result = await transport.FetchAsync(new ProviderAsnCatalogRemoteTransportRequest
        {
            Uri = new Uri("https://catalog.example/catalog.json"),
            Conditional = false,
        });

        await handler.Requests.Count.Should().BeEqualTo(2);
        await handler.Requests[0].AbsoluteUri.Should().BeEqualTo("https://catalog.example/catalog.json");
        await handler.Requests[1].AbsoluteUri.Should().BeEqualTo("https://catalog.example/catalog-v2.json");
        await result.FinalUri.AbsoluteUri.Should().BeEqualTo("https://catalog.example/catalog-v2.json");
        await result.Bytes.SequenceEqual(new byte[] { 1, 2, 3 }).Should().BeTrue();
    }

    [Test]
    public async Task Fetch_ShouldRejectCrossAuthorityRedirectBeforeSecondRequest()
    {
        var handler = new RecordingHandler((request, _) =>
        {
            var redirect = new HttpResponseMessage(HttpStatusCode.Found)
            {
                RequestMessage = request,
            };
            redirect.Headers.Location = new Uri("https://other.example/catalog.json");
            return redirect;
        });
        using var client = new HttpClient(handler);
        var transport = new HttpProviderAsnCatalogRemoteTransport(client);

        var threw = false;
        try
        {
            await transport.FetchAsync(new ProviderAsnCatalogRemoteTransportRequest
            {
                Uri = new Uri("https://catalog.example/catalog.json"),
                Conditional = false,
            });
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.Message.Contains("cross-authority", StringComparison.OrdinalIgnoreCase);
        }

        await threw.Should().BeTrue();
        await handler.Requests.Count.Should().BeEqualTo(1);
    }

    [Test]
    public async Task Fetch_ShouldRejectHttpsDowngradeRedirectBeforeSecondRequest()
    {
        var handler = new RecordingHandler((request, _) =>
        {
            var redirect = new HttpResponseMessage(HttpStatusCode.MovedPermanently)
            {
                RequestMessage = request,
            };
            redirect.Headers.Location = new Uri("http://catalog.example/catalog.json");
            return redirect;
        });
        using var client = new HttpClient(handler);
        var transport = new HttpProviderAsnCatalogRemoteTransport(client);

        var threw = false;
        try
        {
            await transport.FetchAsync(new ProviderAsnCatalogRemoteTransportRequest
            {
                Uri = new Uri("https://catalog.example/catalog.json"),
                Conditional = false,
            });
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.Message.Contains("requires HTTPS", StringComparison.OrdinalIgnoreCase);
        }

        await threw.Should().BeTrue();
        await handler.Requests.Count.Should().BeEqualTo(1);
    }

    private sealed class RecordingHandler(Func<HttpRequestMessage, int, HttpResponseMessage> respond)
        : HttpMessageHandler
    {
        private int _calls;

        public List<Uri> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Requests.Add(request.RequestUri!);
            var call = Interlocked.Increment(ref _calls);
            return Task.FromResult(respond(request, call));
        }
    }
}
