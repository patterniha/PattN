using ServiceLib.Discovery.Protocol;
using ServiceLib.Discovery.Services;
using ServiceLib.Reviver.Services;

namespace ServiceLib.Tests.Reviver;

public class DiscoveryDnsRepairEvidenceProviderTests
{
    [Test]
    public async Task Inspect_ShouldProjectCompositeFamilyEvidenceAndCatalog()
    {
        var provider = new DiscoveryDnsRepairEvidenceProvider(new FakeDnsClient());
        var result = await provider.InspectAsync("proxy.example.");

        await result.Host.Should().BeEqualTo("proxy.example");
        await result.IPv4.Addresses.Should().Contain("203.0.113.7");
        await result.IPv4.DnssecAuthenticated.Should().BeTrue();
        await result.IPv6.Addresses.Should().Contain("2001:db8::7");
        await result.IPv6.DnssecStatus.Should().BeEqualTo("validation-unavailable");
        await result.ResolverCatalogVersion.Should().BeEqualTo("2026-09-23");
        await result.ResolverRecommendations.Count.Should().BeEqualTo(2);
        await result.ResolverRecommendations[0].ReferenceEligible.Should().BeTrue();
        await result.ResolverRecommendations[1].Policy.Should().BeEqualTo("security-filtering");
    }

    private sealed class FakeDnsClient : IDiscoveryDnsDiagnosticClient
    {
        public Task<DiscoveryDnsRepairInspection> InspectDnsRepairAsync(
            DiscoveryDeepDnsRequest request,
            CancellationToken cancellationToken = default)
            => Task.FromResult(new DiscoveryDnsRepairInspection
            {
                Domain = request.Domain,
                IPv4 = new DiscoveryDnsRepairFamilyResult
                {
                    Family = "ipv4",
                    QueryType = 1,
                    DnssecAuthenticated = true,
                    DnssecStatus = "root-anchored-authenticated-answer",
                    Trace = new DiscoveryDnsTraceResult
                    {
                        Domain = request.Domain,
                        QueryType = 1,
                        Complete = true,
                        FinalAnswers =
                        [
                            new DiscoveryDnsRecord
                            {
                                Name = request.Domain,
                                Type = 1,
                                Address = "203.0.113.7",
                            }
                        ],
                    },
                },
                IPv6 = new DiscoveryDnsRepairFamilyResult
                {
                    Family = "ipv6",
                    QueryType = 28,
                    FallbackUsed = true,
                    DnssecStatus = "validation-unavailable",
                    Trace = new DiscoveryDnsTraceResult
                    {
                        Domain = request.Domain,
                        QueryType = 28,
                        Complete = true,
                        FinalAnswers =
                        [
                            new DiscoveryDnsRecord
                            {
                                Name = request.Domain,
                                Type = 28,
                                Address = "2001:db8::7",
                            }
                        ],
                    },
                },
                ResolverCatalogVersion = "2026-09-23",
                ResolverRecommendations =
                [
                    new DiscoveryResolverCatalogIdentity
                    {
                        Id = "quad9-secure",
                        Provider = "Quad9",
                        Name = "Quad9 Secure",
                        IPv4 = ["9.9.9.9"],
                        DotServerName = "dns.quad9.net",
                        DohUrl = "https://dns.quad9.net/dns-query",
                        Policy = "security-filtering",
                        ReferenceEligible = false,
                    },
                    new DiscoveryResolverCatalogIdentity
                    {
                        Id = "cloudflare-standard",
                        Provider = "Cloudflare",
                        Name = "Cloudflare 1.1.1.1",
                        IPv4 = ["1.1.1.1"],
                        DotServerName = "one.one.one.one",
                        DohUrl = "https://cloudflare-dns.com/dns-query",
                        Policy = "neutral",
                        ReferenceEligible = true,
                    },
                ],
            });
    }
}
