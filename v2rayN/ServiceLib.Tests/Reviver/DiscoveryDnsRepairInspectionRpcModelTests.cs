using ServiceLib.Discovery.Protocol;

namespace ServiceLib.Tests.Reviver;

public partial class DiscoveryRpcModelTests
{
    [Test]
    public async Task DnsRepairInspectionDto_ShouldPreserveFamilyFallbackAndCatalogEvidence()
    {
        var result = JsonSerializer.Deserialize<DiscoveryDnsRepairInspection>(
            """
            {
              "domain":"proxy.example",
              "ipv4":{
                "family":"ipv4",
                "queryType":1,
                "trace":{
                  "domain":"proxy.example",
                  "queryType":1,
                  "hops":[],
                  "finalAnswers":[{"name":"proxy.example","type":1,"ttl":60,"address":"203.0.113.7"}],
                  "complete":true
                },
                "dnssecAuthenticated":true,
                "dnssecStatus":"root-anchored-authenticated-answer",
                "fallbackUsed":false
              },
              "ipv6":{
                "family":"ipv6",
                "queryType":28,
                "trace":{
                  "domain":"proxy.example",
                  "queryType":28,
                  "hops":[],
                  "finalAnswers":[{"name":"proxy.example","type":28,"ttl":60,"address":"2001:db8::7"}],
                  "complete":true
                },
                "dnssecAuthenticated":false,
                "dnssecStatus":"validation-unavailable",
                "fallbackUsed":true,
                "error":"dnssec unavailable"
              },
              "resolverCatalogVersion":"2026-09-23",
              "resolverRecommendations":[
                {
                  "id":"cloudflare-standard",
                  "provider":"Cloudflare",
                  "name":"Cloudflare 1.1.1.1",
                  "ipv4":["1.1.1.1"],
                  "port":53,
                  "dotServerName":"one.one.one.one",
                  "dotPort":853,
                  "dohUrl":"https://cloudflare-dns.com/dns-query",
                  "dnssecValidating":true,
                  "policy":"neutral",
                  "referenceEligible":true,
                  "verifiedDate":"2026-09-23"
                }
              ]
            }
            """);

        await result.Should().NotBeNull();
        await result!.Domain.Should().BeEqualTo("proxy.example");
        await result.IPv4.DnssecAuthenticated.Should().BeTrue();
        await result.IPv4.Trace.FinalAnswers[0].Address.Should().BeEqualTo("203.0.113.7");
        await result.IPv6.FallbackUsed.Should().BeTrue();
        await result.IPv6.Trace.FinalAnswers[0].Address.Should().BeEqualTo("2001:db8::7");
        await result.ResolverCatalogVersion.Should().BeEqualTo("2026-09-23");
        await result.ResolverRecommendations[0].ReferenceEligible.Should().BeTrue();
    }
}
