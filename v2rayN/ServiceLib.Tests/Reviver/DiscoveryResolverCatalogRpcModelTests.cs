using ServiceLib.Discovery.Protocol;

namespace ServiceLib.Tests.Reviver;

public partial class DiscoveryRpcModelTests
{
    [Test]
    public async Task ResolverCatalogDto_ShouldPreserveIdentityPolicyAndVerificationMetadata()
    {
        var catalog = JsonSerializer.Deserialize<DiscoveryResolverCatalog>(
            """
            {
              "version":"2026-09-23",
              "resolvers":[
                {
                  "id":"cloudflare-standard",
                  "provider":"Cloudflare",
                  "name":"Cloudflare 1.1.1.1",
                  "ipv4":["1.1.1.1","1.0.0.1"],
                  "ipv6":["2606:4700:4700::1111"],
                  "port":53,
                  "dotServerName":"one.one.one.one",
                  "dotPort":853,
                  "dohUrl":"https://cloudflare-dns.com/dns-query",
                  "dnssecValidating":true,
                  "policy":"neutral",
                  "referenceEligible":true,
                  "sourceUrls":["https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-tls/"],
                  "verifiedDate":"2026-09-23"
                },
                {
                  "id":"quad9-secure",
                  "provider":"Quad9",
                  "name":"Quad9 Secure",
                  "ipv4":["9.9.9.9"],
                  "port":53,
                  "dotServerName":"dns.quad9.net",
                  "dotPort":853,
                  "dohUrl":"https://dns.quad9.net/dns-query",
                  "dnssecValidating":true,
                  "policy":"security-filtering",
                  "referenceEligible":false,
                  "sourceUrls":["https://docs.quad9.net/services/"],
                  "verifiedDate":"2026-09-23"
                }
              ],
              "referenceEligible":[
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

        await catalog.Should().NotBeNull();
        await catalog!.Version.Should().BeEqualTo("2026-09-23");
        await catalog.Resolvers.Count.Should().BeEqualTo(2);
        await catalog.ReferenceEligible.Count.Should().BeEqualTo(1);
        await catalog.Resolvers[0].DotServerName.Should().BeEqualTo("one.one.one.one");
        await catalog.Resolvers[1].Policy.Should().BeEqualTo("security-filtering");
        await catalog.Resolvers[1].ReferenceEligible.Should().BeFalse();
    }

    [Test]
    public async Task ConsensusDto_ShouldSeparateAllEvidenceFromReferenceEligibleEvidence()
    {
        var result = JsonSerializer.Deserialize<DiscoveryDnsConsensusComparison>(
            """
            {
              "domain":"example.com",
              "queryType":1,
              "authority":{"domain":"example.com","queryType":1,"observations":[],"responding":1,"unanimous":true,"divergent":false,"majorityCount":1,"majoritySignature":"A"},
              "resolvers":[
                {"name":"Cloudflare","address":"1.1.1.1","port":53,"kind":"trusted-resolver","catalogId":"cloudflare-standard","policy":"neutral","referenceEligible":true,"signature":"A"},
                {"name":"Quad9","address":"9.9.9.9","port":53,"kind":"trusted-resolver","catalogId":"quad9-secure","policy":"security-filtering","referenceEligible":false,"signature":"B"}
              ],
              "consensus":{"evidenceCount":3,"validEvidenceCount":3,"groups":[{"signature":"A","count":2,"authoritativeCount":1,"sources":["auth","Cloudflare"]},{"signature":"B","count":1,"authoritativeCount":0,"sources":["Quad9"]}],"dominantSignature":"A","dominantCount":2,"unanimous":false,"divergent":true},
              "referenceConsensus":{"evidenceCount":2,"validEvidenceCount":2,"groups":[{"signature":"A","count":2,"authoritativeCount":1,"sources":["auth","Cloudflare"]}],"dominantSignature":"A","dominantCount":2,"unanimous":true,"divergent":false},
              "authorityReferenceSignature":"A",
              "authorityReferenceDefinitive":true,
              "dnssecReferenceDefinitive":false,
              "candidates":[]
            }
            """);

        await result.Should().NotBeNull();
        await result!.Consensus.Divergent.Should().BeTrue();
        await result.ReferenceConsensus.Unanimous.Should().BeTrue();
        await result.Resolvers[1].ReferenceEligible.Should().BeFalse();
        await result.Resolvers[1].CatalogId.Should().BeEqualTo("quad9-secure");
    }

    [Test]
    public async Task ResolverEndpoint_ShouldSerializeCatalogPolicyMetadata()
    {
        var endpoint = new DiscoveryDnsResolverEndpoint
        {
            Name = "Quad9",
            Address = "9.9.9.9",
            CatalogId = "quad9-secure",
            Policy = "security-filtering",
            ServerName = "dns.quad9.net",
            DohUrl = "https://dns.quad9.net/dns-query",
        };

        using var json = JsonDocument.Parse(JsonSerializer.Serialize(endpoint));
        await json.RootElement.GetProperty("catalogId").GetString().Should().BeEqualTo("quad9-secure");
        await json.RootElement.GetProperty("policy").GetString().Should().BeEqualTo("security-filtering");
    }
}
