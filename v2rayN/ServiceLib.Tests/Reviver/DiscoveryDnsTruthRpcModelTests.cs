using ServiceLib.Discovery.Protocol;

namespace ServiceLib.Tests.Reviver;

public partial class DiscoveryRpcModelTests
{
    [Test]
    public async Task DnsConsensusRequest_ShouldKeepTrustedAndCandidateResolversSeparate()
    {
        var request = new DiscoveryDnsConsensusRequest
        {
            Domain = "example.com",
            QueryType = 1,
            UseDefaultTrustedResolvers = false,
            TrustedResolvers =
            [
                new DiscoveryDnsResolverEndpoint { Name = "trusted", Address = "192.0.2.10", Port = 53 }
            ],
            CandidateResolvers =
            [
                new DiscoveryDnsResolverEndpoint { Name = "candidate", Address = "192.0.2.20", Port = 53 }
            ],
        };

        var json = JsonSerializer.Serialize(request);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;

        await root.GetProperty("useDefaultTrustedResolvers").GetBoolean().Should().BeFalse();
        await root.GetProperty("trustedResolvers").GetArrayLength().Should().BeEqualTo(1);
        await root.GetProperty("candidateResolvers").GetArrayLength().Should().BeEqualTo(1);
    }

    [Test]
    public async Task DnsConsensusDto_ShouldPreserveAuthorityBaselineAndCandidateAssessment()
    {
        var result = JsonSerializer.Deserialize<DiscoveryDnsConsensusComparison>(
            """
            {
              "domain":"example.com",
              "queryType":1,
              "authority":{
                "domain":"example.com",
                "queryType":1,
                "observations":[],
                "groups":[],
                "responding":2,
                "unanimous":true,
                "divergent":false,
                "majorityCount":2,
                "majoritySignature":"rcode=0;example.com|1|1|203.0.113.7"
              },
              "resolvers":[{
                "name":"candidate",
                "address":"192.0.2.20",
                "port":53,
                "kind":"candidate-resolver",
                "transport":"udp",
                "rcode":0,
                "signature":"rcode=0;example.com|1|1|203.0.113.8"
              }],
              "consensus":{
                "evidenceCount":3,
                "validEvidenceCount":3,
                "groups":[],
                "dominantSignature":"rcode=0;example.com|1|1|203.0.113.7",
                "dominantCount":2,
                "unanimous":false,
                "divergent":true
              },
              "authorityReferenceSignature":"rcode=0;example.com|1|1|203.0.113.7",
              "authorityReferenceDefinitive":true,
              "candidates":[{
                "source":"candidate",
                "signature":"rcode=0;example.com|1|1|203.0.113.8",
                "authorityReference":"rcode=0;example.com|1|1|203.0.113.7",
                "status":"differs-authority"
              }]
            }
            """);

        await result.Should().NotBeNull();
        await result!.AuthorityReferenceDefinitive.Should().BeTrue();
        await result.Candidates.Count.Should().BeEqualTo(1);
        await result.Candidates[0].Status.Should().BeEqualTo("differs-authority");
        await result.Consensus.Divergent.Should().BeTrue();
    }

    [Test]
    public async Task DnssecInspectionDto_ShouldNotOverstateDsKeyMatchAsFullValidation()
    {
        var result = JsonSerializer.Deserialize<DiscoveryDnssecInspection>(
            """
            {
              "zone":"example.com",
              "ds":{"domain":"example.com","queryType":43,"hops":[],"complete":true},
              "dnskey":{"domain":"example.com","queryType":48,"hops":[],"complete":true},
              "validation":{
                "zone":"example.com",
                "dsCount":1,
                "dnskeyCount":1,
                "supportedDsCount":1,
                "matches":[{
                  "ds":{"keyTag":1234,"algorithm":8,"digestType":2,"digest":"abcd"},
                  "dnskey":{"flags":257,"protocol":3,"algorithm":8,"publicKey":"AQID","keyTag":1234}
                }],
                "status":"ds-key-match"
              }
            }
            """);

        await result.Should().NotBeNull();
        await result!.Validation.Status.Should().BeEqualTo("ds-key-match");
        await result.Validation.Matches.Count.Should().BeEqualTo(1);
    }
}
