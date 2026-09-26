using ServiceLib.Discovery.Protocol;

namespace ServiceLib.Tests.Reviver;

public partial class DiscoveryRpcModelTests
{
    [Test]
    public async Task DeepDnsRequest_ShouldSerializeBoundedTraceControls()
    {
        var request = new DiscoveryDeepDnsRequest
        {
            Domain = "example.com",
            QueryType = 28,
            TimeoutMs = 1500,
            MaxHops = 24,
            MaxNsDepth = 3,
            RootServers = ["192.0.2.1"],
        };

        var json = JsonSerializer.Serialize(request);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;

        await root.GetProperty("domain").GetString().Should().BeEqualTo("example.com");
        await root.GetProperty("queryType").GetInt32().Should().BeEqualTo(28);
        await root.GetProperty("maxHops").GetInt32().Should().BeEqualTo(24);
        await root.GetProperty("maxNsDepth").GetInt32().Should().BeEqualTo(3);
        await root.GetProperty("rootServers").GetArrayLength().Should().BeEqualTo(1);
    }

    [Test]
    public async Task DeepDnsTraceDto_ShouldPreserveDelegationAndHopEvidence()
    {
        var result = JsonSerializer.Deserialize<DiscoveryDnsTraceResult>(
            """
            {
              "domain":"www.example.com",
              "queryType":1,
              "hops":[{
                "nameServer":"192.0.2.1",
                "queryName":"www.example.com",
                "queryType":1,
                "transport":"udp",
                "latencyMs":12.5,
                "rcode":0,
                "authoritative":false,
                "truncated":false,
                "authorities":[{"name":"example.com","type":2,"ttl":60,"target":"ns1.external.net"}]
              }],
              "delegation":[{"name":"ns1.external.net","addresses":["192.0.2.53"]}],
              "aliasChain":[{
                "queryName":"www.example.com",
                "owner":"example.com",
                "target":"example.net",
                "resultName":"www.example.net",
                "type":39,
                "synthesized":true
              }],
              "finalAnswers":[{"name":"www.example.net","type":1,"ttl":60,"address":"203.0.113.9"}],
              "complete":true
            }
            """);

        await result.Should().NotBeNull();
        await result!.Complete.Should().BeTrue();
        await result.Delegation.Count.Should().BeEqualTo(1);
        await result.Delegation[0].Addresses[0].Should().BeEqualTo("192.0.2.53");
        await result.Hops[0].Authorities[0].Target.Should().BeEqualTo("ns1.external.net");
        await result.AliasChain.Count.Should().BeEqualTo(1);
        await result.AliasChain[0].Type.Should().BeEqualTo(39);
        await result.AliasChain[0].Synthesized.Should().BeTrue();
        await result.AliasChain[0].ResultName.Should().BeEqualTo("www.example.net");
        await result.FinalAnswers[0].Address.Should().BeEqualTo("203.0.113.9");
    }

    [Test]
    public async Task AuthorityComparisonDto_ShouldPreserveDisagreementGroups()
    {
        var result = JsonSerializer.Deserialize<DiscoveryDnsAuthorityComparison>(
            """
            {
              "domain":"example.com",
              "queryType":1,
              "delegation":[
                {"name":"ns1.example.com","addresses":["192.0.2.11"]},
                {"name":"ns2.example.com","addresses":["192.0.2.12"]},
                {"name":"ns3.example.com","addresses":["192.0.2.13"]}
              ],
              "observations":[
                {"authority":"ns1.example.com","address":"192.0.2.11","transport":"udp","rcode":0,"authoritative":true,"signature":"A"},
                {"authority":"ns2.example.com","address":"192.0.2.12","transport":"udp","rcode":0,"authoritative":true,"signature":"A"},
                {"authority":"ns3.example.com","address":"192.0.2.13","transport":"udp","rcode":0,"authoritative":true,"signature":"B"}
              ],
              "groups":[
                {"signature":"A","count":2,"endpoints":["ns1.example.com@192.0.2.11","ns2.example.com@192.0.2.12"]},
                {"signature":"B","count":1,"endpoints":["ns3.example.com@192.0.2.13"]}
              ],
              "responding":3,
              "unanimous":false,
              "divergent":true,
              "majorityCount":2,
              "majoritySignature":"A"
            }
            """);

        await result.Should().NotBeNull();
        await result!.Divergent.Should().BeTrue();
        await result.Unanimous.Should().BeFalse();
        await result.Responding.Should().BeEqualTo(3);
        await result.Groups.Count.Should().BeEqualTo(2);
        await result.MajorityCount.Should().BeEqualTo(2);
    }
}
