using ServiceLib.Discovery.Protocol;

namespace ServiceLib.Tests.Reviver;

public partial class DiscoveryRpcModelTests
{
    [Test]
    public async Task ResolverProfileRequest_ShouldSerializeQuorumControls()
    {
        var request = new DiscoveryResolverProfileRequest
        {
            Address = "192.0.2.53",
            Domain = "example.com",
            Attempts = 5,
            MinSuccesses = 3,
            CheckDot = true,
            ServerName = "dns.example.net",
        };

        var json = JsonSerializer.Serialize(request);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;

        await root.GetProperty("attempts").GetInt32().Should().BeEqualTo(5);
        await root.GetProperty("minSuccesses").GetInt32().Should().BeEqualTo(3);
    }

    [Test]
    public async Task ResolverProfileDto_ShouldPreserveQuorumSamplesAndProtocolEvidence()
    {
        var result = JsonSerializer.Deserialize<DiscoveryResolverProfileResult>(
            """
            {
              "address":"192.0.2.53",
              "domain":"example.com",
              "udp":{
                "transport":"udp",
                "attempted":true,
                "responded":true,
                "attempts":3,
                "successes":2,
                "quorumMet":true,
                "reliability":0.6666666667,
                "medianLatencyMs":18,
                "latencyMs":20,
                "rcode":0,
                "answerCount":1,
                "answerSignature":"rcode=0;example.com|1|1|203.0.113.7",
                "samples":[
                  {"responded":true,"latencyMs":16,"rcode":0,"answerSignature":"rcode=0;example.com|1|1|203.0.113.7"},
                  {"responded":true,"latencyMs":20,"rcode":0,"answerSignature":"rcode=0;example.com|1|1|203.0.113.7"},
                  {"responded":false,"error":"timeout"}
                ]
              },
              "doh":{
                "transport":"doh",
                "attempted":true,
                "responded":true,
                "attempts":3,
                "successes":3,
                "quorumMet":true,
                "reliability":1,
                "medianLatencyMs":28,
                "answerSignature":"rcode=0;example.com|1|1|203.0.113.7",
                "tlsVersion":"TLS1.3",
                "alpn":"h2",
                "httpStatus":200,
                "httpVersion":"HTTP/2.0",
                "contentType":"application/dns-message",
                "tlsVerified":true
              },
              "ednsCompatible":true,
              "ednsDowngrade":false,
              "udpAndTcpAgree":true,
              "classicEncryptedAgree":true,
              "encryptedDnsAvailable":true,
              "interceptionSuspected":false,
              "quorumTransportCount":4,
              "reliabilityFloor":0.6666666667,
              "quality":"strong",
              "qualityReasons":["classic-encrypted-agreement"],
              "status":"usable"
            }
            """);

        await result.Should().NotBeNull();
        await result!.Udp!.Attempts.Should().BeEqualTo(3);
        await result.Udp.Successes.Should().BeEqualTo(2);
        await result.Udp.Samples.Count.Should().BeEqualTo(3);
        await result.Doh!.Alpn.Should().BeEqualTo("h2");
        await result.Doh.HttpVersion.Should().BeEqualTo("HTTP/2.0");
        await result.Quality.Should().BeEqualTo("strong");
        await result.ClassicEncryptedAgree.Should().BeTrue();
    }

    [Test]
    public async Task DeepQualificationAndConsensusRequests_ShouldSerializeSamplingControls()
    {
        var qualification = new DiscoveryResolverQualificationRequest
        {
            Address = "192.0.2.53",
            CheckDepth = true,
            DepthAttempts = 5,
            DepthMinSuccesses = 4,
        };
        var consensus = new DiscoveryDnsConsensusRequest
        {
            Domain = "example.com",
            CheckDepth = true,
            DepthAttempts = 5,
            DepthMinSuccesses = 3,
        };

        using var q = JsonDocument.Parse(JsonSerializer.Serialize(qualification));
        using var c = JsonDocument.Parse(JsonSerializer.Serialize(consensus));

        await q.RootElement.GetProperty("depthAttempts").GetInt32().Should().BeEqualTo(5);
        await q.RootElement.GetProperty("depthMinSuccesses").GetInt32().Should().BeEqualTo(4);
        await c.RootElement.GetProperty("depthAttempts").GetInt32().Should().BeEqualTo(5);
        await c.RootElement.GetProperty("depthMinSuccesses").GetInt32().Should().BeEqualTo(3);
    }
}
