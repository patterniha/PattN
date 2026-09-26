using ServiceLib.Discovery.Protocol;

namespace ServiceLib.Tests.Reviver;

public partial class DiscoveryRpcModelTests
{
    [Test]
    public async Task ResolverProfileRequest_ShouldPreserveEncryptedDnsIdentity()
    {
        var request = new DiscoveryResolverProfileRequest
        {
            Address = "192.0.2.53",
            Domain = "example.com",
            ServerName = "dns.example.net",
            DotPort = 853,
            DohUrl = "https://dns.example.net/dns-query",
            CheckDot = true,
            CheckDoh = true,
        };

        var json = JsonSerializer.Serialize(request);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;

        await root.GetProperty("serverName").GetString().Should().BeEqualTo("dns.example.net");
        await root.GetProperty("dotPort").GetInt32().Should().BeEqualTo(853);
        await root.GetProperty("dohUrl").GetString().Should().BeEqualTo("https://dns.example.net/dns-query");
        await root.GetProperty("checkDot").GetBoolean().Should().BeTrue();
        await root.GetProperty("checkDoh").GetBoolean().Should().BeTrue();
    }

    [Test]
    public async Task ResolverProfileDto_ShouldPreserveEdnsTxtDotAndDohEvidence()
    {
        var result = JsonSerializer.Deserialize<DiscoveryResolverProfileResult>(
            """
            {
              "address":"192.0.2.53",
              "domain":"example.com",
              "udp":{"transport":"udp","attempted":true,"responded":true,"rcode":0,"answerCount":1},
              "tcp":{"transport":"tcp","attempted":true,"responded":true,"rcode":0,"answerCount":1},
              "edns512":{"transport":"udp","attempted":true,"responded":true,"rcode":0,"ednsObserved":true},
              "edns1232":{"transport":"udp","attempted":true,"responded":true,"rcode":0,"ednsObserved":true},
              "txt":{"transport":"udp","attempted":true,"responded":true,"rcode":0,"txt":["hello"]},
              "dot":{"transport":"dot","attempted":true,"responded":true,"rcode":0,"tlsVersion":"TLS1.3","tlsServerName":"dns.example.net","tlsVerified":true},
              "doh":{"transport":"doh","attempted":true,"responded":true,"rcode":0,"tlsVerified":true,"httpStatus":200,"contentType":"application/dns-message"},
              "ednsCompatible":true,
              "ednsDowngrade":false,
              "udpAndTcpAgree":true,
              "encryptedDnsAvailable":true,
              "status":"usable"
            }
            """);

        await result.Should().NotBeNull();
        await result!.EdnsCompatible.Should().BeTrue();
        await result.EncryptedDnsAvailable.Should().BeTrue();
        await result.Txt!.Txt[0].Should().BeEqualTo("hello");
        await result.Dot!.TlsVerified.Should().BeTrue();
        await result.Doh!.HttpStatus.Should().BeEqualTo(200);
    }

    [Test]
    public async Task DnssecDomainValidationDto_ShouldPreserveComposedNxDomainProof()
    {
        var result = JsonSerializer.Deserialize<DiscoveryDnssecDomainValidation>(
            """
            {
              "domain":"missing.example.com",
              "queryType":1,
              "rcode":3,
              "trace":{"domain":"missing.example.com","queryType":1,"hops":[],"complete":true,"terminalRcode":3},
              "denialProof":{
                "mechanism":"nsec3",
                "queryName":"missing.example.com",
                "queryType":1,
                "rcode":3,
                "closestEncloser":"example.com",
                "nextCloser":"missing.example.com",
                "wildcardName":"*.example.com",
                "closestEncloserProven":true,
                "nextCloserProven":true,
                "wildcardNonexistenceProven":true,
                "exactNameProven":false,
                "typeAbsent":false,
                "cnameAbsent":false,
                "optOut":false,
                "insecureDelegation":false,
                "complete":true,
                "status":"nxdomain-proven"
              },
              "answerAuthenticated":false,
              "denialAuthenticated":true,
              "trustScope":"root-anchored",
              "status":"root-anchored-authenticated-denial-evidence"
            }
            """);

        await result.Should().NotBeNull();
        await result!.DenialAuthenticated.Should().BeTrue();
        await result.DenialProof.Should().NotBeNull();
        await result.DenialProof!.Status.Should().BeEqualTo("nxdomain-proven");
        await result.DenialProof.WildcardNonexistenceProven.Should().BeTrue();
    }

    [Test]
    public async Task QualificationAndConsensusCanEmbedDepthProfiles()
    {
        var qualification = JsonSerializer.Deserialize<DiscoveryResolverQualification>(
            """
            {
              "address":"192.0.2.53",
              "port":53,
              "domain":"example.com",
              "responded":true,
              "recursionAvailable":true,
              "privateAnswerObserved":false,
              "referenceCompared":false,
              "referenceDivergence":false,
              "dnssecReferenceCompared":false,
              "dnssecReferenceDivergence":false,
              "hijackChecked":false,
              "hijackDetected":false,
              "depth":{"address":"192.0.2.53","domain":"example.com","ednsCompatible":true,"ednsDowngrade":false,"encryptedDnsAvailable":true,"status":"usable"},
              "status":"usable"
            }
            """);

        await qualification.Should().NotBeNull();
        await qualification!.Depth.Should().NotBeNull();
        await qualification.Depth!.EncryptedDnsAvailable.Should().BeTrue();
    }
}
