using ServiceLib.Discovery.Protocol;

namespace ServiceLib.Tests.Reviver;

public partial class DiscoveryRpcModelTests
{
    [Test]
    public async Task DnssecChainDto_ShouldPreserveRootAnchorAndParentSteps()
    {
        var result = JsonSerializer.Deserialize<DiscoveryDnssecChainResult>(
            """
            {
              "targetZone":"example.com",
              "trustAnchors":[
                {"zone":".","keyTag":20326,"algorithm":8,"digestType":2,"digest":"AA","source":"IANA root trust anchors"},
                {"zone":".","keyTag":38696,"algorithm":8,"digestType":2,"digest":"BB","source":"IANA root trust anchors"}
              ],
              "steps":[
                {"zone":".","dnskey":{"domain":".","queryType":48,"hops":[],"complete":true},"authenticated":true,"status":"root-anchored","trustedKeyCount":3},
                {"zone":"com","parent":".","dnskey":{"domain":"com","queryType":48,"hops":[],"complete":true},"authenticated":true,"status":"root-anchored","trustedKeyCount":2},
                {"zone":"example.com","parent":"com","dnskey":{"domain":"example.com","queryType":48,"hops":[],"complete":true},"authenticated":true,"status":"root-anchored","trustedKeyCount":2}
              ],
              "rootAuthenticated":true,
              "chainAuthenticated":true,
              "authenticatedZone":"example.com",
              "status":"root-anchored"
            }
            """);

        await result.Should().NotBeNull();
        await result!.RootAuthenticated.Should().BeTrue();
        await result.ChainAuthenticated.Should().BeTrue();
        await result.TrustAnchors.Count.Should().BeEqualTo(2);
        await result.Steps.Count.Should().BeEqualTo(3);
        await result.AuthenticatedZone.Should().BeEqualTo("example.com");
    }

    [Test]
    public async Task DnssecChainDto_ShouldPreserveAuthenticatedInsecureDelegation()
    {
        var result = JsonSerializer.Deserialize<DiscoveryDnssecChainResult>(
            """
            {
              "targetZone":"unsigned.example",
              "trustAnchors":[],
              "steps":[{
                "zone":"unsigned.example",
                "parent":"example",
                "ds":{"domain":"unsigned.example","queryType":43,"hops":[],"complete":true},
                "dsAbsenceProof":{
                  "mechanism":"nsec3",
                  "queryName":"unsigned.example",
                  "queryType":43,
                  "rcode":0,
                  "closestEncloser":"example",
                  "nextCloser":"unsigned.example",
                  "closestEncloserProven":true,
                  "nextCloserProven":true,
                  "optOut":true,
                  "insecureDelegation":true,
                  "complete":true,
                  "status":"insecure-delegation-optout"
                },
                "delegationAuthenticated":true,
                "insecureDelegation":true,
                "authenticated":false,
                "status":"root-anchored-insecure-delegation",
                "trustedKeyCount":0
              }],
              "rootAuthenticated":true,
              "chainAuthenticated":false,
              "insecureDelegation":true,
              "authenticatedZone":"example",
              "insecureZone":"unsigned.example",
              "status":"root-anchored-insecure-delegation"
            }
            """);

        await result.Should().NotBeNull();
        await result!.RootAuthenticated.Should().BeTrue();
        await result.ChainAuthenticated.Should().BeFalse();
        await result.InsecureDelegation.Should().BeTrue();
        await result.AuthenticatedZone.Should().BeEqualTo("example");
        await result.InsecureZone.Should().BeEqualTo("unsigned.example");
        await result.Steps[0].DelegationAuthenticated.Should().BeTrue();
        await result.Steps[0].InsecureDelegation.Should().BeTrue();
        await result.Steps[0].DsAbsenceProof.Should().NotBeNull();
        await result.Steps[0].DsAbsenceProof!.Complete.Should().BeTrue();
    }

    [Test]
    public async Task ResolverQualificationRequest_ShouldExposeOptInDnssecReference()
    {
        var request = new DiscoveryResolverQualificationRequest
        {
            Address = "192.0.2.53",
            Domain = "example.com",
            CheckDnssec = true,
        };
        var json = JsonSerializer.Serialize(request);
        using var document = JsonDocument.Parse(json);
        await document.RootElement.GetProperty("checkDnssec").GetBoolean().Should().BeTrue();
    }

    [Test]
    public async Task ResolverQualificationDto_ShouldDistinguishDnssecDivergence()
    {
        var result = JsonSerializer.Deserialize<DiscoveryResolverQualification>(
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
              "dnssecReferenceCompared":true,
              "dnssecReferenceDivergence":true,
              "dnssecReferenceStatus":"root-anchored-authenticated-answer",
              "hijackChecked":false,
              "hijackDetected":false,
              "status":"dnssec-divergent"
            }
            """);
        await result.Should().NotBeNull();
        await result!.DnssecReferenceCompared.Should().BeTrue();
        await result.DnssecReferenceDivergence.Should().BeTrue();
        await result.Status.Should().BeEqualTo("dnssec-divergent");
    }

    [Test]
    public async Task ConsensusDto_ShouldKeepAuthorityAndDnssecAssessmentsSeparate()
    {
        var result = JsonSerializer.Deserialize<DiscoveryDnsConsensusComparison>(
            """
            {
              "domain":"example.com",
              "queryType":1,
              "authority":{"domain":"example.com","queryType":1,"observations":[],"responding":2,"unanimous":true,"divergent":false,"majorityCount":2,"majoritySignature":"A"},
              "resolvers":[],
              "consensus":{"evidenceCount":0,"validEvidenceCount":0,"unanimous":false,"divergent":false},
              "authorityReferenceSignature":"A",
              "authorityReferenceDefinitive":true,
              "dnssecReferenceSignature":"A",
              "dnssecReferenceDefinitive":true,
              "candidates":[{"source":"candidate","signature":"B","authorityReference":"A","status":"differs-authority","dnssecStatus":"differs-dnssec"}]
            }
            """);

        await result.Should().NotBeNull();
        await result!.DnssecReferenceDefinitive.Should().BeTrue();
        await result.Candidates.Count.Should().BeEqualTo(1);
        await result.Candidates[0].Status.Should().BeEqualTo("differs-authority");
        await result.Candidates[0].DnssecStatus.Should().BeEqualTo("differs-dnssec");
    }
}
