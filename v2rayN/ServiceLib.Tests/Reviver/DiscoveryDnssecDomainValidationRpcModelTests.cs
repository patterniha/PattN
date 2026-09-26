using ServiceLib.Discovery.Protocol;

namespace ServiceLib.Tests.Reviver;

public partial class DiscoveryRpcModelTests
{
    [Test]
    public async Task DnssecDomainValidationDto_ShouldPreserveAuthenticatedAliasChain()
    {
        var result = JsonSerializer.Deserialize<DiscoveryDnssecDomainValidation>(
            """
            {
              "domain":"alias.example",
              "queryType":1,
              "rcode":0,
              "trace":{
                "domain":"alias.example",
                "queryType":1,
                "hops":[],
                "aliasChain":[{
                  "queryName":"alias.example",
                  "owner":"alias.example",
                  "target":"target.example",
                  "resultName":"target.example",
                  "type":5
                }],
                "finalAnswers":[{"name":"target.example","type":1,"address":"203.0.113.10"}],
                "complete":true
              },
              "aliasValidations":[{
                "step":{
                  "queryName":"alias.example",
                  "owner":"alias.example",
                  "target":"target.example",
                  "resultName":"target.example",
                  "type":5
                },
                "signerZone":"example",
                "signatures":[{
                  "typeCovered":5,
                  "algorithm":15,
                  "keyTag":1234,
                  "signerName":"example",
                  "status":"valid"
                }],
                "authenticated":true,
                "status":"root-anchored-authenticated-alias"
              }],
              "aliasChainAuthenticated":true,
              "answerAuthenticated":true,
              "denialAuthenticated":false,
              "trustScope":"root-anchored",
              "status":"root-anchored-authenticated-answer"
            }
            """);

        await result.Should().NotBeNull();
        await result!.AliasChainAuthenticated.Should().BeTrue();
        await result.AliasValidations.Count.Should().BeEqualTo(1);
        await result.AliasValidations[0].Authenticated.Should().BeTrue();
        await result.AliasValidations[0].Step.Type.Should().BeEqualTo(5);
        await result.Trace.AliasChain[0].ResultName.Should().BeEqualTo("target.example");
    }

    [Test]
    public async Task DnssecDomainValidationDto_ShouldPreserveAnswerAndDenialEvidence()
    {
        var result = JsonSerializer.Deserialize<DiscoveryDnssecDomainValidation>(
            """
            {
              "domain":"www.example.com",
              "queryType":1,
              "rcode":0,
              "trace":{"domain":"www.example.com","queryType":1,"hops":[],"complete":true},
              "signerZone":"example.com",
              "rrsetSignatures":[{
                "typeCovered":1,
                "algorithm":15,
                "keyTag":1234,
                "signerName":"example.com",
                "status":"valid"
              }],
              "denial":[{
                "evidence":{
                  "mechanism":"nsec3",
                  "owner":"ABC",
                  "next":"XYZ",
                  "queryName":"missing.example.com",
                  "queryType":1,
                  "exactName":false,
                  "nameCovered":true,
                  "typeAbsent":true,
                  "cnameAbsent":true,
                  "optOut":false,
                  "status":"name-nonexistence-evidence"
                },
                "signatures":[{
                  "typeCovered":50,
                  "algorithm":15,
                  "keyTag":1234,
                  "signerName":"example.com",
                  "status":"valid"
                }],
                "authenticated":true
              }],
              "answerAuthenticated":true,
              "denialAuthenticated":false,
              "trustScope":"root-anchored",
              "status":"delegation-authenticated-answer"
            }
            """);

        await result.Should().NotBeNull();
        await result!.AnswerAuthenticated.Should().BeTrue();
        await result.TrustScope.Should().BeEqualTo("root-anchored");
        await result.RrsetSignatures.Count.Should().BeEqualTo(1);
        await result.Denial.Count.Should().BeEqualTo(1);
        await result.Denial[0].Evidence.Mechanism.Should().BeEqualTo("nsec3");
    }
}
