using ServiceLib.Discovery.Protocol;

namespace ServiceLib.Tests.Reviver;

public partial class DiscoveryRpcModelTests
{
    [Test]
    public async Task DnssecInspectionDto_ShouldExposeCryptographicDnskeyAuthentication()
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
                  "ds":{"keyTag":1234,"algorithm":15,"digestType":2,"digest":"abcd"},
                  "dnskey":{"flags":257,"protocol":3,"algorithm":15,"publicKey":"AQID","keyTag":1234}
                }],
                "status":"ds-key-match"
              },
              "dnskeySignatures":[{
                "typeCovered":48,
                "algorithm":15,
                "keyTag":1234,
                "signerName":"example.com",
                "status":"valid"
              }],
              "dnskeyAuthenticated":true,
              "authenticationStatus":"dnskey-authenticated"
            }
            """);

        await result.Should().NotBeNull();
        await result!.DnskeyAuthenticated.Should().BeTrue();
        await result.AuthenticationStatus.Should().BeEqualTo("dnskey-authenticated");
        await result.DnskeySignatures.Count.Should().BeEqualTo(1);
        await result.DnskeySignatures[0].Status.Should().BeEqualTo("valid");
    }
}
