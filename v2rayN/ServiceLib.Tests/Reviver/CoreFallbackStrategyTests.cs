using ServiceLib.Reviver.Models;
using ServiceLib.Reviver.Normalization;
using ServiceLib.Reviver.Strategies;

namespace ServiceLib.Tests.Reviver;

public class CoreFallbackStrategyTests
{
    [Test]
    public async Task Compatibility_ShouldRejectSingBoxForXhttp_AndAcceptXray()
    {
        var profile = NewVless(nameof(ETransport.xhttp));
        var compatibility = new ProfileCoreCompatibility();
        await compatibility.Supports(profile, ECoreType.sing_box).Should().BeFalse();
        await compatibility.Supports(profile, ECoreType.Xray).Should().BeTrue();
    }

    [Test]
    public async Task Generate_ShouldChangeOnlyCoreType()
    {
        var profile = NewVless(nameof(ETransport.ws));
        profile.CoreType = ECoreType.Xray;
        var session = new RepairSession { Original = ProfileSnapshot.Capture(profile) };
        var strategy = new CoreFallbackStrategy(new ProfileCoreCompatibility());
        var results = new List<RepairCandidate>();
        await foreach (var candidate in strategy.GenerateAsync(session, ERepairFailureClass.CoreStartupFailure))
        {
            results.Add(candidate);
        }
        await results.Count.Should().BeEqualTo(1);
        await results[0].Profile.CoreType.Should().BeEqualTo(ECoreType.sing_box);
        await ProfileMutationGuard.ChangesOnly(profile, results[0].Profile, nameof(ProfileItem.CoreType)).Should().BeTrue();
    }

    private static ProfileItem NewVless(string network)
        => new()
        {
            ConfigType = EConfigType.VLESS,
            Address = "example.com",
            Port = 443,
            Password = Guid.NewGuid().ToString(),
            Network = network,
            StreamSecurity = "tls",
        };
}
