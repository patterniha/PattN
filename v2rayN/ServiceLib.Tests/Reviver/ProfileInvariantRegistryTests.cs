using ServiceLib.Reviver.Normalization;

namespace ServiceLib.Tests.Reviver;

public class ProfileInvariantRegistryTests
{
    [Test]
    public async Task Validate_ShouldRejectInvalidWebSocketEarlyDataWithoutChangingPath()
    {
        var profile = BaseProfile(nameof(ETransport.ws));
        profile.SetTransportExtra(new TransportExtraItem { Path = "/ws?foo=1&ed=oops" });
        var violations = new ProfileInvariantRegistry().Validate(profile);
        await violations.Any(x => x.Code == "ws.earlyData.invalid").Should().BeTrue();
        await profile.GetTransportExtra().Path.Should().BeEqualTo("/ws?foo=1&ed=oops");
    }

    [Test]
    public async Task Validate_ShouldRecognizeKnownInvalidXhttpRangesButPreserveUnknownFields()
    {
        var profile = BaseProfile(nameof(ETransport.xhttp));
        profile.SetTransportExtra(new TransportExtraItem
        {
            XhttpExtra = """{"xPaddingBytes":"8-4","unknownFutureField":{"x":1},"xmux":{"maxConcurrency":"+001-008"}}""",
        });
        var violations = new ProfileInvariantRegistry().Validate(profile);
        await violations.Any(x => x.Code == "xhttp.xPaddingBytes.invalid").Should().BeTrue();
        await violations.Any(x => x.Code.Contains("unknownFutureField", StringComparison.Ordinal)).Should().BeFalse();
    }

    [Test]
    public async Task Validate_ShouldRejectUnknownTargetStrategy()
    {
        var profile = BaseProfile(nameof(ETransport.ws));
        profile.TargetStrategy = "GuessIPv9";
        var violations = new ProfileInvariantRegistry().Validate(profile);
        await violations.Any(x => x.Code == "dns.targetStrategy.unknown").Should().BeTrue();
    }

    [Test]
    public async Task Validate_ShouldAcceptKnownTargetStrategies()
    {
        foreach (var value in Global.TargetStrategies)
        {
            var profile = BaseProfile(nameof(ETransport.ws));
            profile.TargetStrategy = value;
            var violations = new ProfileInvariantRegistry().Validate(profile);
            await violations.Any(x => x.Code == "dns.targetStrategy.unknown").Should().BeFalse();
        }
    }

    private static ProfileItem BaseProfile(string network)
        => new()
        {
            ConfigType = EConfigType.VLESS,
            Address = "example.com",
            Port = 443,
            Password = Guid.NewGuid().ToString(),
            Network = network,
            StreamSecurity = Global.StreamSecurity,
        };
}
