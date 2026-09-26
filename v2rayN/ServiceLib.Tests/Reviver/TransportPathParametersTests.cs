namespace ServiceLib.Tests.Reviver;

public class TransportPathParametersTests
{
    [Test]
    public async Task Extract_ShouldRemoveOnlyRequestedMetadata_AndPreserveUnknownQueryBytes()
    {
        var (path, value) = TransportPathParameters.Extract("/ws?foo=a%2Fb&ed=2048&bar=x+y", "ed");
        await path.Should().BeEqualTo("/ws?foo=a%2Fb&bar=x+y");
        await value.Should().BeEqualTo("2048");
    }

    [Test]
    public async Task Extract_ShouldDecodeHeaderMetadataWithoutTouchingOtherEncodedParameters()
    {
        var (path, value) = TransportPathParameters.Extract("/ws?foo=a%2Fb&eh=Sec-WebSocket-Protocol&bar=x+y", "eh");
        await path.Should().BeEqualTo("/ws?foo=a%2Fb&bar=x+y");
        await value.Should().BeEqualTo("Sec-WebSocket-Protocol");
    }

    [Test]
    public async Task Extract_ShouldPreserveEmptyQueryComponents()
    {
        var (path, value) = TransportPathParameters.Extract("/ws?foo=1&&ed=2048&bar=2", "ed");
        await path.Should().BeEqualTo("/ws?foo=1&&bar=2");
        await value.Should().BeEqualTo("2048");
    }

    [Test]
    public async Task Get_ShouldPreserveLiteralPlusInDecodedMetadata()
    {
        await TransportPathParameters.Get("/ws?eh=X+EarlyData", "eh").Should().BeEqualTo("X+EarlyData");
    }

    [Test]
    public async Task Remove_ShouldDropInvalidOrEmptyMetadataWithoutChangingOtherComponents()
    {
        var path = TransportPathParameters.Remove("/ws?foo=1&&ed=invalid&eh=&bar=2", "ed", "eh");
        await path.Should().BeEqualTo("/ws?foo=1&&bar=2");
    }

    [Test]
    public async Task Set_ShouldReplaceDuplicateMetadataWithoutDiscardingOtherParameters()
    {
        var path = TransportPathParameters.Set("/ws?ed=10&foo=1&ed=20", "ed", "4096");
        await path.Should().BeEqualTo("/ws?foo=1&ed=4096");
        await TransportPathParameters.Get(path, "ed").Should().BeEqualTo("4096");
    }
}
