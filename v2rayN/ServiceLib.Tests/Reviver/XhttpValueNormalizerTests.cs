namespace ServiceLib.Tests.Reviver;

public class XhttpValueNormalizerTests
{
    [Test]
    public async Task Range_ShouldAcceptPositiveSignsLeadingZerosAndWhitespace()
    {
        var ok = XhttpValueNormalizer.TryNormalizeRange(" +001 - 0008 ", out var normalized, false, false);
        await ok.Should().BeTrue();
        await normalized.Should().BeEqualTo("1-8");
    }

    [Test]
    public async Task Range_ShouldRejectDescendingOrForbiddenZeroBounds()
    {
        await XhttpValueNormalizer.TryNormalizeRange("8-1", out _).Should().BeFalse();
        await XhttpValueNormalizer.TryNormalizeRange("0-8", out _, false, false).Should().BeFalse();
        await XhttpValueNormalizer.TryNormalizeRange("0-0", out _, true, false).Should().BeFalse();
    }

    [Test]
    public async Task Integer_ShouldAcceptExplicitSignButRejectFractions()
    {
        await XhttpValueNormalizer.TryNormalizeInteger("+0012", out var value).Should().BeTrue();
        await value.Should().BeEqualTo(12);
        await XhttpValueNormalizer.TryNormalizeInteger("1.5", out _).Should().BeFalse();
    }
}
