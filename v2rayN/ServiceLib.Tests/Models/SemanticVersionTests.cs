namespace ServiceLib.Tests.Models;

public class SemanticVersionTests
{
    [Test]
    [Arguments("7.24.9-P1", "7.24.9")] // a PattN revision ranks above the bare upstream version
    [Arguments("7.24.9-P2", "7.24.9-P1")] // revisions compare numerically...
    [Arguments("7.24.9-P10", "7.24.9-P9")] // ...not lexically
    [Arguments("7.24.10", "7.24.9-P3")] // the upstream part still dominates
    [Arguments("7.24.9-P1", "7.24.9-beta.1")] // a PattN revision beats a real pre-release
    [Arguments("1.14.0", "1.14.0-beta.1")] // plain semver pre-release ordering is untouched
    public async Task CompareTo_ShouldOrderPattNRevisions(string greater, string lesser)
    {
        var greaterVersion = new SemanticVersion(greater);
        var lesserVersion = new SemanticVersion(lesser);

        await (greaterVersion > lesserVersion).Should().BeTrue();
        await (lesserVersion >= greaterVersion).Should().BeFalse();
    }

    [Test]
    public async Task ToStandardVersionString_ShouldKeepPattNRevision()
    {
        var version = new SemanticVersion("v7.24.9-P2");

        await version.ToStandardVersionString("v").Should().BeEqualTo("v7.24.9-P2");
        await version.Equals(new SemanticVersion("7.24.9-P2")).Should().BeTrue();
    }
}
