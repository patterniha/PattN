using v2rayN.WebAPI.Services;

namespace v2rayN.WebAPI.Tests;

public class WebReleaseChannelTests
{
    [Test]
    public async Task OfficialReleaseTagsAreAcceptedAndLegacyWebTagsAreIgnored()
    {
        var accepted = WebReleaseChannel.TryParseReleaseTag("7.25.3", out var version);
        await accepted.Should().BeTrue();
        await version.Should().BeEqualTo("7.25.3");

        foreach (var legacy in new[] { "web-v7.25.3-web.1", "7.25.3-web.1", "v7.25.3", "7.25", "7.25.3.1", "", null })
        {
            var parsed = WebReleaseChannel.TryParseReleaseTag(legacy, out var parsedVersion);
            await parsed.Should().BeFalse();
            await parsedVersion.Should().BeEqualTo(string.Empty);
        }
    }

    [Test]
    public async Task PattNReleaseTagsAreAccepted()
    {
        // PattN: releases are tagged x.y.z-P<n>
        var accepted = WebReleaseChannel.TryParseReleaseTag("7.25.6-P35", out var version);
        await accepted.Should().BeTrue();
        await version.Should().BeEqualTo("7.25.6-P35");

        foreach (var invalid in new[] { "7.25.6-P", "7.25.6-P0", "7.25.6-P01", "7.25.6-p35", "7.25.6-P35-web.1", "v7.25.6-P35" })
        {
            var parsed = WebReleaseChannel.TryParseReleaseTag(invalid, out var parsedVersion);
            await parsed.Should().BeFalse();
            await parsedVersion.Should().BeEqualTo(string.Empty);
        }
    }

    [Test]
    public async Task ReleaseIndexUrlIsBuiltFromTheBuildRepository()
    {
        await WebReleaseChannel.BuildReleaseIndexUrl("patterniha/PattN")
            .Should().BeEqualTo("https://api.github.com/repos/patterniha/PattN/releases?per_page=100");
        await WebReleaseChannel.DefaultRepository.Should().BeEqualTo("patterniha/PattN");

        var rejected = false;
        try
        { _ = WebReleaseChannel.BuildReleaseIndexUrl("patterniha/PattN/../../evil"); }
        catch (ArgumentException) { rejected = true; }
        await rejected.Should().BeTrue();
        await WebReleaseChannel.IsValidRepository("community-fork/v2rayN").Should().BeTrue();
        await WebReleaseChannel.IsValidRepository("not-a-repository").Should().BeFalse();
    }

    [Test]
    public async Task TrustedAssetUrlsMustUseTheBuildRepositoryTagAndAsset()
    {
        var repository = "patterniha/PattN";
        var tag = "7.25.3";
        var asset = "PattN-linux-64-WebAPI-update.zip";
        var trusted = $"https://github.com/{repository}/releases/download/{tag}/{asset}";

        await WebReleaseChannel.IsTrustedAssetUrl(trusted, repository, tag, asset).Should().BeTrue();
        // A build must not accept the same asset from another repository.
        await WebReleaseChannel.IsTrustedAssetUrl(trusted.Replace(repository, "another-owner/v2rayN", StringComparison.Ordinal),
            repository, tag, asset).Should().BeFalse();
        await WebReleaseChannel.IsTrustedAssetUrl("http://github.com/patterniha/PattN/releases/download/7.25.3/" + asset,
            repository, tag, asset).Should().BeFalse();
        await WebReleaseChannel.IsTrustedAssetUrl("https://example.com/patterniha/PattN/releases/download/7.25.3/" + asset,
            repository, tag, asset).Should().BeFalse();
        await WebReleaseChannel.IsTrustedAssetUrl(trusted, repository, "7.25.4", asset).Should().BeFalse();
        await WebReleaseChannel.IsTrustedAssetUrl(trusted, repository, tag, "WebAPI-update.json").Should().BeFalse();
        await WebReleaseChannel.IsTrustedAssetUrl("https://github.com/patterniha/PattN/releases/download/7.25.3/sub/" + asset,
            repository, tag, asset).Should().BeFalse();
        await WebReleaseChannel.IsTrustedAssetUrl(null, repository, tag, asset).Should().BeFalse();
    }

    [Test]
    public async Task RuntimeIdentifiersMapToSupportedArchiveNames()
    {
        await WebUpdatePackageStager.ArtifactArch("linux-x64").Should().BeEqualTo("64");
        await WebUpdatePackageStager.ArtifactArch("linux-arm64").Should().BeEqualTo("arm64");
        await WebUpdatePackageStager.FullInstallAssetName("linux-x64").Should().BeEqualTo("PattN-linux-64-WebAPI.zip");
        await WebUpdatePackageStager.FullInstallAssetName("linux-arm64").Should().BeEqualTo("PattN-linux-arm64-WebAPI.zip");
        await WebUpdatePackageStager.AppOnlyAssetName("linux-x64").Should().BeEqualTo("PattN-linux-64-WebAPI-update.zip");
        await WebUpdatePackageStager.AppOnlyAssetName("linux-arm64").Should().BeEqualTo("PattN-linux-arm64-WebAPI-update.zip");
        await WebUpdatePackageStager.ArtifactArch("win-x64").Should().BeEqualTo("64");
        await WebUpdatePackageStager.FullInstallAssetName("win-x64").Should().BeEqualTo("PattN-windows-64-WebAPI.zip");
        await WebUpdatePackageStager.AppOnlyAssetName("win-x64").Should().BeEqualTo("PattN-windows-64-WebAPI-update.zip");
        await WebUpdatePackageStager.ArtifactArch("linux-riscv64").Should().BeEqualTo("riscv64");
        await WebUpdatePackageStager.FullInstallAssetName("linux-riscv64").Should().BeEqualTo("PattN-linux-riscv64-WebAPI.zip");
        await WebUpdatePackageStager.AppOnlyAssetName("linux-riscv64").Should().BeEqualTo("PattN-linux-riscv64-WebAPI-update.zip");
        await WebUpdatePackageStager.ArtifactArch("linux-loongarch64").Should().BeEqualTo("loong64");
        await WebUpdatePackageStager.FullInstallAssetName("linux-loongarch64").Should().BeEqualTo("PattN-linux-loong64-WebAPI.zip");
        await WebUpdatePackageStager.AppOnlyAssetName("linux-loongarch64").Should().BeEqualTo("PattN-linux-loong64-WebAPI-update.zip");
        await WebUpdatePackageStager.ArtifactArch("win-arm64").Should().BeEqualTo("arm64");
        await WebUpdatePackageStager.FullInstallAssetName("win-arm64").Should().BeEqualTo("PattN-windows-arm64-WebAPI.zip");
        await WebUpdatePackageStager.AppOnlyAssetName("win-arm64").Should().BeEqualTo("PattN-windows-arm64-WebAPI-update.zip");
        await WebUpdatePackageStager.IsSupportedRid("linux-riscv64").Should().BeTrue();
        await WebUpdatePackageStager.IsSupportedRid("linux-loongarch64").Should().BeTrue();
        await WebUpdatePackageStager.IsSupportedRid("win-arm64").Should().BeTrue();
        await WebUpdatePackageStager.IsSupportedRid("linux-unknown64").Should().BeFalse();
        await WebUpdatePackageStager.FullInstallAssetName("linux-unknown64").Should().BeNull();
        await WebUpdatePackageStager.AppOnlyAssetName(null).Should().BeNull();
    }

    [Test]
    public async Task OfficialVersionsCompareGreaterThanDevAndLegacyIdentities()
    {
        await WebUpdatePackageStager.IsUpdateAvailable("7.25.2", "7.25.3", allowPrerelease: false).Should().BeTrue();
        await WebUpdatePackageStager.IsUpdateAvailable("7.25.3", "7.25.3", allowPrerelease: false).Should().BeFalse();
        await WebUpdatePackageStager.IsUpdateAvailable("7.25.3", "7.25.2", allowPrerelease: false).Should().BeFalse();
        await WebUpdatePackageStager.IsUpdateAvailable("0.0.0-dev", "7.25.3", allowPrerelease: false).Should().BeTrue();
        await WebUpdatePackageStager.IsUpdateAvailable("7.25.2-web.9", "7.25.3", allowPrerelease: false).Should().BeTrue();
    }

    [Test]
    public async Task PattNRevisionsCompareNumericallyAndAboveTheirUpstreamVersion()
    {
        // PattN: ServiceLib's SemanticVersion ranks "-P<n>" above the bare version and compares n as a number
        await WebUpdatePackageStager.IsUpdateAvailable("7.25.6-P34", "7.25.6-P35", allowPrerelease: false).Should().BeTrue();
        await WebUpdatePackageStager.IsUpdateAvailable("7.25.6-P35", "7.25.6-P35", allowPrerelease: false).Should().BeFalse();
        await WebUpdatePackageStager.IsUpdateAvailable("7.25.6-P35", "7.25.6-P34", allowPrerelease: false).Should().BeFalse();
        await WebUpdatePackageStager.IsUpdateAvailable("7.25.6-P99", "7.25.6-P100", allowPrerelease: false).Should().BeTrue();
        await WebUpdatePackageStager.IsUpdateAvailable("7.25.6", "7.25.6-P1", allowPrerelease: false).Should().BeTrue();
        await WebUpdatePackageStager.IsUpdateAvailable("7.25.6-P35", "7.26.0-P36", allowPrerelease: false).Should().BeTrue();
        await WebUpdatePackageStager.IsUpdateAvailable("0.0.0-dev", "7.25.6-P35", allowPrerelease: false).Should().BeTrue();
    }
}
