using ServiceLib.ViewModels;

namespace ServiceLib.Tests.Reviver;

public class DNSSettingViewModelValidationTests
{
    [Test]
    public async Task IsValidXrayDnsText_ShouldAcceptEmptyAndLegacyLineValues()
    {
        await DNSSettingViewModel.IsValidXrayDnsText(null).Should().BeTrue();
        await DNSSettingViewModel.IsValidXrayDnsText(string.Empty).Should().BeTrue();
        await DNSSettingViewModel.IsValidXrayDnsText("1.1.1.1,8.8.8.8").Should().BeTrue();
    }

    [Test]
    public async Task IsValidXrayDnsText_ShouldRequireNonEmptyServersForJsonInput()
    {
        await DNSSettingViewModel.IsValidXrayDnsText("""{"servers":["1.1.1.1"]}""").Should().BeTrue();
        await DNSSettingViewModel.IsValidXrayDnsText("""{"servers":[]}""").Should().BeFalse();
        await DNSSettingViewModel.IsValidXrayDnsText("""{"hosts":{"example.com":"192.0.2.1"}}""").Should().BeFalse();
    }

    [Test]
    public async Task IsValidXrayDnsText_ShouldRejectMalformedJsonLookingInput()
    {
        await DNSSettingViewModel.IsValidXrayDnsText("""{"servers":["1.1.1.1"]""").Should().BeFalse();
        await DNSSettingViewModel.IsValidXrayDnsText("not-json }").Should().BeFalse();
    }


    [Test]
    public async Task IsValidSingBoxDnsText_ShouldRequireTypedServersAndHandleNullSafely()
    {
        await DNSSettingViewModel.IsValidSingBoxDnsText(null).Should().BeTrue();
        await DNSSettingViewModel.IsValidSingBoxDnsText("""{"servers":[{"type":"https"}]}""").Should().BeTrue();
        await DNSSettingViewModel.IsValidSingBoxDnsText("""{"servers":[]}""").Should().BeFalse();
        await DNSSettingViewModel.IsValidSingBoxDnsText("""{"servers":null}""").Should().BeFalse();
        await DNSSettingViewModel.IsValidSingBoxDnsText("""{"servers":[{"type":""}]}""").Should().BeFalse();
        await DNSSettingViewModel.IsValidSingBoxDnsText("""{"servers":""").Should().BeFalse();
    }
}
