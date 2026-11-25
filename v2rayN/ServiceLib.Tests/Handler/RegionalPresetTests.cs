using ServiceLib.Tests.CoreConfig;

namespace ServiceLib.Tests.Handler;

// PattN: the cases do not run beside each other or other tests, as the other database tests: sqlite-net shares one
// connection, whose transactions cannot overlap.
[NotInParallel]
public class RegionalPresetTests
{
    [Test]
    [Arguments(EPresetType.Default)]
    [Arguments(EPresetType.China)]
    [Arguments(EPresetType.Russia)]
    [Arguments(EPresetType.Iran)]
    public async Task ApplyRegionalPreset_ShouldKeepTheDnsSettings(EPresetType type)
    {
        SQLiteHelper.Instance.CreateTable<DNSItem>();
        SQLiteHelper.Instance.CreateTable<RoutingItem>();
        var config = CoreConfigTestFactory.CreateConfig();
        var simpleDns = config.SimpleDNSItem;
        var simpleDnsBefore = JsonUtils.Serialize(simpleDns);
        var dnsItemsBefore = JsonUtils.Serialize(await ConfigDbQuery.DNSItems());

        await ConfigDbHandler.ApplyRegionalPreset(type);

        await ReferenceEquals(config.SimpleDNSItem, simpleDns).Should().BeTrue();
        await JsonUtils.Serialize(config.SimpleDNSItem).Should().BeEqualTo(simpleDnsBefore);
        await JsonUtils.Serialize(await ConfigDbQuery.DNSItems()).Should().BeEqualTo(dnsItemsBefore);
    }
}
