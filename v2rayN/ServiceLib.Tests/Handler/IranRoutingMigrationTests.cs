using ServiceLib.Handler;

namespace ServiceLib.Tests.Handler;

public class IranRoutingMigrationTests
{
    private static RulesItem DirectRule(params string[] domains) => new()
    {
        OutboundTag = Global.DirectTag,
        Domain = [.. domains],
    };

    private static string Domains(RulesItem rule) => string.Join(",", rule.Domain ?? []);

    [Test]
    public async Task MigrateIranDirectDomains_ShouldRewriteGeositeIr()
    {
        var rules = new List<RulesItem> { DirectRule("geosite:private"), DirectRule("geosite:ir") };

        var changed = ConfigHandler.MigrateIranDirectDomains(rules);

        await changed.Should().BeTrue();
        await Domains(rules[0]).Should().BeEqualTo("geosite:private");
        await Domains(rules[1]).Should().BeEqualTo("domain:ir,geosite:category-ir");
    }

    [Test]
    public async Task MigrateIranDirectDomains_ShouldBeIdempotent()
    {
        var rules = new List<RulesItem> { DirectRule("domain:ir", "geosite:category-ir") };

        var changed = ConfigHandler.MigrateIranDirectDomains(rules);

        await changed.Should().BeFalse();
        await Domains(rules[0]).Should().BeEqualTo("domain:ir,geosite:category-ir");
    }

    [Test]
    public async Task MigrateIranDirectDomains_ShouldNotDuplicateExistingEntries()
    {
        var rules = new List<RulesItem> { DirectRule("domain:ir", "geosite:ir", "geosite:category-ir") };

        var changed = ConfigHandler.MigrateIranDirectDomains(rules);

        await changed.Should().BeTrue();
        await Domains(rules[0]).Should().BeEqualTo("domain:ir,geosite:category-ir");
    }

    [Test]
    public async Task MigrateIranDirectDomains_ShouldLeaveNonDirectRulesAlone()
    {
        var proxyRule = new RulesItem { OutboundTag = Global.ProxyTag, Domain = ["geosite:ir"] };
        var rules = new List<RulesItem> { proxyRule };

        var changed = ConfigHandler.MigrateIranDirectDomains(rules);

        await changed.Should().BeFalse();
        await Domains(proxyRule).Should().BeEqualTo("geosite:ir");
    }
}
