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

        var changed = ConfigDbHandler.MigrateIranDirectDomains(rules);

        await changed.Should().BeTrue();
        await Domains(rules[0]).Should().BeEqualTo("geosite:private");
        await Domains(rules[1]).Should().BeEqualTo("domain:ir,geosite:category-ir");
    }

    [Test]
    public async Task MigrateIranDirectDomains_ShouldBeIdempotent()
    {
        var rules = new List<RulesItem> { DirectRule("domain:ir", "geosite:category-ir") };

        var changed = ConfigDbHandler.MigrateIranDirectDomains(rules);

        await changed.Should().BeFalse();
        await Domains(rules[0]).Should().BeEqualTo("domain:ir,geosite:category-ir");
    }

    [Test]
    public async Task MigrateIranDirectDomains_ShouldNotDuplicateExistingEntries()
    {
        var rules = new List<RulesItem> { DirectRule("domain:ir", "geosite:ir", "geosite:category-ir") };

        var changed = ConfigDbHandler.MigrateIranDirectDomains(rules);

        await changed.Should().BeTrue();
        await Domains(rules[0]).Should().BeEqualTo("domain:ir,geosite:category-ir");
    }

    [Test]
    public async Task MigrateIranDirectDomains_ShouldLeaveNonDirectRulesAlone()
    {
        var proxyRule = new RulesItem { OutboundTag = Global.ProxyTag, Domain = ["geosite:ir"] };
        var rules = new List<RulesItem> { proxyRule };

        var changed = ConfigDbHandler.MigrateIranDirectDomains(rules);

        await changed.Should().BeFalse();
        await Domains(proxyRule).Should().BeEqualTo("geosite:ir");
    }

    // The last rule of custom_routing_white_iran up to 7.25.2-P28, exactly as it shipped
    private const string ShippedProxyCatchAll = """
        [{"port":"0-65535","outboundTag":"proxy","enabled":true,"remarks":"\u0633\u0627\u06cc\u0631\u0020\u0645\u0648\u0627\u0631\u062f\u0020\u002d\u0020\u067e\u0631\u0627\u06a9\u0633\u06cc"}]
        """;

    private static RulesItem ShippedProxyCatchAllRule() => JsonUtils.Deserialize<List<RulesItem>>(ShippedProxyCatchAll)![0];

    [Test]
    public async Task RemoveIranProxyCatchAll_ShouldRemoveTheShippedRule()
    {
        var rules = new List<RulesItem> { DirectRule("domain:ir", "geosite:category-ir"), ShippedProxyCatchAllRule() };

        var removed = ConfigDbHandler.RemoveIranProxyCatchAll(rules);

        await removed.Should().BeEqualTo(1);
        await rules.Count.Should().BeEqualTo(1);
        await Domains(rules[0]).Should().BeEqualTo("domain:ir,geosite:category-ir");
        await ConfigDbHandler.RemoveIranProxyCatchAll(rules).Should().BeEqualTo(0);
    }

    [Test]
    public async Task RemoveIranProxyCatchAll_ShouldLeaveEditedRulesAlone()
    {
        var rules = new List<RulesItem>();
        foreach (var edit in new Action<RulesItem>[]
        {
            t => t.Domain = ["geosite:google"],
            t => t.Ip = ["1.1.1.1"],
            t => t.Network = "udp",
            t => t.Port = "443",
            t => t.OutboundTag = Global.DirectTag,
            t => t.Remarks = "proxy",
        })
        {
            var rule = ShippedProxyCatchAllRule();
            edit(rule);
            rules.Add(rule);
        }

        var removed = ConfigDbHandler.RemoveIranProxyCatchAll(rules);

        await removed.Should().BeEqualTo(0);
        await rules.Count.Should().BeEqualTo(6);
    }

    [Test]
    public async Task CustomRoutingWhiteIran_ShouldNotShipTheProxyCatchAll()
    {
        // Fresh installs get the same rules as updaters after the migration
        var rules = JsonUtils.Deserialize<List<RulesItem>>(EmbedUtils.GetEmbedText(Global.CustomRoutingFileName + "white_iran")) ?? [];

        await (rules.Count > 0).Should().BeTrue();
        await ConfigDbHandler.RemoveIranProxyCatchAll(rules).Should().BeEqualTo(0);
        await rules.Any(t => t.OutboundTag == Global.ProxyTag).Should().BeFalse();
    }

    // Chocolate4U's v2rayN/all_except_ir.json, the rules of the Iran direct rule-set of the Iran template, as downloaded
    // on 2026-09-27
    private const string IranTemplateRules = """
        [{"outboundtag":"direct","ip":["8.8.8.8"],"enabled":true,"remarks":"\u062a\u0628\u062f\u06cc\u0644 \u0646\u0627\u0645 \u062f\u0627\u0645\u0646\u0647 \u0647\u0627\u06cc \u0627\u06cc\u0631\u0627\u0646 - \u0645\u0633\u062a\u0642\u06cc\u0645"},{"outboundtag":"block","port":"443","network":"udp","enabled":true,"remarks":"udp443 - \u0645\u0633\u062f\u0648\u062f"},{"outboundTag":"direct","protocol":["bittorrent"],"enabled":true,"remarks":"\u062a\u0648\u0631\u0646\u062a - \u0645\u0633\u062a\u0642\u06cc\u0645"},{"outboundTag":"block","domain":["geosite:category-ads-all"],"enabled":true,"remarks":"\u062a\u0628\u0644\u06cc\u063a\u0627\u062a - \u0645\u0633\u062f\u0648\u062f"},{"outboundTag":"direct","ip":["geoip:private"],"enabled":true,"remarks":"\u0622\u06cc \u067e\u06cc \u0647\u0627\u06cc \u0645\u062d\u0644\u06cc - \u0645\u0633\u062a\u0642\u06cc\u0645"},{"outboundTag":"direct","domain":["geosite:private"],"enabled":true,"remarks":"\u062f\u0627\u0645\u0646\u0647 \u0647\u0627\u06cc \u0645\u062d\u0644\u06cc - \u0645\u0633\u062a\u0642\u06cc\u0645"},{"outboundTag":"direct","domain":["geosite:ir"],"enabled":true,"remarks":"\u062f\u0627\u0645\u0646\u0647 \u0647\u0627\u06cc \u0627\u06cc\u0631\u0627\u0646 - \u0645\u0633\u062a\u0642\u06cc\u0645"},{"outboundTag":"direct","ip":["geoip:ir"],"enabled":true,"remarks":"\u0622\u06cc \u067e\u06cc \u0647\u0627\u06cc \u0627\u06cc\u0631\u0627\u0646 - \u0645\u0633\u062a\u0642\u06cc\u0645"},{"port":"0-65535","outboundTag":"proxy","enabled":true,"remarks":"\u0633\u0627\u06cc\u0631 \u0645\u0648\u0627\u0631\u062f - \u067e\u0631\u0627\u06a9\u0633\u06cc"}]
        """;

    private static RoutingItem IranTemplateRuleSet() => new()
    {
        Remarks = ConfigDbHandler.IranDirectRoutingRemarks,
        DomainStrategy = Global.IPOnDemand,
        RuleSet = IranTemplateRules,
    };

    private static List<RulesItem> PattNIranRules() =>
        JsonUtils.Deserialize<List<RulesItem>>(EmbedUtils.GetEmbedText(Global.CustomRoutingFileName + "white_iran")) ?? [];

    private static string Describe(IEnumerable<RulesItem> rules) => string.Join("\n", rules.Select(t =>
        $"{t.OutboundTag}|{t.Port}|{t.Network}|{string.Join(",", t.Domain ?? [])}|{string.Join(",", t.Ip ?? [])}|{string.Join(",", t.Protocol ?? [])}|{t.Remarks}"));

    [Test]
    public async Task CleanIranDirectRouting_ShouldTurnTheIranTemplateIntoPattNRules()
    {
        var item = IranTemplateRuleSet();

        var changed = ConfigDbHandler.CleanIranDirectRouting(item);

        await changed.Should().BeTrue();
        await item.DomainStrategy.Should().BeEqualTo(string.Empty);
        await item.RuleNum.Should().BeEqualTo(PattNIranRules().Count);
        await Describe(JsonUtils.Deserialize<List<RulesItem>>(item.RuleSet) ?? []).Should().BeEqualTo(Describe(PattNIranRules()));
        await ConfigDbHandler.CleanIranDirectRouting(item).Should().BeFalse();
    }

    [Test]
    public async Task CleanIranDirectRoutings_ShouldCleanEveryIranDirectRuleSetOnly()
    {
        // PattN's own rule-set, the Iran template's copy that "Import Rules" adds after it under the same name, and the
        // Iran global rule-set, whose own catch-all stays
        var pattn = new RoutingItem
        {
            Remarks = ConfigDbHandler.IranDirectRoutingRemarks,
            RuleSet = JsonUtils.Serialize(PattNIranRules(), false),
        };
        var imported = IranTemplateRuleSet();
        var global = new RoutingItem
        {
            Remarks = "IR-global",
            DomainStrategy = Global.IPOnDemand,
            RuleSet = IranTemplateRules,
        };

        var changed = ConfigDbHandler.CleanIranDirectRoutings([pattn, imported, global]);

        await changed.Count.Should().BeEqualTo(1);
        await ReferenceEquals(changed[0], imported).Should().BeTrue();
        await Describe(JsonUtils.Deserialize<List<RulesItem>>(imported.RuleSet) ?? []).Should().BeEqualTo(Describe(PattNIranRules()));
        await global.DomainStrategy.Should().BeEqualTo(Global.IPOnDemand);
        await global.RuleSet.Should().BeEqualTo(IranTemplateRules);
    }
}
