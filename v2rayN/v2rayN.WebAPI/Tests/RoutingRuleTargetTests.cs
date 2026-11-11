using ServiceLib;
using ServiceLib.Common;
using ServiceLib.Enums;
using ServiceLib.Helper;
using ServiceLib.Manager;
using ServiceLib.Models.Entities;
using ServiceLib.Resx;
using v2rayN.WebAPI.Contracts;
using v2rayN.WebAPI.Services;

namespace v2rayN.WebAPI.Tests;

// PattN (N2, PattNG RoutingEditViewModel): the API refuses a routing rule the desktop's rule editor refuses, one whose
// target names no profile, or a name several profiles have, with code routing_rule_target_invalid and PattNG's words as
// its detail; a rule the save keeps as it is stored is left alone, as the desktop's routing list saves it.
[NotInParallel]
public class RoutingRuleTargetTests
{
    private static RulesItem Rule(string? id, string target, bool enabled = true, ERuleType? ruleType = null) => new()
    {
        Id = id!,
        Remarks = "rule",
        OutboundTag = target,
        Enabled = enabled,
        RuleType = ruleType,
        Domain = ["example.com"],
    };

    private static RoutingItem Stored(params RulesItem[] rules) => new()
    {
        Id = "stored",
        Remarks = "stored",
        RuleSet = JsonUtils.Serialize(rules.ToList(), false),
    };

    private static async Task<string?> DetailOf(OperationView? refusal)
    {
        await refusal.Should().NotBeNull();
        await refusal!.Success.Should().BeFalse();
        await refusal.Code.Should().BeEqualTo("routing_rule_target_invalid");
        await refusal.MessageKey.Should().BeEqualTo(ApiMessageKeys.RoutingRulesInvalid);
        var data = System.Text.Json.JsonSerializer.SerializeToElement(refusal.Data);
        return data.GetProperty("detail").GetString();
    }

    [Test]
    public async Task ARuleTheSaveAddsOrChangesMustNameOneProfile()
    {
        var suffix = Guid.NewGuid().ToString("N");
        var found = new ProfileItem { IndexId = $"found-{suffix}", ConfigType = EConfigType.VLESS, CoreType = ECoreType.Xray, Remarks = $"found-{suffix}" };
        var shared = $"shared-{suffix}";
        var twins = new[]
        {
            new ProfileItem { IndexId = $"twin-a-{suffix}", ConfigType = EConfigType.VLESS, CoreType = ECoreType.Xray, Remarks = shared },
            new ProfileItem { IndexId = $"twin-b-{suffix}", ConfigType = EConfigType.Trojan, CoreType = ECoreType.Xray, Remarks = $"{shared} " },
        };
        var missing = $"missing-{suffix}";
        SQLiteHelper.Instance.CreateTable<ProfileItem>();
        try
        {
            foreach (var profile in twins.Append(found))
            {
                await SQLiteHelper.Instance.ReplaceAsync(profile);
            }
            // A rule stored before its profile was renamed away.
            var stored = Stored(Rule("kept", missing));

            await (await DetailOf(await V2rayRuntime.RoutingRuleTargetRefusalAsync([Rule(null, missing)], stored)))
                .Should().BeEqualTo(string.Format(ResUI.MsgRoutingRuleTargetNotFound, missing));
            await (await DetailOf(await V2rayRuntime.RoutingRuleTargetRefusalAsync([Rule("new", $" {shared}")], stored)))
                .Should().BeEqualTo(string.Format(ResUI.MsgRoutingRuleTargetDuplicate, shared));
            // Changed: another target, or turned on.
            await (await DetailOf(await V2rayRuntime.RoutingRuleTargetRefusalAsync([Rule("kept", $"{missing}-2")], stored)))
                .Should().BeEqualTo(string.Format(ResUI.MsgRoutingRuleTargetNotFound, $"{missing}-2"));
            await DetailOf(await V2rayRuntime.RoutingRuleTargetRefusalAsync([Rule("off", missing)], Stored(Rule("off", missing, enabled: false))));

            // Kept as it is stored, or what the start takes.
            await (await V2rayRuntime.RoutingRuleTargetRefusalAsync([Rule("kept", missing)], stored)).Should().BeNull();
            foreach (var rule in new[]
                     {
                         Rule("one", $" {found.Remarks} "),
                         Rule("proxy", Global.ProxyTag),
                         Rule("direct", Global.DirectTag),
                         Rule("block", Global.BlockTag),
                         Rule("none", string.Empty),
                         Rule("disabled", missing, enabled: false),
                         Rule("dns", missing, ruleType: ERuleType.DNS),
                     })
            {
                await (await V2rayRuntime.RoutingRuleTargetRefusalAsync([rule], stored)).Should().BeNull().Because(rule.Id);
            }
        }
        finally
        {
            foreach (var profile in twins.Append(found))
            {
                await SQLiteHelper.Instance.DeleteAsync(profile);
            }
        }
    }

    [Test]
    public async Task TheSaveOfTheRulesIsRefusedBeforeAnythingIsApplied()
    {
        // The runtime has none of its services: the refusal comes before the save would reach them.
        SQLiteHelper.Instance.CreateTable<ProfileItem>();
        SQLiteHelper.Instance.CreateTable<RoutingItem>();
        var missing = $"missing-{Guid.NewGuid():N}";
        var routing = new RoutingItem
        {
            Id = $"routing-{Guid.NewGuid():N}",
            Remarks = "routing",
            Url = string.Empty,
            RuleSet = JsonUtils.Serialize(new List<RulesItem> { Rule("kept", Global.DirectTag) }, false),
        };
        var runtime = new V2rayRuntime(null!, null!, null!, null!, null!);
        await SQLiteHelper.Instance.ReplaceAsync(routing);
        try
        {
            var refusal = await runtime.SaveRoutingRulesAsync(routing.Id, [Rule(null, missing)]);

            await (await DetailOf(refusal)).Should().BeEqualTo(string.Format(ResUI.MsgRoutingRuleTargetNotFound, missing));
            await (await AppManager.Instance.GetRoutingItem(routing.Id))!.RuleSet.Should().BeEqualTo(routing.RuleSet);
        }
        finally
        {
            await SQLiteHelper.Instance.DeleteAsync(routing);
        }
    }

    [Test]
    public async Task RulesForARoutingProfileThatDoesNotExistAreToldThatFirst()
    {
        // Not that a rule's target names no profile: the routing profile the rules are for is not there.
        SQLiteHelper.Instance.CreateTable<ProfileItem>();
        SQLiteHelper.Instance.CreateTable<RoutingItem>();
        var routingId = $"routing-{Guid.NewGuid():N}";
        var runtime = new V2rayRuntime(null!, null!, null!, null!, null!);

        var refusal = await runtime.SaveRoutingRulesAsync(routingId, [Rule(null, $"missing-{Guid.NewGuid():N}")]);

        await refusal.Success.Should().BeFalse();
        await refusal.Code.Should().BeEqualTo("routing_profile_not_found");
        await refusal.MessageKey.Should().BeEqualTo(ApiMessageKeys.RoutingProfileNotFound);
        await (await AppManager.Instance.GetRoutingItem(routingId)).Should().BeNull();
    }

    [Test]
    public async Task TheSaveStoresTheRulesItIsGiven()
    {
        // The API hands the rules on as an IReadOnlyList, which the source-generated JSON context does not know: they
        // were serialized to nothing, and the save failed.
        SQLiteHelper.Instance.CreateTable<RoutingItem>();
        var routing = new RoutingItem
        {
            Id = $"routing-{Guid.NewGuid():N}",
            Remarks = "routing",
            Url = string.Empty,
            RuleSet = JsonUtils.Serialize(new List<RulesItem> { Rule("old", Global.DirectTag) }, false),
        };
        await SQLiteHelper.Instance.ReplaceAsync(routing);
        try
        {
            IReadOnlyList<RulesItem> rules = [Rule(null, Global.ProxyTag), Rule(null, Global.BlockTag)];

            await (await V2rayRuntime.SaveRoutingRulesLockedAsync(routing.Id, rules)).Should().BeEqualTo(0);

            var stored = await AppManager.Instance.GetRoutingItem(routing.Id);
            await stored!.RuleNum.Should().BeEqualTo(2);
            var storedRules = JsonUtils.Deserialize<List<RulesItem>>(stored.RuleSet)!;
            await storedRules.Select(rule => rule.OutboundTag).SequenceEqual([Global.ProxyTag, Global.BlockTag]).Should().BeTrue();
        }
        finally
        {
            await SQLiteHelper.Instance.DeleteAsync(routing);
        }
    }
}
