using NLog;
using NLog.Config;
using NLog.Targets;
using TUnit.Assertions.Enums;
using static ServiceLib.Tests.CoreConfig.V2ray.AetherConfigTests;

namespace ServiceLib.Tests.CoreConfig.Context;

/// <summary>
/// PattN (PattNG CoreConfigContextBuilder.kt resolveOutbound): the profile a routing rule sends to runs inside its
/// subscription's previous/next chain, as the main profile does, whatever its type; upstream v2rayN resolves it alone.
/// The chain is stored entry hop first (previous, profile, next), and built from the exit hop, which the rule sends to.
/// A target that names no profile, a name several have, or a profile that cannot be built refuses the session (E2), as
/// PattNG refuses it; a latency test's context (refuseRuleTargets false) sends such a rule to the proxy, as upstream does.
/// Each test builds the whole context (CoreConfigContextBuilder.Build) with a routing of its own made the active one in
/// the test database, and gives the active one back after; every name is new to the test, as the database is shared.
/// </summary>
[NotInParallel]
public class RuleTargetChainTests
{
    private const string RuleName = "rule to a subscription profile";
    private const string RuleDomain = "rule.example.com";

    private static string NewName(string prefix)
    {
        return $"{prefix}-{Guid.NewGuid():N}";
    }

    private static async Task Store(params ProfileItem[] profiles)
    {
        SQLiteHelper.Instance.CreateTable<ProfileItem>();
        foreach (var profile in profiles)
        {
            await SQLiteHelper.Instance.ReplaceAsync(profile);
        }
    }

    /// <summary>A stored subscription with the previous and the next profile it names; its id.</summary>
    private static async Task<string> Subscription(string? prev, string? next)
    {
        SQLiteHelper.Instance.CreateTable<SubItem>();
        var id = NewName("sub");
        await SQLiteHelper.Instance.ReplaceAsync(new SubItem { Id = id, Remarks = "chained", Url = string.Empty, PrevProfile = prev, NextProfile = next });
        return id;
    }

    private static ProfileItem In(string subId, ProfileItem profile)
    {
        profile.Subid = subId;
        return profile;
    }

    /// <summary>The hops of a subscription's chain around <paramref name="profile" />, entry first, as it is stored.</summary>
    private static ProfileItem[] Hops(ProfileItem? prev, ProfileItem profile, ProfileItem? next)
    {
        return new[] { prev, profile, next }.OfType<ProfileItem>().ToArray();
    }

    private static ProfileItem XrayHop(string prefix, string address)
    {
        return Vless(NewName(prefix), NewName(prefix), address);
    }

    private static ProfileItem SingboxHop(string prefix, string address)
    {
        var hop = CoreConfigTestFactory.CreateSocksNode(ECoreType.sing_box, NewName(prefix), NewName(prefix));
        hop.Address = address;
        return hop;
    }

    /// <summary>A TUIC profile, which Xray cannot run.</summary>
    private static ProfileItem TuicHop(string prefix, string address)
    {
        return new ProfileItem
        {
            IndexId = NewName(prefix),
            ConfigType = EConfigType.TUIC,
            CoreType = ECoreType.sing_box,
            Remarks = NewName(prefix),
            Address = address,
            Port = 443,
            Username = Guid.NewGuid().ToString(),
            Password = "pass",
            Network = nameof(ETransport.raw),
            StreamSecurity = Global.StreamSecurity,
            Subid = string.Empty,
        };
    }

    /// <summary>A VLESS profile over xhttp, which sing-box cannot run.</summary>
    private static ProfileItem XhttpHop(string prefix, string address)
    {
        var hop = XrayHop(prefix, address);
        hop.Network = nameof(ETransport.xhttp);
        return hop;
    }

    /// <summary>The warning of a rule that goes to the proxy because the chain of its subscription lost <paramref name="lost" />.</summary>
    private static string ChainLost(ProfileItem target, ProfileItem lost)
    {
        return string.Format(ResUI.MsgRoutingRuleOutboundNodeError, RuleName, target.Remarks,
            string.Format(ResUI.MsgRoutingRuleChainHopNotBuilt, lost.Remarks));
    }

    /// <summary>
    /// E2: the errors that refuse a context for a rule to <paramref name="target" />, which could not be built for
    /// <paramref name="reasons" />: PattNG's message, and why after it.
    /// </summary>
    private static string[] Unbuilt(ProfileItem target, params string[] reasons)
    {
        return [string.Format(ResUI.MsgRoutingRuleTargetUnbuilt, target.Remarks), .. reasons];
    }

    /// <summary>E2: the context of a session refused for its rule, with exactly <paramref name="errors" />, and nothing of the rule's target left in it.</summary>
    private static async Task AssertRefused(CoreConfigContextBuilderResult built, string[] errors, params ProfileItem[] notLeft)
    {
        await built.Success.Should().BeFalse();
        await built.ValidatorResult.Errors.Should().BeEquivalentTo(errors, CollectionOrdering.Matching);
        await AssertNoneRegistered(built.Context, notLeft);
        await built.Context.AllProxiesMap.Keys.Any(key => key.StartsWith("remark:", StringComparison.Ordinal)).Should().BeFalse();
    }

    /// <summary>Nothing of <paramref name="profiles" />, nor a chain of a subscription, stayed in the context.</summary>
    private static async Task AssertNoneRegistered(CoreConfigContext context, params ProfileItem[] profiles)
    {
        foreach (var profile in profiles)
        {
            await context.AllProxiesMap.Should().NotContainKey(profile.IndexId);
        }
        await context.AllProxiesMap.Keys.Any(key => key.StartsWith("inner-", StringComparison.Ordinal)).Should().BeFalse();
    }

    /// <summary>
    /// The context Build makes for <paramref name="main" /> while the active routing has one rule, sending
    /// <see cref="RuleDomain" /> to the profile named <paramref name="target" />.
    /// </summary>
    private static Task<CoreConfigContextBuilderResult> BuildWithRuleTo(Config config, ProfileItem main, string target, bool refuseRuleTargets = true)
    {
        return WithRuleTo(target, () => CoreConfigContextBuilder.Build(config, main, refuseRuleTargets: refuseRuleTargets));
    }

    /// <summary>What <paramref name="build" /> gives while the active routing has one rule, sending <see cref="RuleDomain" /> to <paramref name="target" />.</summary>
    private static Task<T> WithRuleTo<T>(string target, Func<Task<T>> build)
    {
        return WithRules([Rule(target)], build);
    }

    /// <summary>A routing rule sending <see cref="RuleDomain" /> to <paramref name="target" />.</summary>
    private static RulesItem Rule(string target, ERuleType type = ERuleType.Routing, string remarks = RuleName)
    {
        return new RulesItem
        {
            Id = NewName("rule"),
            Remarks = remarks,
            Enabled = true,
            RuleType = type,
            OutboundTag = target,
            Domain = [$"full:{RuleDomain}"],
        };
    }

    /// <summary>What <paramref name="build" /> gives while the active routing has <paramref name="rules" />.</summary>
    internal static async Task<T> WithRules<T>(List<RulesItem> rules, Func<Task<T>> build)
    {
        // The tables Build reads, which the app's start makes and a test can be the first to use: the rules' targets are
        // looked up among the profiles though the test stores none.
        SQLiteHelper.Instance.CreateTable<ProfileItem>();
        SQLiteHelper.Instance.CreateTable<FullConfigTemplateItem>();
        SQLiteHelper.Instance.CreateTable<DNSItem>();
        SQLiteHelper.Instance.CreateTable<RoutingItem>();
        var wasActive = (await ConfigDbQuery.RoutingItems() ?? []).Where(routing => routing.IsActive).ToList();
        var routing = new RoutingItem
        {
            Id = NewName("routing"),
            Remarks = "rule targets",
            RuleSet = JsonUtils.Serialize(rules),
            DomainStrategy = Global.AsIs,
            DomainStrategy4Singbox = string.Empty,
            IsActive = true,
        };
        wasActive.ForEach(other => other.IsActive = false);
        await SQLiteHelper.Instance.UpdateAllAsync(wasActive);
        await SQLiteHelper.Instance.ReplaceAsync(routing);
        try
        {
            return await build();
        }
        finally
        {
            await SQLiteHelper.Instance.DeleteAsync(routing);
            wasActive.ForEach(other => other.IsActive = true);
            await SQLiteHelper.Instance.UpdateAllAsync(wasActive);
        }
    }

    private static async Task<CoreConfigContext> Built(Config config, ProfileItem main, string target)
    {
        var (context, result) = await BuildWithRuleTo(config, main, target);
        await result.Success.Should().BeTrue().Because(string.Join(" | ", result.Errors));
        return context;
    }

    /// <summary>The profile the rule to <paramref name="target" /> resolved to, as the routing services read it.</summary>
    private static ProfileItem? RuleNode(CoreConfigContext context, ProfileItem target)
    {
        return context.AllProxiesMap.GetValueOrDefault($"remark:{target.Remarks}");
    }

    private static string RuleTag(ProfileItem ruleNode)
    {
        return $"{ruleNode.IndexId}-{Global.ProxyTag}-{ruleNode.Remarks}";
    }

    /// <summary>The rule's node is the chain of <paramref name="storedEntryFirst" />, in their order.</summary>
    private static async Task<ProfileItem> AssertChain(CoreConfigContext context, ProfileItem target, params ProfileItem[] storedEntryFirst)
    {
        var chain = RuleNode(context, target);
        await (chain?.ConfigType).Should().BeEqualTo(EConfigType.ProxyChain);
        await chain!.Remarks.Should().BeEqualTo(target.Remarks);
        await chain.GetProtocolExtra().ChildItems.Should().BeEqualTo(string.Join(",", storedEntryFirst.Select(hop => hop.IndexId)));
        return chain;
    }

    private static string HopTag(string tag, List<ProfileItem> exitFirst, int i)
    {
        return i == 0 ? tag : $"chain-{tag}-{i}-{exitFirst[i].Remarks}";
    }

    /// <summary>Xray dials the rule's chain from its exit hop, tagged as the rule's outbound, to its entry hop.</summary>
    private static async Task AssertXrayChain(CoreConfigContext context, ProfileItem chain, params ProfileItem[] storedEntryFirst)
    {
        var generated = new CoreConfigV2rayService(context).GenerateClientConfigContent();
        await generated.Success.Should().BeTrue().Because(generated.Msg ?? string.Empty);
        var config = JsonUtils.Deserialize<V2rayConfig>(generated.Data!.ToString())!;
        var tag = RuleTag(chain);
        var exitFirst = storedEntryFirst.AsEnumerable().Reverse().ToList();
        for (var i = 0; i < exitFirst.Count; i++)
        {
            var outbound = config.outbounds.Single(outbound => outbound.tag == HopTag(tag, exitFirst, i));
            await outbound.settings.address!.ToString().Should().BeEqualTo(exitFirst[i].Address);
            var dialer = i + 1 < exitFirst.Count ? HopTag(tag, exitFirst, i + 1) : null;
            await (outbound.streamSettings?.sockopt?.dialerProxy).Should().BeEqualTo(dialer);
        }
        await config.outbounds.Count(outbound => outbound.tag.Contains(tag, StringComparison.Ordinal)).Should().BeEqualTo(exitFirst.Count);
        await config.routing.rules.Any(rule => rule.domain?.Contains($"full:{RuleDomain}") == true && rule.outboundTag == tag).Should().BeTrue();
    }

    // ---- Xray

    [Test]
    [Arguments(true, false)]
    [Arguments(false, true)]
    [Arguments(true, true)]
    public async Task ARuleToAProfileOfASubscriptionWithNeighboursRunsInsideTheirChain(bool withPrev, bool withNext)
    {
        var prev = XrayHop("prev", "198.51.100.1");
        var next = XrayHop("next", "198.51.100.3");
        var subId = await Subscription(withPrev ? prev.Remarks : null, withNext ? next.Remarks : null);
        var target = In(subId, XrayHop("target", "198.51.100.2"));
        await Store(prev, next, target);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));

        var context = await Built(NewConfig(), main, target.Remarks);

        var hops = Hops(withPrev ? prev : null, target, withNext ? next : null);
        var chain = await AssertChain(context, target, hops);
        await AssertXrayChain(context, chain, hops);
        // The main profile, outside the subscription, stays alone.
        await context.Node.IndexId.Should().BeEqualTo(main.IndexId);
    }

    [Test]
    public async Task ARuleToAProfileOfASubscriptionWithoutNeighboursIsUnchanged()
    {
        var subId = await Subscription(null, null);
        var target = In(subId, XrayHop("target", "198.51.100.2"));
        await Store(target);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));

        var context = await Built(NewConfig(), main, target.Remarks);

        await (RuleNode(context, target)?.IndexId).Should().BeEqualTo(target.IndexId);
        var generated = new CoreConfigV2rayService(context).GenerateClientConfigContent();
        await generated.Success.Should().BeTrue().Because(generated.Msg ?? string.Empty);
        var config = JsonUtils.Deserialize<V2rayConfig>(generated.Data!.ToString())!;
        var outbound = config.outbounds.Single(outbound => outbound.tag == RuleTag(target));
        await outbound.settings.address!.ToString().Should().BeEqualTo(target.Address);
        await (outbound.streamSettings?.sockopt?.dialerProxy).Should().BeNull();
    }

    // N1: the main profile's way (BuildSubscriptionChainNodeAsync): a name of the subscription that no profile has, or
    // several have, refuses the chain, never left out nor taken for the first of them; the session is refused for the rule
    // (E2), and a test's context sends the rule to the proxy, nothing of the chain left in it.
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ARulesSubscriptionNamingAProfileNoneOrSeveralHaveRefusesTheSessionAsForTheMainProfile(bool several)
    {
        var named = NewName("named");
        var next = XrayHop("next", "198.51.100.3");
        // Two profiles of the name, the spaces around it aside, or none.
        ProfileItem[] twins = several ? [Vless(NewName("twin"), named, "198.51.100.5"), Vless(NewName("twin"), $" {named} ", "198.51.100.6")] : [];
        var alone = In(await Subscription(named, null), XrayHop("alone", "198.51.100.2"));
        var withNext = In(await Subscription(named, next.Remarks), XrayHop("with-next", "198.51.100.4"));
        await Store([next, alone, withNext, .. twins]);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));
        var problem = string.Format(several ? ResUI.MsgRoutingRuleTargetDuplicate : ResUI.MsgRoutingRuleTargetNotFound, named);

        foreach (var target in new[] { alone, withNext })
        {
            await AssertRefused(await BuildWithRuleTo(NewConfig(), main, target.Remarks), Unbuilt(target, problem), [target, next, .. twins]);

            var (context, result) = await BuildWithRuleTo(NewConfig(), main, target.Remarks, refuseRuleTargets: false);
            await result.Success.Should().BeTrue();
            await result.Warnings.Should().Contain(string.Format(ResUI.MsgRoutingRuleOutboundNodeError, RuleName, target.Remarks, problem));
            await RuleNode(context, target).Should().BeNull();
            await AssertNoneRegistered(context, [target, next, .. twins]);
        }
    }

    // D1-R1: the traversal of the chain leaves out a hop that fails its checks, and without the profile the rule names the
    // rule would leave by its neighbours alone; the session is refused (E2), and a test's context sends the rule to the
    // proxy, as when upstream resolves the profile alone.
    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task ARuleToAProfileItsCoreCannotRunRefusesTheSessionAndNeverGoesThroughItsNeighbours(bool withNext)
    {
        var prev = XrayHop("prev", "198.51.100.41");
        var next = XrayHop("next", "198.51.100.43");
        var target = In(await Subscription(prev.Remarks, withNext ? next.Remarks : null), TuicHop("tuic", "198.51.100.42"));
        await Store(prev, next, target);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));

        var session = await BuildWithRuleTo(NewConfig(), main, target.Remarks);
        await AssertRefused(session, Unbuilt(target, string.Format(ResUI.MsgRoutingRuleChainHopNotBuilt, target.Remarks)), prev, next, target);

        var (context, result) = await BuildWithRuleTo(NewConfig(), main, target.Remarks, refuseRuleTargets: false);

        await result.Success.Should().BeTrue();
        await result.Warnings.Should().Contain(ChainLost(target, target));
        await RuleNode(context, target).Should().BeNull();
        await AssertNoneRegistered(context, prev, next, target);
        var g = await Succeeds(context);
        await g.Config.outbounds.Any(outbound => outbound.settings?.address?.ToString() is "198.51.100.41" or "198.51.100.43").Should().BeFalse();
        await g.Config.routing.rules.Any(rule => rule.domain?.Contains($"full:{RuleDomain}") == true && rule.outboundTag == Global.ProxyTag).Should().BeTrue();
    }

    // D1-R3: the routing services read the strategy of the rule's node, the chain; the group's own one counts.
    [Test]
    public async Task APolicyGroupARuleSendsToKeepsItsStrategyInsideItsSubscriptionsChain()
    {
        var prev = XrayHop("prev", "198.51.100.71");
        var first = XrayHop("first", "198.51.100.72");
        var second = XrayHop("second", "198.51.100.73");
        var group = CoreConfigTestFactory.CreatePolicyGroupNode(ECoreType.Xray, NewName("group"), NewName("group"), [first.IndexId, second.IndexId]);
        group.SetProtocolExtra(group.GetProtocolExtra() with { MultipleLoad = EMultipleLoad.Random });
        group = In(await Subscription(prev.Remarks, null), group);
        await Store(prev, first, second, group);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));

        var context = await Built(NewConfig(), main, group.Remarks);

        var chain = await AssertChain(context, group, prev, group);
        var g = await Succeeds(context);
        var tag = RuleTag(chain);
        var balancer = g.Config.routing.balancers?.SingleOrDefault(balancer => balancer.tag == $"{tag}{Global.BalancerTagSuffix}");
        await (balancer?.strategy?.type).Should().BeEqualTo("random");
        // A random balancer measures nothing.
        await (g.Config.observatory?.subjectSelector?.Contains(tag) ?? false).Should().BeFalse();
        await (g.Config.burstObservatory?.subjectSelector?.Contains(tag) ?? false).Should().BeFalse();
        await g.Config.routing.rules.Any(rule => rule.domain?.Contains($"full:{RuleDomain}") == true && rule.balancerTag == balancer!.tag).Should().BeTrue();
    }

    // ---- sing-box in front of Xray (the legacy TUN)

    private static Config LegacyTunConfig()
    {
        return NewConfig(config =>
        {
            config.TunModeItem.EnableTun = true;
            config.TunModeItem.EnableLegacyProtect = true;
        });
    }

    // D1-R1, D1-R2: Xray, behind sing-box, routes the same rule with the whole chain, so sing-box sends the rule to it
    // rather than the way it can build without the profile itself or without a neighbour.
    [Test]
    public async Task InFrontOfXraySingBoxSendsARuleWhoseChainItCannotBuildWholeToXray()
    {
        var prev = XrayHop("prev", "198.51.100.61");
        var next = XrayHop("next", "198.51.100.63");
        var xhttpTarget = In(await Subscription(prev.Remarks, next.Remarks), XhttpHop("xhttp", "198.51.100.62"));
        var xhttpPrev = XhttpHop("xhttp-prev", "198.51.100.64");
        var rawTarget = In(await Subscription(xhttpPrev.Remarks, null), XrayHop("raw", "198.51.100.65"));
        await Store(prev, next, xhttpTarget, xhttpPrev, rawTarget);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));

        foreach (var (target, hops, lost) in new[]
                 {
                     (xhttpTarget, Hops(prev, xhttpTarget, next), xhttpTarget),
                     (rawTarget, Hops(xhttpPrev, rawTarget, null), xhttpPrev),
                 })
        {
            var built = await WithRuleTo(target.Remarks, () => CoreConfigContextBuilder.BuildAll(LegacyTunConfig(), main));

            await built.Success.Should().BeTrue();
            var front = built.PreSocksResult!;
            await front.ValidatorResult.Warnings.Should().Contain(ChainLost(target, lost));
            await RuleNode(front.Context, target).Should().BeNull();
            await AssertNoneRegistered(front.Context, hops);
            var behind = built.MainResult.Context;
            var chain = await AssertChain(behind, target, hops);
            await AssertXrayChain(behind, chain, hops);
        }
    }

    // Without a core behind it, a chain that lost a neighbour still carries the rule, as the main profile's does.
    [Test]
    public async Task WithoutACoreBehindARuleKeepsTheChainOfTheHopsItsCoreCanRun()
    {
        var tuicPrev = TuicHop("tuic-prev", "198.51.100.66");
        var target = In(await Subscription(tuicPrev.Remarks, null), XrayHop("raw", "198.51.100.67"));
        await Store(tuicPrev, target);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));

        var context = await Built(NewConfig(), main, target.Remarks);

        var chain = RuleNode(context, target);
        await (chain?.ConfigType).Should().BeEqualTo(EConfigType.ProxyChain);
        await chain!.GetProtocolExtra().ChildItems.Should().BeEqualTo(target.IndexId);
    }

    // ---- sing-box

    [Test]
    [Arguments(true, false)]
    [Arguments(false, true)]
    [Arguments(true, true)]
    public async Task UnderSingBoxARuleToAProfileOfASubscriptionWithNeighboursRunsInsideTheirChain(bool withPrev, bool withNext)
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.sing_box);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var prev = SingboxHop("prev", "198.51.100.11");
        var next = SingboxHop("next", "198.51.100.13");
        var subId = await Subscription(withPrev ? prev.Remarks : null, withNext ? next.Remarks : null);
        var target = In(subId, SingboxHop("target", "198.51.100.12"));
        await Store(prev, next, target);
        var main = CoreConfigTestFactory.CreateSocksNode(ECoreType.sing_box, NewName("main"), NewName("main"));

        var context = await Built(config, main, target.Remarks);

        var hops = Hops(withPrev ? prev : null, target, withNext ? next : null);
        var chain = await AssertChain(context, target, hops);
        var generated = new CoreConfigSingboxService(context).GenerateClientConfigContent();
        await generated.Success.Should().BeTrue().Because(generated.Msg ?? string.Empty);
        var singbox = JsonUtils.Deserialize<SingboxConfig>(generated.Data!.ToString())!;
        var tag = RuleTag(chain);
        var exitFirst = hops.AsEnumerable().Reverse().ToList();
        for (var i = 0; i < exitFirst.Count; i++)
        {
            var outbound = singbox.outbounds.Single(outbound => outbound.tag == HopTag(tag, exitFirst, i));
            await outbound.server.Should().BeEqualTo(exitFirst[i].Address);
            await outbound.detour.Should().BeEqualTo(i + 1 < exitFirst.Count ? HopTag(tag, exitFirst, i + 1) : null);
        }
        await singbox.route.rules.Any(rule => rule.domain?.Contains(RuleDomain) == true && rule.outbound == tag).Should().BeTrue();
    }

    // D1-R1 under sing-box: a profile over xhttp, which sing-box cannot run.
    [Test]
    public async Task UnderSingBoxARuleToAProfileItCannotRunRefusesTheSessionAndNeverGoesThroughItsNeighbours()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.sing_box);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var prev = SingboxHop("prev", "198.51.100.51");
        var next = SingboxHop("next", "198.51.100.53");
        var target = In(await Subscription(prev.Remarks, next.Remarks), XhttpHop("xhttp", "198.51.100.52"));
        await Store(prev, next, target);
        var main = CoreConfigTestFactory.CreateSocksNode(ECoreType.sing_box, NewName("main"), NewName("main"));

        var session = await BuildWithRuleTo(config, main, target.Remarks);
        await AssertRefused(session, Unbuilt(target, string.Format(ResUI.MsgRoutingRuleChainHopNotBuilt, target.Remarks)), prev, next, target);

        var (context, result) = await BuildWithRuleTo(config, main, target.Remarks, refuseRuleTargets: false);

        await result.Success.Should().BeTrue();
        await result.Warnings.Should().Contain(ChainLost(target, target));
        await RuleNode(context, target).Should().BeNull();
        await AssertNoneRegistered(context, prev, next, target);
        var generated = new CoreConfigSingboxService(context).GenerateClientConfigContent();
        await generated.Success.Should().BeTrue().Because(generated.Msg ?? string.Empty);
        var singbox = JsonUtils.Deserialize<SingboxConfig>(generated.Data!.ToString())!;
        await singbox.outbounds.Any(outbound => outbound.server is "198.51.100.51" or "198.51.100.53").Should().BeFalse();
        await singbox.route.rules.Any(rule => rule.domain?.Contains(RuleDomain) == true && rule.outbound == Global.ProxyTag).Should().BeTrue();
    }

    // critique 4: sing-box runs no Aether profile, so the chain would run without WARP; the session is refused (E2), and a
    // test's context sends the rule to the proxy, as when sing-box is told to run the Aether profile alone, and never
    // through the previous profile alone.
    [Test]
    public async Task UnderSingBoxARuleToAnAetherProfileOfAChainingSubscriptionRefusesTheSession()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.sing_box);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var prev = SingboxHop("prev", "198.51.100.11");
        var warp = In(await Subscription(prev.Remarks, null), Warp(NewName("warp"), NewName("WARP")));
        await Store(prev, warp);
        var main = CoreConfigTestFactory.CreateSocksNode(ECoreType.sing_box, NewName("main"), NewName("main"));
        var refusal = string.Format(ResUI.MsgAetherChainHopDropped, warp.Remarks, warp.Remarks);

        var session = await BuildWithRuleTo(config, main, warp.Remarks);
        await session.Success.Should().BeFalse();
        // The refusal, and why after it: the chain's, beside sing-box's own word on the Aether profile.
        await session.ValidatorResult.Errors.First().Should().BeEqualTo(Unbuilt(warp)[0]);
        await session.ValidatorResult.Errors.Should().Contain(refusal);
        await AssertNoneRegistered(session.Context, prev, warp);

        var (context, result) = await BuildWithRuleTo(config, main, warp.Remarks, refuseRuleTargets: false);

        await result.Success.Should().BeTrue();
        await result.Warnings.Should().Contain(string.Format(ResUI.MsgRoutingRuleOutboundNodeError, RuleName, warp.Remarks, refusal));
        await RuleNode(context, warp).Should().BeNull();
        var generated = new CoreConfigSingboxService(context).GenerateClientConfigContent();
        await generated.Success.Should().BeTrue().Because(generated.Msg ?? string.Empty);
        var singbox = JsonUtils.Deserialize<SingboxConfig>(generated.Data!.ToString())!;
        await singbox.outbounds.Any(outbound => outbound.server == prev.Address).Should().BeFalse();
        await singbox.route.rules.Any(rule => rule.domain?.Contains(RuleDomain) == true && rule.outbound == Global.ProxyTag).Should().BeTrue();
    }

    // ---- Aether

    [Test]
    public async Task ARuleToAnAetherProfileOfASubscriptionWithAPreviousProfileExitsThroughIt()
    {
        // Design 2.8, rows 5 and 6: the core dials out through the hop on the Aether hop's entry side, the exit-node.
        var prev = XrayHop("prev", "198.51.100.21");
        var warp = In(await Subscription(prev.Remarks, null), Warp(NewName("warp"), NewName("WARP")));
        await Store(prev, warp);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));

        var context = await Built(NewConfig(), main, warp.Remarks);

        var chain = await AssertChain(context, warp, prev, warp);
        var g = await Succeeds(context);
        var ruleOutbound = g.Outbound(RuleTag(chain));
        await ruleOutbound.protocol.Should().BeEqualTo("socks");
        await ruleOutbound.settings.address!.ToString().Should().BeEqualTo(Global.Loopback);
        await ruleOutbound.settings.port.Should().BeEqualTo(AetherPorts.DefaultListenPort);
        await (ruleOutbound.streamSettings?.sockopt?.dialerProxy).Should().BeNull();
        var exitNode = g.Outbound(Global.AetherExitNodeTag);
        await exitNode.settings.address!.ToString().Should().BeEqualTo(prev.Address);
        await g.Core.Exit.Should().BeEqualTo(AetherExit.Through([prev]));
        await g.Outbound(Global.ProxyTag).protocol.Should().BeEqualTo("vmess");
    }

    [Test]
    public async Task ARuleToAProfileWhoseSubscriptionPutsAnAetherProfileInFrontRunsTheCore()
    {
        // Design 2.8, row 2: the Aether profile is the entry hop and dials out by its own exit-node; the rule's profile
        // carries the traffic. The configuration needs the core, as the WebAPI preflight reads it from the profiles the
        // context holds.
        var warp = Warp(NewName("warp"), NewName("WARP"));
        var target = In(await Subscription(warp.Remarks, null), XrayHop("target", "198.51.100.22"));
        await Store(warp, target);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));

        var context = await Built(NewConfig(), main, target.Remarks);

        var chain = await AssertChain(context, target, warp, target);
        await context.AllProxiesMap.Values.Any(profile => profile.ConfigType == EConfigType.Aether).Should().BeTrue();
        var g = await Succeeds(context);
        var tag = RuleTag(chain);
        var ruleOutbound = g.Outbound(tag);
        await ruleOutbound.settings.address!.ToString().Should().BeEqualTo(target.Address);
        await (ruleOutbound.streamSettings?.sockopt?.dialerProxy).Should().BeEqualTo($"chain-{tag}-1-{warp.Remarks}");
        var hop = g.Outbound($"chain-{tag}-1-{warp.Remarks}");
        await hop.protocol.Should().BeEqualTo("socks");
        await hop.settings.port.Should().BeEqualTo(AetherPorts.DefaultListenPort);
        await g.Outbound(Global.AetherExitNodeTag).protocol.Should().BeEqualTo("freedom");
        await g.Core.Exit.Should().BeEqualTo(AetherExit.Plain);
    }

    [Test]
    public async Task ARuleToAnAetherProfileWhoseSubscriptionNamesAProfileNoneHasRefusesTheSession()
    {
        // The main profile's chain is refused rather than shortened (N1, BuildSubscriptionChainNodeAsync), and so is a
        // session whose rule sends to such a profile, as for any target that cannot be built (E2); a test's context sends
        // the rule to the proxy with the refusal as a warning.
        var missing = NewName("missing");
        var warp = In(await Subscription(missing, null), Warp(NewName("warp"), NewName("WARP")));
        await Store(warp);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));
        var refusal = string.Format(ResUI.MsgRoutingRuleTargetNotFound, missing);

        await AssertRefused(await BuildWithRuleTo(NewConfig(), main, warp.Remarks), Unbuilt(warp, refusal), warp);

        var (context, result) = await BuildWithRuleTo(NewConfig(), main, warp.Remarks, refuseRuleTargets: false);

        await result.Success.Should().BeTrue();
        await result.Warnings.Should().Contain(string.Format(ResUI.MsgRoutingRuleOutboundNodeError, RuleName, warp.Remarks, refusal));
        await RuleNode(context, warp).Should().BeNull();
        await context.AllProxiesMap.Should().NotContainKey(warp.IndexId);
        var g = await Succeeds(context);
        await g.Tags.Any(tag => tag.Contains(warp.Remarks, StringComparison.Ordinal)).Should().BeFalse();
        await g.Config.routing.rules.Any(rule => rule.domain?.Contains($"full:{RuleDomain}") == true && rule.outboundTag == Global.ProxyTag).Should().BeTrue();
        await g.Context.Aether.Core.Should().BeNull();

        // The main profile itself is refused for it.
        var (_, mainResult) = await BuildWithRuleTo(NewConfig(), warp, NewName("nobody"));
        await mainResult.Success.Should().BeFalse();
        await mainResult.Errors.Should().Contain(refusal);
    }

    // D1-R4: the WebAPI's preflight asks for the aether core when the context holds an Aether profile
    // (CoreLaunchPreflight.NeedsAether); a rule that goes to the proxy leaves none of the profiles it resolved behind, and
    // nor does one that refuses the session (E2).
    [Test]
    public async Task ARefusedRuleLeavesNoAetherProfileInTheContext()
    {
        var warp = Warp(NewName("warp"), NewName("WARP"));
        var behindWarp = In(await Subscription(warp.Remarks, null), TuicHop("tuic", "198.51.100.81"));
        var tuic = TuicHop("tuic", "198.51.100.82");
        var userChain = CoreConfigTestFactory.CreateProxyChainNode(ECoreType.Xray, NewName("chain"), NewName("chain"), [warp.IndexId, tuic.IndexId]);
        await Store(warp, behindWarp, tuic, userChain);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));

        // The subscription's chain, and a proxy chain the user made: each loses its TUIC hop, which Xray cannot run.
        foreach (var target in new[] { behindWarp, userChain })
        {
            var session = await BuildWithRuleTo(NewConfig(), main, target.Remarks);
            await session.Success.Should().BeFalse();
            await session.ValidatorResult.Errors.First().Should().BeEqualTo(string.Format(ResUI.MsgRoutingRuleTargetUnbuilt, target.Remarks));
            await session.Context.AllProxiesMap.Values.Any(profile => profile.ConfigType == EConfigType.Aether).Should().BeFalse();
            await AssertNoneRegistered(session.Context, warp, target);

            var (context, result) = await BuildWithRuleTo(NewConfig(), main, target.Remarks, refuseRuleTargets: false);

            await result.Success.Should().BeTrue();
            await RuleNode(context, target).Should().BeNull();
            await context.AllProxiesMap.Values.Any(profile => profile.ConfigType == EConfigType.Aether).Should().BeFalse();
            await AssertNoneRegistered(context, warp, target);
            var g = await Succeeds(context);
            await g.Context.Aether.Core.Should().BeNull();
        }
    }

    [Test]
    public async Task ARulesChainIsHeldToTheOneCoreRule()
    {
        // One core cannot dial out two ways: the same tunnel as the main profile, alone, and behind the rule's chain.
        var prev = XrayHop("prev", "198.51.100.31");
        var warp = In(await Subscription(prev.Remarks, null), Warp(NewName("warp"), NewName("WARP")));
        await Store(prev, warp);
        var mainWarp = Warp(NewName("main-warp"), NewName("main WARP"));

        var twoExits = await Built(NewConfig(), mainWarp, warp.Remarks);
        await AssertChain(twoExits, warp, prev, warp);
        await Refused(twoExits, ResUI.MsgAetherConfigTwoExits);

        // A chain can have one Aether profile: the previous one of the subscription counts.
        var wg = Wg(NewName("wg"), NewName("WG"));
        var behindWg = In(await Subscription(wg.Remarks, null), Warp(NewName("warp"), NewName("WARP")));
        await Store(wg, behindWg);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));
        var twoTunnels = await Built(NewConfig(), main, behindWg.Remarks);
        await AssertChain(twoTunnels, behindWg, wg, behindWg);
        await Refused(twoTunnels, ResUI.MsgAetherChainOneProfile);
    }

    // ---- E2: a target that names no profile, a name several have, or a profile that cannot be built

    private static ProfileItem CustomConfig(string remarks)
    {
        return new ProfileItem
        {
            IndexId = NewName("custom"),
            ConfigType = EConfigType.Custom,
            CoreType = ECoreType.Xray,
            Remarks = remarks,
            Address = "custom-config.json",
            Subid = string.Empty,
        };
    }

    /// <summary>A test's context for the rule: built, the rule sent to the proxy with <paramref name="warning" />.</summary>
    private static async Task AssertGoesToTheProxy(Config config, ProfileItem main, string target, string warning, params ProfileItem[] notLeft)
    {
        var (context, result) = await BuildWithRuleTo(config, main, target, refuseRuleTargets: false);
        await result.Success.Should().BeTrue().Because(string.Join(" | ", result.Errors));
        await result.Warnings.Should().Contain(warning);
        await AssertNoneRegistered(context, notLeft);
        var g = await Succeeds(context);
        await g.Config.routing.rules.Any(rule => rule.domain?.Contains($"full:{RuleDomain}") == true && rule.outboundTag == Global.ProxyTag).Should().BeTrue();
    }

    [Test]
    public async Task ARuleToANameNoProfileHasRefusesTheSession()
    {
        // PattNG: "No profile named ... was found", as for a renamed or deleted profile; never the proxy in its place.
        var nobody = NewName("nobody");
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));

        await AssertRefused(await BuildWithRuleTo(NewConfig(), main, nobody), [string.Format(ResUI.MsgRoutingRuleTargetNotFound, nobody)]);

        await AssertGoesToTheProxy(NewConfig(), main, nobody, string.Format(ResUI.MsgRoutingRuleOutboundNodeNotFound, RuleName, nobody));
    }

    [Test]
    public async Task ARuleToANameSeveralProfilesShareRefusesTheSessionAndNeverTakesTheFirst()
    {
        var name = NewName("twice");
        var first = Vless(NewName("first"), name, "198.51.100.91");
        var second = Vless(NewName("second"), name, "198.51.100.92");
        await Store(first, second);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));
        var duplicate = string.Format(ResUI.MsgRoutingRuleTargetDuplicate, name);

        await AssertRefused(await BuildWithRuleTo(NewConfig(), main, name), [duplicate], first, second);

        // Nor does a test's context take one of them.
        await AssertGoesToTheProxy(NewConfig(), main, name, string.Format(ResUI.MsgRoutingRuleOutboundNodeError, RuleName, name, duplicate), first, second);
    }

    [Test]
    public async Task OnlyAProfileThatCanBeARoutingTargetIsFoundByTheName()
    {
        // A custom configuration is no outbound (PattNG takesAsRoutingTarget): a name only it has names no profile, and one
        // it shares with another profile names that one.
        var alone = CustomConfig(NewName("custom"));
        var shared = NewName("shared");
        var customShared = CustomConfig(shared);
        var vless = Vless(NewName("vless"), shared, "198.51.100.93");
        await Store(alone, customShared, vless);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));

        await AssertRefused(await BuildWithRuleTo(NewConfig(), main, alone.Remarks), [string.Format(ResUI.MsgRoutingRuleTargetNotFound, alone.Remarks)], alone);

        var context = await Built(NewConfig(), main, shared);
        await (RuleNode(context, vless)?.IndexId).Should().BeEqualTo(vless.IndexId);
        await context.AllProxiesMap.Should().NotContainKey(customShared.IndexId);
        var g = await Succeeds(context);
        await g.Outbound(RuleTag(vless)).settings.address!.ToString().Should().BeEqualTo(vless.Address);
    }

    [Test]
    public async Task TheNameIsToldApartWithoutTheSpacesAroundIt()
    {
        // As PattNG's ByName and the other references by name of PattN: the target " X " is the profile "X", and the
        // message names the profile as the lists show it.
        var target = Vless(NewName("target"), NewName("target"), "198.51.100.94");
        await Store(target);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));
        var spaced = $" {target.Remarks} ";

        var context = await Built(NewConfig(), main, spaced);
        await (context.AllProxiesMap.GetValueOrDefault($"remark:{spaced}")?.IndexId).Should().BeEqualTo(target.IndexId);
        var g = await Succeeds(context);
        await g.Config.routing.rules.Any(rule => rule.domain?.Contains($"full:{RuleDomain}") == true && rule.outboundTag == RuleTag(target)).Should().BeTrue();

        var nobody = NewName("nobody");
        await AssertRefused(await BuildWithRuleTo(NewConfig(), main, $"  {nobody}\t"), [string.Format(ResUI.MsgRoutingRuleTargetNotFound, nobody)]);
    }

    [Test]
    public async Task ATargetOfAnyTypeThatCannotBeBuiltRefusesTheSession()
    {
        // A profile Xray cannot run (TUIC), a policy group and a proxy chain with no member it can run.
        var tuic = TuicHop("tuic", "198.51.100.95");
        var member = TuicHop("member", "198.51.100.96");
        var group = CoreConfigTestFactory.CreatePolicyGroupNode(ECoreType.Xray, NewName("group"), NewName("group"), [member.IndexId]);
        var chain = CoreConfigTestFactory.CreateProxyChainNode(ECoreType.Xray, NewName("chain"), NewName("chain"), [member.IndexId]);
        await Store(tuic, member, group, chain);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));

        foreach (var target in new[] { tuic, group, chain })
        {
            var session = await BuildWithRuleTo(NewConfig(), main, target.Remarks);
            await session.Success.Should().BeFalse().Because(target.Remarks);
            var errors = session.ValidatorResult.Errors;
            await errors.First().Should().BeEqualTo(string.Format(ResUI.MsgRoutingRuleTargetUnbuilt, target.Remarks));
            // Why, after it.
            await (errors.Count > 1).Should().BeTrue().Because(string.Join(" | ", errors));
            await AssertNoneRegistered(session.Context, target, member);

            var (context, result) = await BuildWithRuleTo(NewConfig(), main, target.Remarks, refuseRuleTargets: false);
            await result.Success.Should().BeTrue();
            await RuleNode(context, target).Should().BeNull();
            var g = await Succeeds(context);
            await g.Config.routing.rules.Any(rule => rule.domain?.Contains($"full:{RuleDomain}") == true && rule.outboundTag == Global.ProxyTag).Should().BeTrue();
        }
    }

    [Test]
    public async Task ATargetSeveralRulesSendToIsToldOnce()
    {
        var nobody = NewName("nobody");
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));

        var built = await WithRules([Rule(nobody), Rule($" {nobody}", remarks: "second rule")],
            () => CoreConfigContextBuilder.Build(NewConfig(), main));

        await AssertRefused(built, [string.Format(ResUI.MsgRoutingRuleTargetNotFound, nobody)]);
    }

    [Test]
    public async Task ARuleOfTheDnsAloneOrACustomConfigurationsSessionIsNotRefused()
    {
        // A rule of the DNS sends no traffic to its target; a custom configuration runs as it is written, by none of the
        // rules (PattNG getV2rayConfig). Both go on as upstream's do.
        var nobody = NewName("nobody");
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));
        var dns = await WithRules([Rule(nobody, ERuleType.DNS)], () => CoreConfigContextBuilder.Build(NewConfig(), main));
        await dns.Success.Should().BeTrue();
        await dns.ValidatorResult.Warnings.Should().Contain(string.Format(ResUI.MsgRoutingRuleOutboundNodeNotFound, RuleName, nobody));

        var custom = CustomConfig(NewName("custom main"));
        await Store(custom);
        var (_, result) = await BuildWithRuleTo(NewConfig(), custom, nobody);
        await result.Success.Should().BeTrue();
        await result.Warnings.Should().Contain(string.Format(ResUI.MsgRoutingRuleOutboundNodeNotFound, RuleName, nobody));
    }

    [Test]
    public async Task UnderTheLegacyTunTheCoreBehindRefusesTheSessionAndNothingIsBuiltInFront()
    {
        // Xray behind sing-box refuses the rule; the context in front, which would send the rule to Xray, is never built.
        var nobody = NewName("nobody");
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));

        var built = await WithRuleTo(nobody, () => CoreConfigContextBuilder.BuildAll(LegacyTunConfig(), main));

        await built.Success.Should().BeFalse();
        await built.PreSocksResult.Should().BeNull();
        await built.CombinedValidatorResult.Errors.Should().BeEquivalentTo([string.Format(ResUI.MsgRoutingRuleTargetNotFound, nobody)]);
    }

    // ---- the contexts of a test, which drop the routing rules (E2)

    /// <summary>The lines <paramref name="action" /> logs, caught in memory while it runs; the logging set up before comes back after.</summary>
    private static async Task<List<string>> Logged(Func<Task> action)
    {
        var previous = LogManager.Configuration;
        var memory = new MemoryTarget(NewName("rule-targets")) { Layout = "${message}" };
        var caught = new LoggingConfiguration();
        caught.AddRuleForAllLevels(memory);
        LogManager.Configuration = caught;
        try
        {
            await action();
        }
        finally
        {
            LogManager.Configuration = previous;
        }
        return [.. memory.Logs];
    }

    // E2-2: an Aether latency test measures the profile alone and drops the rules: a rule's target never refuses it, as it
    // refuses the session.
    [Test]
    public async Task TheAetherTesterOfTheAppIsNotRefusedForARulesTarget()
    {
        var config = NewConfig();
        var tested = XrayHop("tested", "198.51.100.61");
        await Store(tested);

        var (session, test) = await WithRuleTo(NewName("nobody"), async () =>
            (await CoreConfigContextBuilder.Build(config, tested), await AetherTestHost.Default().Build(tested)));

        await session.Success.Should().BeFalse();
        await test.Success.Should().BeTrue().Because(string.Join(" | ", test.ValidatorResult.Errors));
    }

    // E2-2: a group sing-box runs leaves its Aether member out, as its session does, and stays in the batch: the checks
    // that tell whether its test leaves it drop the rules, so that a rule's target does not take it out to be refused.
    [Test]
    public async Task TheAetherCandidatesOfTheAppAreNotTakenOutForARulesTarget()
    {
        var config = NewConfig();
        var warp = Warp(NewName("warp"), NewName("WARP"));
        warp.Address = "162.159.198.1";
        warp.Port = 443;
        var socks = SingboxHop("socks", "198.51.100.62");
        var group = CoreConfigTestFactory.CreatePolicyGroupNode(ECoreType.sing_box, NewName("group"), NewName("group"), [warp.IndexId, socks.IndexId]);
        await Store(warp, socks, group);
        // Taking the candidates builds contexts, which read these tables; the first take is outside WithRuleTo.
        SQLiteHelper.Instance.CreateTable<FullConfigTemplateItem>();
        SQLiteHelper.Instance.CreateTable<DNSItem>();
        SQLiteHelper.Instance.CreateTable<RoutingItem>();
        // Read afresh for each use: the builder rewrites the members of a group it builds.
        async Task<ProfileItem> Group() => (await ConfigDbQuery.GetProfileItem(group.IndexId))!;
        async Task<List<ServerTestItem>> Taken()
        {
            var item = new ServerTestItem { IndexId = group.IndexId, ConfigType = EConfigType.PolicyGroup, CoreType = ECoreType.sing_box, Profile = await Group() };
            return await AetherTestCandidates.FromDatabase().TakeAsync(ESpeedActionType.Realping, [item]);
        }
        var nobody = NewName("nobody");

        await (await Taken()).Should().BeEmpty();
        await (await WithRuleTo(nobody, Taken)).Should().BeEmpty();
        // The rule refuses the group's session all the same.
        await (await WithRuleTo(nobody, async () => await CoreConfigContextBuilder.Build(config, await Group()))).Success.Should().BeFalse();
    }

    // E2-3: the context of a scan's or a key run's exit, of the editor's look at an exit-node and of a batch latency test
    // is never refused for a rule's target, and does not log that it is; the session's does.
    [Test]
    public async Task ContextsThatDropTheRulesLogNoRefusalForARulesTarget()
    {
        var config = NewConfig();
        var nobody = NewName("nobody");
        var refusal = $"Routing rule target '{nobody}'";

        var session = await Logged(() => WithRuleTo(nobody, async () =>
            await CoreConfigContextBuilder.Build(config, AetherExitHost.ContextProfile())));
        await session.Any(line => line.Contains(refusal, StringComparison.Ordinal)).Should().BeTrue();

        var file = Path.Combine(Path.GetTempPath(), $"{NewName("speedtest")}.json");
        var tests = await Logged(() => WithRuleTo(nobody, async () =>
        {
            var exit = await AetherExitHost.GenerateAsync(AetherExit.Plain, 20808, new AetherUplinkBinding { TunRunning = () => false, FindUplink = () => null });
            await exit.Success.Should().BeTrue().Because(exit.Msg ?? string.Empty);
            var lookup = await new AetherEditorSource(config).FindExitNodeAsync(NewName("node"));
            await (lookup is ExitNodeLookup.NotFound).Should().BeTrue();
            try
            {
                await CoreConfigHandler.GenerateClientSpeedtestConfig(config, file, [], ECoreType.Xray);
            }
            finally
            {
                File.Delete(file);
            }
            return true;
        }));
        await tests.Any(line => line.Contains(refusal, StringComparison.Ordinal)).Should().BeFalse().Because(string.Join(" | ", tests));
    }
}
