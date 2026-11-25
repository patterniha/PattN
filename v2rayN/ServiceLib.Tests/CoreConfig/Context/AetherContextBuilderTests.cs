using TUnit.Assertions.Enums;
using static ServiceLib.Tests.CoreConfig.V2ray.AetherConfigTests;

namespace ServiceLib.Tests.CoreConfig.Context;

/// <summary>
/// PattN (design 2.7.2, 2.7.6, 2.9; critique 4 and 11; PattNG CoreConfigContextBuilderTest): what the context builder does
/// for Aether profiles, with the test database: the exit-node a profile names is looked up by name, the names its core
/// asks Xray for are protected under the TUN, a group a filter fills keeps one core, and a chain holding an Aether
/// profile is built whole or not at all. Every name is new to the test, as the database is shared. The tests do not run
/// beside the others that write to it.
/// </summary>
[NotInParallel]
public class AetherContextBuilderTests
{
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

    private static ProfileItem Noded(string node)
    {
        return Warp(NewName("warp"), "WARP", extra => extra with { AetherExitNode = $"  {node} " });
    }

    private static CoreConfigContext ContextOf(Config config, ProfileItem node, ECoreType coreType = ECoreType.Xray)
    {
        var context = CoreConfigTestFactory.CreateContext(config, node, coreType);
        context.AllProxiesMap.Clear();
        return context;
    }

    // ---- the exit-node

    [Test]
    public async Task TheExitNodeAProfileNamesIsLookedUpAndRegisteredLikeAnyProfile()
    {
        var name = NewName("germany");
        var germany = Vless(NewName("id"), name, "germany.example");
        var warp = Noded(name);
        await Store(germany, warp);
        var config = NewConfig();
        var context = ContextOf(config, warp);

        var (_, result) = await CoreConfigContextBuilder.ResolveNodeAsync(context, warp, false);

        await result.Success.Should().BeTrue();
        var lookup = context.Aether.ExitNodes[name] as ExitNodeLookup.One;
        await (lookup?.Profile.IndexId).Should().BeEqualTo(germany.IndexId);
        await (lookup?.Content).Should().BeEqualTo(AetherExit.ContentOf(germany));
        // Its server is resolved directly, as any proxy's; the Aether profile's own Address never is.
        await context.AllProxiesMap.Should().ContainKey(germany.IndexId);
        await context.ProtectDomainList.Should().Contain("germany.example");

        // The configuration takes its outbound for the exit-node.
        var g = await Succeeds(context with { Node = warp });
        await g.Outbound(Global.AetherExitNodeTag).settings.address!.ToString().Should().BeEqualTo("germany.example");
        await g.Core.Exit.NodeContent.Should().BeEqualTo(AetherExit.ContentOf(germany));
    }

    [Test]
    public async Task AnExitNodeNameThatFindsNoneOrSeveralOrAnUnusableOneIsToldByWhatItFinds()
    {
        var config = NewConfig();

        // None any more, or only an Aether profile, which is never an exit-node.
        var gone = NewName("gone");
        var aetherOfTheName = Warp(NewName("id"), gone);
        var noneWarp = Noded(gone);
        await Store(aetherOfTheName, noneWarp);
        var none = ContextOf(config, noneWarp);
        await CoreConfigContextBuilder.ResolveNodeAsync(none, noneWarp, false);
        await none.Aether.ExitNodes[gone].Should().BeEqualTo(ExitNodeLookup.NotFound.Instance);

        // Several.
        var twice = NewName("twice");
        var severalWarp = Noded(twice);
        await Store(Vless(NewName("id"), twice), Vless(NewName("id"), $" {twice}"), severalWarp);
        var several = ContextOf(config, severalWarp);
        await CoreConfigContextBuilder.ResolveNodeAsync(several, severalWarp, false);
        await several.Aether.ExitNodes[twice].Should().BeEqualTo(ExitNodeLookup.SameName.Instance);

        // One that fails the checks Xray needs.
        var broken = NewName("broken");
        var brokenProfile = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("id"), broken);
        brokenProfile.Password = "not a uuid";
        var brokenWarp = Noded(broken);
        await Store(brokenProfile, brokenWarp);
        var unusable = ContextOf(config, brokenWarp);
        await CoreConfigContextBuilder.ResolveNodeAsync(unusable, brokenWarp, false);
        await unusable.Aether.ExitNodes[broken].Should().BeEqualTo(ExitNodeLookup.NoOutbound.Instance);

        // One whose ECH outbound cannot go beside it: tagged exit-node, as its own outbound is there, or none at all.
        foreach (var echOutbound in new[] { """{"tag": "exit-node", "protocol": "freedom"}""", "freedom" })
        {
            var ech = NewName("ech");
            var echProfile = Vless(NewName("id"), ech);
            echProfile.StreamSecurity = Global.StreamSecurity;
            echProfile.EchConfigList = "cloudflare-ech.com+https://1.1.1.1/dns-query";
            echProfile.EchOutbound = echOutbound;
            var echWarp = Noded(ech);
            await Store(echProfile, echWarp);
            var echContext = ContextOf(config, echWarp);
            await CoreConfigContextBuilder.ResolveNodeAsync(echContext, echWarp, false);
            await echContext.Aether.ExitNodes[ech].Should().BeEqualTo(ExitNodeLookup.EchUnusable.Instance).Because(echOutbound);
        }
    }

    // ---- protected names

    [Test]
    public async Task UnderTheTunTheNamesTheCoreAsksXrayForAreProtected()
    {
        var warp = Warp(NewName("warp"), "WARP", extra => extra with
        {
            AetherTor = AetherTor.Reverse.Type,
            AetherEch = true,
            AetherEchDns = "https://dns.example/dns-query",
        });
        // A subscription's override may put a name where the endpoint goes; the core scans then, and Xray never dials it.
        warp.Address = "engage.cloudflareclient.com";
        warp.Port = 2408;
        var tun = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, enableIPv6Address: false);
        CoreConfigTestFactory.BindAppManagerConfig(tun);
        var context = ContextOf(tun, warp);

        var (_, result) = await CoreConfigContextBuilder.ResolveNodeAsync(context, warp, false);

        await result.Success.Should().BeTrue();
        await context.ProtectDomainList.Should().Contain(AetherBootstrapNames.WarpApi);
        await context.ProtectDomainList.Should().Contain("dns.example");
        await context.ProtectDomainList.Should().Contain("bridges.torproject.org");
        await context.ProtectDomainList.Should().NotContain("engage.cloudflareclient.com");

        // Without the TUN, the OS resolver looks them up for the freedom exit-node.
        var plain = ContextOf(NewConfig(), warp);
        await CoreConfigContextBuilder.ResolveNodeAsync(plain, warp, false);
        await plain.ProtectDomainList.Should().BeEmpty();
    }

    [Test]
    public async Task UnderTheTunACoreWithANamedExitNodeHasNoNamesProtected()
    {
        // The named exit-node passes every name the core sends on to its server as it is: Xray never looks them up, and
        // protecting them would only have every app's lookups of them answered by the direct DNS.
        var germanyName = NewName("germany");
        var germany = Vless(NewName("id"), germanyName, "germany.example");
        var warp = Warp(NewName("warp"), "WARP", extra => extra with { AetherTor = AetherTor.Reverse.Type, AetherExitNode = germanyName });
        await Store(germany, warp);
        var tun = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, enableIPv6Address: false);
        CoreConfigTestFactory.BindAppManagerConfig(tun);
        var context = ContextOf(tun, warp);

        var (_, result) = await CoreConfigContextBuilder.ResolveNodeAsync(context, warp, false);

        await result.Success.Should().BeTrue();
        await context.ProtectDomainList.Should().NotContain(AetherBootstrapNames.WarpApi);
        await context.ProtectDomainList.Should().NotContain("bridges.torproject.org");
        // The node's own server is resolved directly, as any proxy's.
        await context.ProtectDomainList.Should().Contain("germany.example");
    }

    [Test]
    public async Task UnderTheTunTheProxyACommandDialsOutThroughIsProtected()
    {
        // A command written by hand with an upstream of its own: the core looks the proxy's name up with the system
        // resolver, whose query enters the TUN; the names it sends through that proxy are the proxy's to look up.
        var warp = Warp(NewName("warp"), "WARP", extra => extra with
        {
            AetherCommand = "aether --bind 127.0.0.1:10819 --protocol masque --upstream socks5://proxy.example.net:1080",
        });
        var tun = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, enableIPv6Address: false);
        CoreConfigTestFactory.BindAppManagerConfig(tun);
        var context = ContextOf(tun, warp);

        await CoreConfigContextBuilder.ResolveNodeAsync(context, warp, false);

        await context.ProtectDomainList.Should().BeEquivalentTo(["proxy.example.net"], CollectionOrdering.Any);
    }

    // ---- the whole context (CoreConfigContextBuilder.Build, with the tables it reads)

    private static async Task<ProfileItem> StoreForBuild(ProfileItem profile)
    {
        SQLiteHelper.Instance.CreateTable<FullConfigTemplateItem>();
        SQLiteHelper.Instance.CreateTable<DNSItem>();
        SQLiteHelper.Instance.CreateTable<RoutingItem>();
        await Store(profile);
        return profile;
    }

    [Test]
    public async Task UnderTheTunWhatTheAetherProgramsDialThemselvesGoesDirect()
    {
        // Design 2.7.6 point 1: the process rule of the TUN names the Aether programs, for a command's upstream elsewhere
        // and the helpers a command leaves without one.
        var warp = await StoreForBuild(Warp(NewName("warp"), NewName("WARP")));
        var tun = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, enableIPv6Address: false);
        tun.CoreBasicItem.AetherListenPort = AetherPorts.DefaultListenPort;
        CoreConfigTestFactory.BindAppManagerConfig(tun);

        var (context, result) = await CoreConfigContextBuilder.Build(tun, warp);

        await result.Success.Should().BeTrue().Because(string.Join(" | ", result.Errors));
        await context.ProtectCoreTypeList.Should().Contain(ECoreType.aether);
        await context.ProtectDomainList.Should().Contain(AetherBootstrapNames.WarpApi);

        // Without the TUN, nothing is protected.
        var (plain, _) = await CoreConfigContextBuilder.Build(NewConfig(), warp);
        await plain.ProtectCoreTypeList.Should().BeEmpty();
        await plain.ProtectDomainList.Should().BeEmpty();

        // The sing-box TUN in front of Xray takes the main context's core types.
        tun.TunModeItem.EnableLegacyProtect = true;
        var all = await CoreConfigContextBuilder.BuildAll(tun, warp);
        await (all.PreSocksResult is not null).Should().BeTrue();
        await all.PreSocksResult!.Context.ProtectCoreTypeList.Should().Contain(ECoreType.aether);
        await all.PreSocksResult.Context.ProtectDomainList.Should().Contain(AetherBootstrapNames.WarpApi);
    }

    [Test]
    public async Task TheExitOfACoreOfItsOwnLeavesOutTheSendThroughAddressASessionLeavesOut()
    {
        // Design 2.6.5: the exit of a scan or a key run is built as a session's context is, to the end, where an address
        // that is none of this machine's is left out with a warning; Xray cannot send from it.
        await StoreForBuild(Vless(NewName("id"), NewName("any")));
        var config = NewConfig(config => config.CoreBasicItem.SendThrough = "203.0.113.50");

        var (context, result) = await CoreConfigContextBuilder.Build(config, AetherExitHost.ContextProfile());

        await result.Success.Should().BeTrue().Because(string.Join(" | ", result.Errors));
        await context.AppConfig.CoreBasicItem.SendThrough.Should().BeEmpty();
        var generated = new CoreConfigV2rayService(context).GenerateAetherExitConfig(AetherExit.Plain, 41975);
        await generated.Success.Should().BeTrue().Because(generated.Msg ?? string.Empty);
        var exitNode = JsonNode.Parse(generated.Data!.ToString()!)!["outbounds"]![0]!.AsObject();
        await exitNode["tag"]!.GetValue<string>().Should().BeEqualTo(Global.AetherExitNodeTag);
        await exitNode.ContainsKey("sendThrough").Should().BeFalse();
    }

    // ---- groups

    [Test]
    public async Task AGroupAFilterFillsKeepsOneAetherCoreAndTellsWhatItLeavesOut()
    {
        var subId = NewName("sub");
        var warp = Warp(NewName("warp"), NewName("WARP"));
        var wg = Wg(NewName("wg"), NewName("WG"));
        var vless = Vless(NewName("vless"), NewName("vless"));
        foreach (var member in new[] { warp, wg, vless })
        {
            member.Subid = subId;
        }
        await Store(warp, wg, vless);
        var group = CoreConfigTestFactory.CreatePolicyGroupNode(ECoreType.Xray, NewName("group"), "filtered", []);
        group.SetProtocolExtra(group.GetProtocolExtra() with { ChildItems = null, SubChildItems = subId, Filter = null });
        var context = ContextOf(NewConfig(), group);

        var (_, result) = await CoreConfigContextBuilder.ResolveNodeAsync(context, group, false);

        await result.Success.Should().BeTrue();
        var members = await ConfigDbQuery.ProfileItems(subId) ?? [];
        var kept = members.First(member => member.ConfigType == EConfigType.Aether);
        var leftOut = members.Single(member => member.ConfigType == EConfigType.Aether && member.IndexId != kept.IndexId);
        await result.Warnings.Should().Contain(string.Format(ResUI.MsgAetherGroupLeavesOut, "filtered", leftOut.Remarks));
        var children = Utils.String2List(group.GetProtocolExtra().ChildItems) ?? [];
        await children.Should().BeEquivalentTo(members.Where(member => member.IndexId != leftOut.IndexId).Select(member => member.IndexId), CollectionOrdering.Any);

        // The configuration then runs on the one core.
        var g = await Succeeds(context with { Node = group });
        await g.Core.Should().BeEqualTo(AetherCore.Of(kept, AetherPorts.DefaultListenPort).Through(AetherPorts.DefaultListenPort + AetherPorts.SecondaryOffset));
    }

    [Test]
    public async Task AGroupPickedByHandKeepsItsMembersAndIsRefusedWhenItIsBuilt()
    {
        var warp = Warp(NewName("warp"), NewName("WARP"));
        var wg = Wg(NewName("wg"), NewName("WG"));
        await Store(warp, wg);
        var group = CoreConfigTestFactory.CreatePolicyGroupNode(ECoreType.Xray, NewName("group"), "picked", [warp.IndexId, wg.IndexId]);
        var context = ContextOf(NewConfig(), group);

        var (_, result) = await CoreConfigContextBuilder.ResolveNodeAsync(context, group, false);

        await result.Success.Should().BeTrue();
        await result.Warnings.Should().BeEmpty();
        await (Utils.String2List(group.GetProtocolExtra().ChildItems) ?? []).Should()
            .BeEquivalentTo([warp.IndexId, wg.IndexId], CollectionOrdering.Matching);
        await Refused(context with { Node = group }, ResUI.MsgAetherConfigSingleProfile);
    }

    // ---- chains built whole

    [Test]
    public async Task AChainHoldingAnAetherProfileIsBuiltWholeOrNotAtAll()
    {
        var broken = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("broken"), NewName("broken"));
        broken.Password = "not a uuid";
        var warp = Warp(NewName("warp"), NewName("WARP"));
        var vless = Vless(NewName("vless"), NewName("vless"));
        await Store(broken, warp, vless);

        var chain = CoreConfigTestFactory.CreateProxyChainNode(ECoreType.Xray, NewName("chain"), "with aether", [broken.IndexId, warp.IndexId]);
        var context = ContextOf(NewConfig(), chain);
        var (_, refused) = await CoreConfigContextBuilder.ResolveNodeAsync(context, chain, false);
        await refused.Success.Should().BeFalse();
        await refused.Errors.Should().Contain(string.Format(ResUI.MsgAetherChainHopDropped, "with aether", broken.Remarks));
        await context.AllProxiesMap.Should().NotContainKey(chain.IndexId);

        // A chain without one keeps PattN's way: the hop is dropped with a warning.
        var plain = CoreConfigTestFactory.CreateProxyChainNode(ECoreType.Xray, NewName("chain"), "plain", [broken.IndexId, vless.IndexId]);
        var plainContext = ContextOf(NewConfig(), plain);
        var (_, shortened) = await CoreConfigContextBuilder.ResolveNodeAsync(plainContext, plain, false);
        await shortened.Success.Should().BeTrue();
        await shortened.Warnings.Should().NotBeEmpty();
        await plain.GetProtocolExtra().ChildItems.Should().BeEqualTo(vless.IndexId);
    }

    [Test]
    public async Task AChainHoldingAnAetherProfileWithAHopWhoseProfileIsGoneIsRefused()
    {
        // A subscription update gives its profiles new ids, and the chain still names the old one: the chain X, WARP would
        // run as WARP alone, its handshake going out directly where X was to hide it.
        var gone = NewName("gone");
        var warp = Warp(NewName("warp"), NewName("WARP"));
        await Store(warp);
        var chain = CoreConfigTestFactory.CreateProxyChainNode(ECoreType.Xray, NewName("chain"), "renewed", [gone, warp.IndexId]);
        var context = ContextOf(NewConfig(), chain);

        var (_, result) = await CoreConfigContextBuilder.ResolveNodeAsync(context, chain, false);

        await result.Success.Should().BeFalse();
        await result.Errors.Should().Contain(string.Format(ResUI.MsgAetherChainHopDropped, "renewed", gone));
        await context.AllProxiesMap.Should().NotContainKey(chain.IndexId);
    }

    [Test]
    public async Task AChainHoldingAnAetherProfileThatRepeatsAHopIsRefused()
    {
        // The profiles loaded for a chain name a hop it repeats once: X, WARP, X would run as X, WARP, its traffic leaving
        // at WARP instead of X; and WARP, X, WARP would run as WARP, X, past the rule that a chain has one Aether profile.
        var x = Vless(NewName("x"), NewName("X"));
        var warp = Warp(NewName("warp"), NewName("WARP"));
        await Store(x, warp);

        var twiceX = CoreConfigTestFactory.CreateProxyChainNode(ECoreType.Xray, NewName("chain"), "x twice", [x.IndexId, warp.IndexId, x.IndexId]);
        var (_, xResult) = await CoreConfigContextBuilder.ResolveNodeAsync(ContextOf(NewConfig(), twiceX), twiceX, false);
        await xResult.Success.Should().BeFalse();
        await xResult.Errors.Should().Contain(string.Format(ResUI.MsgAetherChainHopDropped, "x twice", x.Remarks));

        var twiceWarp = CoreConfigTestFactory.CreateProxyChainNode(ECoreType.Xray, NewName("chain"), "warp twice", [warp.IndexId, x.IndexId, warp.IndexId]);
        var (_, warpResult) = await CoreConfigContextBuilder.ResolveNodeAsync(ContextOf(NewConfig(), twiceWarp), twiceWarp, false);
        await warpResult.Success.Should().BeFalse();
        await warpResult.Errors.Should().Contain(ResUI.MsgAetherChainOneProfile);

        // Named once each, it is built as it names.
        var once = CoreConfigTestFactory.CreateProxyChainNode(ECoreType.Xray, NewName("chain"), "once", [x.IndexId, warp.IndexId]);
        var (_, onceResult) = await CoreConfigContextBuilder.ResolveNodeAsync(ContextOf(NewConfig(), once), once, false);
        await onceResult.Success.Should().BeTrue();
    }

    // critique 4: under sing-box, which runs no Aether profile, the chain would run without WARP.
    [Test]
    public async Task ASingBoxChainHoldingAnAetherProfileIsRefused()
    {
        var warp = Warp(NewName("warp"), NewName("WARP"));
        var vless = Vless(NewName("vless"), NewName("vless"));
        await Store(warp, vless);
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.sing_box);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var chain = CoreConfigTestFactory.CreateProxyChainNode(ECoreType.sing_box, NewName("chain"), "sing-box chain", [vless.IndexId, warp.IndexId]);
        var context = ContextOf(config, chain, ECoreType.sing_box);

        var (_, result) = await CoreConfigContextBuilder.ResolveNodeAsync(context, chain, false);

        await result.Success.Should().BeFalse();
        await result.Errors.Should().Contain(string.Format(ResUI.MsgAetherChainHopDropped, "sing-box chain", warp.Remarks));
    }

    [Test]
    public async Task ASubscriptionChainThatLacksAHopIsRefusedWithOrWithoutAnAetherProfile()
    {
        SQLiteHelper.Instance.CreateTable<SubItem>();
        var subId = NewName("sub");
        var missing = NewName("missing");
        await SQLiteHelper.Instance.ReplaceAsync(new SubItem { Id = subId, Remarks = "chained", Url = string.Empty, PrevProfile = missing });
        var warp = Warp(NewName("warp"), NewName("WARP"));
        warp.Subid = subId;
        var vless = Vless(NewName("vless"), NewName("vless"));
        vless.Subid = subId;
        await Store(warp, vless);
        var notFound = string.Format(ResUI.MsgRoutingRuleTargetNotFound, missing);

        var (_, refused) = await CoreConfigContextBuilder.ResolveNodeAsync(ContextOf(NewConfig(), warp), warp, true);
        await refused.Success.Should().BeFalse();
        await refused.Errors.Should().BeEquivalentTo([notFound], CollectionOrdering.Matching);

        // N1: a profile of the same subscription without Aether is refused alike, never run alone.
        var vlessContext = ContextOf(NewConfig(), vless);
        var (_, vlessRefused) = await CoreConfigContextBuilder.ResolveNodeAsync(vlessContext, vless, true);
        await vlessRefused.Success.Should().BeFalse();
        await vlessRefused.Errors.Should().BeEquivalentTo([notFound], CollectionOrdering.Matching);
        await vlessContext.AllProxiesMap.Should().NotContainKey(vless.IndexId);
    }

    // ---- sing-box

    // critique 34: a routing rule naming an Aether profile under a sing-box main profile falls back to the proxy with a
    // warning, as for any target sing-box cannot run: the profile fails its check there (CoreConfigContextBuilder.Build
    // turns the error into the warning), and sing-box's routing sends the rule to the proxy.
    [Test]
    public async Task UnderSingBoxARuleNamingAnAetherProfileFallsBackToTheProxy()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.sing_box);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var warp = Warp(NewName("warp"), NewName("WARP"));
        var main = CoreConfigTestFactory.CreateSocksNode(ECoreType.sing_box, NewName("main"), "main");

        var (_, result) = await CoreConfigContextBuilder.ResolveNodeAsync(ContextOf(config, main, ECoreType.sing_box), warp, false);
        await result.Success.Should().BeFalse();
        await result.Errors.Should().Contain(string.Format(ResUI.MsgCoreNotSupportProtocol, nameof(ECoreType.sing_box), EConfigType.Aether));

        var context = CoreConfigTestFactory.CreateContext(config, main, ECoreType.sing_box) with { RoutingItem = RuleTo(warp.Remarks) };
        // Even if it were there, sing-box builds no outbound for it.
        context.AllProxiesMap[$"remark:{warp.Remarks}"] = warp;
        var generated = new CoreConfigSingboxService(context).GenerateClientConfigContent();
        await generated.Success.Should().BeTrue().Because(generated.Msg ?? string.Empty);
        var singbox = JsonUtils.Deserialize<SingboxConfig>(generated.Data!.ToString())!;
        await singbox.outbounds.Any(outbound => outbound.tag.StartsWith(warp.IndexId, StringComparison.Ordinal)).Should().BeFalse();
        await singbox.route.rules.Any(rule => rule.domain?.Contains("rule.example.com") == true && rule.outbound == Global.ProxyTag).Should().BeTrue();
    }
}
