namespace ServiceLib.Handler.Builder;

/// <summary>
/// PattN: the Aether part of the context builder (design 2.7.2, 2.7.6, 2.9; PattNG core/CoreConfigContextBuilder.kt).
/// What needs the database is done here, since the generator is synchronous: the exit-node of an Aether profile is looked
/// up by its name, the names its core asks Xray for are protected under the TUN, a policy group a filter fills keeps one
/// Aether core, and a proxy chain holding an Aether profile is built whole or not at all.
/// </summary>
public partial class CoreConfigContextBuilder
{
    /// <summary>
    /// The exit-node <paramref name="name" /> finds (design 2.9.3): the one profile that has the name among those that can
    /// be an exit-node, registered into <paramref name="context" /> as any profile of a configuration is, so that its
    /// custom outbound is read and the names of its servers are protected; or why there is none: no such profile has the
    /// name any more, several have it, the one that has it fails the checks Xray needs, or its ECH outbound cannot go
    /// beside it (one no configuration takes, or one tagged exit-node, as the profile's own outbound is there). The
    /// digest of the profile is taken with its custom outbound, as the configuration reads it.
    /// </summary>
    public static async Task<ExitNodeLookup> LookUpAetherExitNodeAsync(CoreConfigContext context, string name)
    {
        var found = AetherExit.NodeProfile(name, await ConfigDbQuery.GetProfileItemsViaRemarksAsync(name));
        if (found is not ByName<ProfileItem>.One one)
        {
            return ExitNodeLookup.Of(found);
        }
        var profile = one.Value;
        if (NodeValidator.ValidateEchOutbound(profile, out var echOutbound) != null
            || (echOutbound != null && NodeValidator.GetOutboundTag(echOutbound) == Global.AetherExitNodeTag))
        {
            return ExitNodeLookup.EchUnusable.Instance;
        }
        var registered = await RegisterSingleNodeAsync(context, profile);
        if (!registered.Success)
        {
            return ExitNodeLookup.NoOutbound.Instance;
        }
        return ExitNodeLookup.Of(found, outboundProfile => context.CustomOutboundContent.GetValueOrDefault(outboundProfile.IndexId));
    }

    /// <summary>
    /// Registers what the Aether profile <paramref name="node" />, validated and in the proxy map, needs beyond itself.
    /// Its Address is the WARP endpoint its core dials, or a host name a subscription's override put there, which the
    /// core then scans: no server Xray resolves, so it is not protected. Under the TUN the names its core has Xray look
    /// up before its tunnel is up are protected instead (<see cref="AetherBootstrapNames" />): only for a core that
    /// dials out by the freedom exit-node, since a named exit-node passes every name on to its server as it is, and a
    /// core told an upstream of its own hands its names to that proxy. The name of that proxy the core looks up itself,
    /// with the system resolver, and is protected whatever the exit. An Aether profile that is a hop behind another in
    /// a proxy chain dials out through that hop, which the builder cannot see here: its names are protected all the
    /// same. Its exit-node is looked up once for every name, however many profiles name it.
    /// </summary>
    private static async Task RegisterAetherNodeAsync(CoreConfigContext context, ProfileItem node)
    {
        var core = AetherCore.Of(node, AetherPorts.ListenPortOf(context.AppConfig.CoreBasicItem.AetherListenPort));
        if (context.IsTunEnabled)
        {
            if (AetherBootstrapNames.UpstreamHostOf(core.Arguments) is { } upstreamHost)
            {
                context.ProtectDomainList.Add(upstreamHost);
            }
            if (!core.HasUpstream && core.Exit.Node == null)
            {
                foreach (var name in AetherBootstrapNames.Of(core.Arguments))
                {
                    context.ProtectDomainList.Add(name);
                }
                if (AetherBootstrapNames.PsiphonBeforeTheTunnel(core.Arguments))
                {
                    Logging.SaveLog($"{node.Remarks}: Psiphon runs before the Aether tunnel under the TUN, and the names its fronted transports dial are not protected");
                }
                if (AetherBootstrapNames.TorBeforeTheTunnel(core.Arguments))
                {
                    Logging.SaveLog($"{node.Remarks}: Tor runs before the Aether tunnel under the TUN, and the names the bridges it learns from moat or keeps from an earlier run dial are not protected");
                }
            }
        }
        if (core.Exit.Node is { } exitNode && !context.Aether.ExitNodes.ContainsKey(exitNode))
        {
            context.Aether.ExitNodes[exitNode] = await LookUpAetherExitNodeAsync(context, exitNode);
        }
    }

    /// <summary>
    /// Why the group or chain <paramref name="node" /> cannot be built with its registered children
    /// <paramref name="childIndexIds" /> of <paramref name="children" />, as a localized message, or null; a policy group a
    /// filter fills loses its Aether children that need another core, with a warning each, in
    /// <paramref name="childIndexIds" /> and <paramref name="result" />.
    /// <para>
    /// A proxy chain holding an Aether profile is built whole or not at all (critique 4, PattNG chainHops): without a hop
    /// it would carry the traffic a shorter way than it names, as to WARP directly where a hop was to hide it, or, under
    /// sing-box, which runs no Aether profile, without WARP at all. Other chains keep PattN's way.
    /// </para>
    /// <para>
    /// A policy group a filter fills can catch several Aether profiles while one core serves one of them (PattNG
    /// withOneAetherProfile): see <see cref="AetherMembers.WithOneAetherProfile" />. Members picked by hand stay; a
    /// conflict among them refuses the configuration when it is generated.
    /// </para>
    /// </summary>
    private static string? SettleAetherChildren(
        CoreConfigContext context,
        ProfileItem node,
        List<ProfileItem> children,
        List<string> childIndexIds,
        NodeValidatorResult result)
    {
        if (node.ConfigType == EConfigType.ProxyChain)
        {
            if (!children.Any(child => child.ConfigType == EConfigType.Aether))
            {
                return null;
            }
            // The hops the chain names, as it stores them: the profiles loaded for it leave out a hop whose profile is gone
            // (a subscription update gives its profiles new ids) and name a hop it repeats once, either of which would
            // build the chain shorter than it names. A chain whose Aether profile itself is gone is no Aether chain here.
            var named = (Utils.String2List(node.GetProtocolExtra().ChildItems) ?? []).Where(id => !id.IsNullOrEmpty()).ToList();
            if (named.FirstOrDefault(id => children.All(child => child.IndexId != id)) is { } gone)
            {
                return string.Format(ResUI.MsgAetherChainHopDropped, node.Remarks, gone);
            }
            if (named.GroupBy(id => id).FirstOrDefault(ids => ids.Count() > 1)?.Key is { } repeatedId
                && children.First(child => child.IndexId == repeatedId) is var repeated)
            {
                return repeated.ConfigType == EConfigType.Aether
                    ? ResUI.MsgAetherChainOneProfile
                    : string.Format(ResUI.MsgAetherChainHopDropped, node.Remarks, repeated.Remarks);
            }
            var dropped = children.FirstOrDefault(child => !childIndexIds.Contains(child.IndexId));
            return dropped == null ? null : string.Format(ResUI.MsgAetherChainHopDropped, node.Remarks, dropped.Remarks);
        }
        if (node.ConfigType != EConfigType.PolicyGroup)
        {
            return null;
        }
        var picked = (Utils.String2List(node.GetProtocolExtra().ChildItems) ?? []).ToHashSet();
        var registered = childIndexIds
            .Distinct()
            .Select(id => children.FirstOrDefault(child => child.IndexId == id))
            .OfType<ProfileItem>()
            .ToList();
        var (_, leftOut) = AetherMembers.WithOneAetherProfile(
            registered,
            child => !picked.Contains(child.IndexId),
            AetherPorts.ListenPortOf(context.AppConfig.CoreBasicItem.AetherListenPort));
        foreach (var child in leftOut)
        {
            Logging.SaveLog($"Policy group '{node.Remarks}' leaves out '{child.Remarks}': a second Aether profile with other settings, and one core serves one profile");
            result.Warnings.Add(string.Format(ResUI.MsgAetherGroupLeavesOut, node.Remarks, child.Remarks));
            childIndexIds.RemoveAll(id => id == child.IndexId);
        }
        return null;
    }
}
