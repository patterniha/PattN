namespace ServiceLib.Handler.Builder;

/// <summary>
/// PattN: the profile a routing rule sends to, which runs inside its subscription's previous/next chain as the main
/// profile does (D1; PattNG CoreConfigContextBuilder.kt resolveOutbound). A chain that lost a hop it needs cannot carry
/// the rule, as any target that cannot be built; what resolving the target added to the context is taken back then, so
/// that nothing outside the configuration reads a profile it never runs. A target that names no profile, a name several
/// have, or a profile that cannot be built refuses the context, as PattNG refuses the session for it, rather than send the
/// rule's traffic by the proxy, or by a profile it may not mean (E2; PattNG resolveRoutingOutbounds and
/// CoreConfigManager.unbuiltRoutingTarget); where rule targets do not refuse it (<see cref="RefusesRuleTarget" />), the rule
/// goes to the proxy, as upstream's does.
/// </summary>
public partial class CoreConfigContextBuilder
{
    /// <summary>
    /// Whether the target of <paramref name="rule" /> refuses the context of <paramref name="node" /> when it names no
    /// profile, a name several have, or a profile that cannot be built (E2). It does where <paramref name="refuseRuleTargets" />
    /// (not for a latency test, which measures the profile alone and drops the rules, PattNG getV2rayConfig4Speedtest), but
    /// not in front of a core that carries the rules behind it (<paramref name="rulesCarriedBehind" />), whose own context
    /// is refused for them and which takes the rules this core cannot build; not for a custom configuration, which runs as
    /// it is written and routes by none of the rules (PattNG getV2rayConfig); and not for a rule of the DNS alone, which
    /// sends no traffic to its target.
    /// </summary>
    private static bool RefusesRuleTarget(ProfileItem node, RulesItem rule, bool rulesCarriedBehind, bool refuseRuleTargets)
    {
        return refuseRuleTargets
               && !rulesCarriedBehind
               && node.ConfigType != EConfigType.Custom
               && rule.RuleType != ERuleType.DNS;
    }

    /// <summary>
    /// Whether <paramref name="profile" /> can be what a routing rule sends to: any profile but a custom configuration, which
    /// is no outbound (PattNG takesAsRoutingTarget). A name that only a custom configuration has names no profile here.
    /// </summary>
    public static bool TakesAsRuleTarget(ProfileItem profile)
    {
        return profile.ConfigType != EConfigType.Custom;
    }

    /// <summary>
    /// What the target <paramref name="name" /> of a routing rule finds among the profiles a rule can send to
    /// (<see cref="TakesAsRuleTarget" />), the names told apart without the spaces around them (<see cref="ByName{T}" />):
    /// one profile, none, or several, which name none of them, rather than the first of them as upstream finds it.
    /// </summary>
    private static async Task<ByName<ProfileItem>> FindRuleTargetAsync(string? name)
    {
        var named = await ConfigDbQuery.GetProfileItemsViaRemarksAsync(name);
        return ByName.Find(name, named.Where(TakesAsRuleTarget), profile => profile.Remarks);
    }

    /// <summary>
    /// Why the context is refused for a routing rule's target: <see cref="Message" />, which names the target
    /// <see cref="Name" />, and the <see cref="Reasons" /> told after it.
    /// </summary>
    private sealed record RuleTargetRefusal(string Name, string Message, IReadOnlyList<string> Reasons);

    /// <summary>The refusal for the target <paramref name="target" /> that finds no profile, or several, as <paramref name="found" /> says.</summary>
    private static RuleTargetRefusal RuleTargetNotFound(ByName<ProfileItem> found, string target)
    {
        var name = KotlinText.Trim(target);
        var message = found is ByName<ProfileItem>.Several ? ResUI.MsgRoutingRuleTargetDuplicate : ResUI.MsgRoutingRuleTargetNotFound;
        return new RuleTargetRefusal(name, string.Format(message, name), []);
    }

    /// <summary>The refusal for the target <paramref name="target" />, whose profile could not be built for <paramref name="reasons" />.</summary>
    private static RuleTargetRefusal RuleTargetUnbuilt(string target, IEnumerable<string> reasons)
    {
        var name = KotlinText.Trim(target);
        return new RuleTargetRefusal(name, string.Format(ResUI.MsgRoutingRuleTargetUnbuilt, name), [.. reasons]);
    }

    /// <summary>
    /// Refuses the context of <paramref name="result" /> for <paramref name="refusal" />: its message and reasons as errors,
    /// once for a target that several rules send to, which <paramref name="told" /> keeps.
    /// </summary>
    private static void RefuseRuleTarget(NodeValidatorResult result, HashSet<string> told, RuleTargetRefusal refusal)
    {
        if (!told.Add(refusal.Name))
        {
            return;
        }
        Logging.SaveLog($"Routing rule target '{refusal.Name}': the configuration is refused: {string.Join("; ", [refusal.Message, .. refusal.Reasons])}");
        result.Errors.Add(refusal.Message);
        result.Errors.AddRange(refusal.Reasons);
    }

    /// <summary>
    /// Why the chain <paramref name="resolved" /> that the subscription of <paramref name="target" /> put around it cannot
    /// carry a routing rule, as a result with that error and the warnings of <paramref name="resolution" />; null when it
    /// can, or when <paramref name="resolved" /> is the target itself. The traversal of a chain leaves out a hop that fails
    /// its checks with a warning, which would send the rule a shorter way than its subscription names:
    /// <list type="bullet">
    /// <item>without the target itself, the rule would leave by its neighbours alone and never reach the profile it names;</item>
    /// <item>
    /// with <paramref name="carriedBehind" />, the context is the one of the core in front of another (sing-box in front of
    /// Xray under the legacy TUN) whose routing has the same rule and builds the same chain with its own checks: the rule
    /// goes to that core, the proxy here, rather than the way this core can build without a neighbour.
    /// </item>
    /// </list>
    /// </summary>
    private static async Task<NodeValidatorResult?> RuleChainShortfallAsync(
        ProfileItem target,
        ProfileItem resolved,
        NodeValidatorResult resolution,
        bool carriedBehind)
    {
        if (resolved.IndexId == target.IndexId || resolved.ConfigType != EConfigType.ProxyChain)
        {
            return null;
        }
        // The traversal leaves the hops it built in the chain's ChildItems.
        var built = (Utils.String2List(resolved.GetProtocolExtra().ChildItems) ?? []).ToHashSet();
        string? lost = null;
        if (!built.Contains(target.IndexId))
        {
            lost = target.Remarks;
        }
        else if (carriedBehind)
        {
            // The hops the subscription names, as BuildSubscriptionChainNodeAsync found them for the chain.
            var (named, _) = await BuildSubscriptionChainNodeAsync(target);
            if ((Utils.String2List(named?.GetProtocolExtra().ChildItems) ?? []).FirstOrDefault(id => !built.Contains(id)) is { } lostId)
            {
                lost = (await ConfigDbQuery.GetProfileItem(lostId))?.Remarks ?? lostId;
            }
        }
        if (lost == null)
        {
            return null;
        }
        Logging.SaveLog($"Routing rule target '{target.Remarks}': the chain of its subscription lost '{lost}' and cannot carry the rule");
        return new NodeValidatorResult([string.Format(ResUI.MsgRoutingRuleChainHopNotBuilt, lost)], resolution.Warnings);
    }

    /// <summary>
    /// A policy group a rule sends to keeps its own strategy inside the chain of its subscription: the routing services
    /// read the strategy of the rule's node, the chain, which would otherwise have none and balance by the lowest ping.
    /// </summary>
    private static void KeepRuleGroupStrategy(ProfileItem target, ProfileItem resolved)
    {
        if (target.ConfigType != EConfigType.PolicyGroup || resolved.IndexId == target.IndexId)
        {
            return;
        }
        resolved.SetProtocolExtra(resolved.GetProtocolExtra() with { MultipleLoad = target.GetProtocolExtra().MultipleLoad });
    }

    /// <summary>
    /// What registering profiles adds to a context: the proxies, the protected names, the custom outbounds read and the
    /// exit-nodes looked up; taken before the profile of a routing rule is resolved and given back when the rule cannot
    /// use it. The WebAPI's preflight reads the proxies to tell whether the configuration needs the Aether core.
    /// </summary>
    private sealed class RuleTargetState
    {
        private readonly Dictionary<string, ProfileItem> _proxies;
        private readonly HashSet<string> _protectDomains;
        private readonly Dictionary<string, string> _customOutbounds;
        private readonly Dictionary<string, ExitNodeLookup> _exitNodes;

        private RuleTargetState(CoreConfigContext context)
        {
            _proxies = new Dictionary<string, ProfileItem>(context.AllProxiesMap);
            _protectDomains = [.. context.ProtectDomainList];
            _customOutbounds = new Dictionary<string, string>(context.CustomOutboundContent);
            _exitNodes = new Dictionary<string, ExitNodeLookup>(context.Aether.ExitNodes);
        }

        public static RuleTargetState Of(CoreConfigContext context)
        {
            return new RuleTargetState(context);
        }

        public void Restore(CoreConfigContext context)
        {
            Refill(context.AllProxiesMap, _proxies);
            context.ProtectDomainList.Clear();
            context.ProtectDomainList.UnionWith(_protectDomains);
            Refill(context.CustomOutboundContent, _customOutbounds);
            Refill(context.Aether.ExitNodes, _exitNodes);
        }

        private static void Refill<TValue>(Dictionary<string, TValue> target, Dictionary<string, TValue> saved)
        {
            target.Clear();
            foreach (var (key, value) in saved)
            {
                target[key] = value;
            }
        }
    }
}
