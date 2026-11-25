namespace ServiceLib.Handler.Builder;

/// <summary>
/// PattN (N1, N2; PattNG CoreConfigContextBuilder.kt resolveProxyChainProfilesFromGroup, SubEditViewModel.kt and
/// RoutingEditViewModel.kt; memory "profile references by name"): the previous and the next profile a subscription names,
/// and the profile a routing rule sends to, are found by their names, the spaces around them aside
/// (<see cref="ByName{T}" />), which tell the one profile that has a name from none, as after a rename or a delete, and from
/// several, among which the name cannot tell the one meant. A name none or several have is refused with PattNG's words,
/// never taken for the first of them, nor left out of a chain that then runs a shorter way: the session is refused for
/// it, the subscription editor and the routing rule editor do not save it, and a latency test never measures such a
/// profile without that hop.
/// </summary>
public partial class CoreConfigContextBuilder
{
    /// <summary>
    /// Whether <paramref name="profile" /> can be the previous or the next profile a subscription chains its profiles with:
    /// any profile but a custom configuration, which is no outbound a chain can pass through (PattNG takesAsHop; the
    /// subscription editor's picker hides it too). A name that only a custom configuration has names no profile here.
    /// </summary>
    public static bool TakesAsSubscriptionNeighbour(ProfileItem profile)
    {
        return profile.ConfigType != EConfigType.Custom;
    }

    /// <summary>
    /// What the previous or the next profile <paramref name="name" /> of a subscription finds among the profiles a chain
    /// can pass through (<see cref="TakesAsSubscriptionNeighbour" />); a blank name finds none.
    /// </summary>
    public static async Task<ByName<ProfileItem>> FindSubscriptionNeighbourAsync(string? name)
    {
        var named = await ConfigDbQuery.GetProfileItemsViaRemarksAsync(name);
        return ByName.Find(name, named.Where(TakesAsSubscriptionNeighbour), profile => profile.Remarks);
    }

    /// <summary>
    /// Why the profile name <paramref name="name" />, which found <paramref name="found" />, cannot be used, as PattNG
    /// tells it, with the name trimmed: no profile has it, or several have it, of which one has to be renamed; null when
    /// it found the one profile.
    /// </summary>
    public static string? NameProblem(ByName<ProfileItem> found, string? name)
    {
        var trimmed = KotlinText.TrimOrNull(name) ?? string.Empty;
        return found switch
        {
            ByName<ProfileItem>.None => string.Format(ResUI.MsgRoutingRuleTargetNotFound, trimmed),
            ByName<ProfileItem>.Several => string.Format(ResUI.MsgRoutingRuleTargetDuplicate, trimmed),
            _ => null,
        };
    }

    /// <summary>
    /// The profile the previous or the next profile <paramref name="name" /> of a subscription finds; null when the name
    /// is blank, which names none, and when no profile has it, or several have it, which adds why to the errors of
    /// <paramref name="result" /> (N1).
    /// </summary>
    private static async Task<ProfileItem?> FindSubscriptionNeighbourAsync(string? name, NodeValidatorResult result)
    {
        if (KotlinText.TrimOrNull(name).IsNullOrEmpty())
        {
            return null;
        }
        var found = await FindSubscriptionNeighbourAsync(name);
        if (NameProblem(found, name) is { } problem)
        {
            result.Errors.Add(problem);
            return null;
        }
        return (found as ByName<ProfileItem>.One)?.Value;
    }

    /// <summary>
    /// Why a subscription cannot be saved with the previous profile <paramref name="prevProfile" /> and the next profile
    /// <paramref name="nextProfile" />, named as its editor names them, as a localized message: the first of the names that
    /// no profile has, or several have, as the chain it puts around each of its profiles finds them when it runs (N1,
    /// PattNG SubEditViewModel); null when each finds its one profile or is blank.
    /// </summary>
    public static async Task<string?> SubscriptionNamesProblemAsync(string? prevProfile, string? nextProfile)
    {
        var result = NodeValidatorResult.Empty();
        await FindSubscriptionNeighbourAsync(prevProfile, result);
        await FindSubscriptionNeighbourAsync(nextProfile, result);
        return result.Errors.FirstOrDefault();
    }

    /// <summary>
    /// Why the chain the subscription of <paramref name="node" /> puts around it is refused, its errors joined; null when
    /// it is not, or when the subscription chains nothing. For a test that measures a profile by a context it does not
    /// check: such a profile is never measured without a hop its subscription names (N1).
    /// </summary>
    public static async Task<string?> SubscriptionChainRefusalAsync(ProfileItem node)
    {
        var (_, result) = await BuildSubscriptionChainNodeAsync(node);
        return result.Success ? null : string.Join("; ", result.Errors);
    }

    /// <summary>
    /// Why <paramref name="rule" /> cannot be saved with its target, as a localized message (N2, PattNG
    /// RoutingEditViewModel): its target names a profile, and the name has to find that one profile among those a rule can
    /// send to (<see cref="TakesAsRuleTarget" />), as at the start (<see cref="Build" />, which refuses the session for
    /// it); null when it does. Only what the start looks up is looked at: the target of an enabled rule that sends
    /// traffic, a rule of the DNS alone sending none; a built-in tag (proxy, direct, block) and none are no profile's name.
    /// </summary>
    public static async Task<string?> RuleTargetProblemAsync(RulesItem rule)
    {
        if (!rule.Enabled
            || rule.RuleType == ERuleType.DNS
            || rule.OutboundTag.IsNullOrEmpty()
            || Global.OutboundTags.Contains(rule.OutboundTag))
        {
            return null;
        }
        return NameProblem(await FindRuleTargetAsync(rule.OutboundTag), rule.OutboundTag);
    }
}
