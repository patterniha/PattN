namespace ServiceLib.Aether;

/// <summary>
/// PattN: the rules for Aether profiles among the members of a proxy chain or a policy group (PattNG
/// ui/server/ProxyChainMembers.kt and core/CoreConfigContextBuilder.kt withOneAetherProfile). One core runs at a time, and
/// it serves one profile.
/// </summary>
public static class AetherMembers
{
    /// <summary>
    /// True when <paramref name="memberTypes" />, the types of a chain's members, hold more than one Aether profile. One
    /// can stand anywhere in the chain; a second would need a core of its own, and one core runs at a time.
    /// </summary>
    public static bool HasSecondAetherMember(IEnumerable<EConfigType?> memberTypes)
    {
        return memberTypes.Count(type => type == EConfigType.Aether) > 1;
    }

    /// <summary>
    /// Why a proxy chain or a policy group of <paramref name="groupType" /> run by <paramref name="coreType" /> cannot be
    /// saved with <paramref name="members" />, the profiles it holds (picked by hand and found by its filter alike), as a
    /// localized message; null when it can. sing-box runs no Aether profile, and a group or chain of its own would drop
    /// it, so a chain would carry the traffic another way than it names; a chain can have one Aether member.
    /// </summary>
    public static string? SaveProblem(EConfigType groupType, ECoreType coreType, IEnumerable<ProfileItem> members)
    {
        var list = members.ToList();
        if (coreType == ECoreType.sing_box && list.Any(member => member.ConfigType == EConfigType.Aether))
        {
            return string.Format(ResUI.MsgCoreNotSupportProtocol, nameof(ECoreType.sing_box), EConfigType.Aether);
        }
        if (groupType == EConfigType.ProxyChain && HasSecondAetherMember(list.Select(member => (EConfigType?)member.ConfigType)))
        {
            return ResUI.MsgAetherChainOneProfile;
        }
        return null;
    }

    /// <summary>
    /// The members a group editor saves, as <see cref="SaveProblem" /> counts them (PattNG proxyChainProblem counts the
    /// hops of every name listed): <paramref name="picked" />, those picked by hand as the editor lists them, one picked
    /// twice counted twice, then those the subscription filter of <paramref name="protocolExtra" /> finds. The stored
    /// members, read back, would count a profile picked twice once.
    /// </summary>
    public static async Task<List<ProfileItem>> EditorMembersAsync(IEnumerable<ProfileItem> picked, ProtocolExtraItem protocolExtra)
    {
        var members = picked.ToList();
        members.AddRange(await GroupProfileManager.GetChildProfileItemsByProtocolExtra(protocolExtra with { ChildItems = null }));
        return members;
    }

    /// <summary>
    /// <see cref="SaveProblem" /> for the group or chain <paramref name="group" /> saved with <paramref name="protocolExtra" />
    /// from elsewhere than its editor (the WebAPI): its members picked by hand as its ChildItems name them, one named twice
    /// counted twice, and those its subscription filter finds. A run by no core named is Xray's, as the API saves it.
    /// </summary>
    public static async Task<string?> SaveProblemAsync(ProfileItem group, ProtocolExtraItem protocolExtra)
    {
        var childIds = (Utils.String2List(protocolExtra.ChildItems) ?? []).Where(id => !id.IsNullOrEmpty()).ToList();
        var found = (await ConfigDbQuery.GetProfileItemsByIndexIds(childIds))
            .DistinctBy(profile => profile.IndexId)
            .ToDictionary(profile => profile.IndexId);
        var picked = childIds.Select(found.GetValueOrDefault).OfType<ProfileItem>();
        return SaveProblem(group.ConfigType, group.CoreType ?? ECoreType.Xray, await EditorMembersAsync(picked, protocolExtra));
    }

    /// <summary>
    /// Why a subscription cannot be saved with the previous profile <paramref name="prevProfile" /> and the next profile
    /// <paramref name="nextProfile" />, named as the subscription editor names them, as a localized message; null when it
    /// can. They chain every profile of the subscription, so either can be an Aether profile, not both: one core runs,
    /// and a chain can have one Aether profile. Each is found by its name as the chain finds it
    /// (<see cref="CoreConfigContextBuilder.FindSubscriptionNeighbourAsync(string?)" />): a name no profile has, or several
    /// have, names none of them here, never the first of them, and is refused for itself (N1,
    /// <see cref="CoreConfigContextBuilder.SubscriptionNamesProblemAsync" />).
    /// </summary>
    public static async Task<string?> SubscriptionProblemAsync(string? prevProfile, string? nextProfile)
    {
        var prev = await CoreConfigContextBuilder.FindSubscriptionNeighbourAsync(prevProfile);
        var next = await CoreConfigContextBuilder.FindSubscriptionNeighbourAsync(nextProfile);
        return HasSecondAetherMember([TypeOf(prev), TypeOf(next)]) ? ResUI.MsgAetherChainOneProfile : null;
    }

    /// <summary>The type of the one profile a name found; none for a name no profile has, or several have.</summary>
    private static EConfigType? TypeOf(ByName<ProfileItem> found)
    {
        return (found as ByName<ProfileItem>.One)?.Value.ConfigType;
    }

    /// <summary>
    /// The members of a policy group that stay, and those left out (PattNG withOneAetherProfile). A filter fills a group
    /// rather than named members, so it can catch several Aether profiles while one core serves one of them: the members
    /// <paramref name="isFilterBuilt" /> says the filter found keep the first Aether profile, together with any whose
    /// core is the same (<see cref="AetherCore.Of" /> on <paramref name="listenPort" />, arguments and exit-node), and the
    /// others are left out. The core of the first Aether member picked by hand counts first, since a member picked by
    /// hand is never left out: a group, a chain or a routing rule names its profiles, so a conflict among them is
    /// reported instead.
    /// </summary>
    public static (List<ProfileItem> Kept, List<ProfileItem> LeftOut) WithOneAetherProfile(
        IReadOnlyList<ProfileItem> members,
        Func<ProfileItem, bool> isFilterBuilt,
        int listenPort)
    {
        var aether = members.Where(member => member.ConfigType == EConfigType.Aether).ToList();
        var first = aether.FirstOrDefault(member => !isFilterBuilt(member)) ?? aether.FirstOrDefault();
        if (first == null)
        {
            return (members.ToList(), []);
        }
        var kept = AetherCore.Of(first, listenPort);
        var stays = new List<ProfileItem>();
        var leftOut = new List<ProfileItem>();
        foreach (var member in members)
        {
            if (member.ConfigType != EConfigType.Aether || !isFilterBuilt(member) || AetherCore.Of(member, listenPort) == kept)
            {
                stays.Add(member);
            }
            else
            {
                leftOut.Add(member);
            }
        }
        return (stays, leftOut);
    }
}
