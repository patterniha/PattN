namespace ServiceLib.Aether;

/// <summary>
/// PattN (design 2.12.1, critique 25): which profiles of one run of tests need an Aether core, and so leave the batch, in
/// which one Xray serves many profiles, for <see cref="AetherDelayTester" />, which tests them one at a time: an Aether
/// profile, a policy group or a proxy chain with one among its members, at whatever depth, and a profile whose
/// subscription chains it with one, as its previous or its next profile (CoreConfigContextBuilder wraps every profile of
/// such a subscription). It is told from the stored profiles, without building a configuration for each: the previous and
/// next profiles of a subscription are looked up once per subscription and run, by their names as the chain finds them
/// (<see cref="ByName{T}" />). The test of each such profile builds its configuration all the same, which has the last
/// word. Only a profile another core runs is built here, see <see cref="TakeAsync" />.
/// </summary>
/// <param name="refused">
/// Whether the checks a session start makes refuse a profile (CoreConfigContextBuilder.Build), but for the targets of the
/// routing rules, which a test drops; null leaves every profile another core than Xray runs to the batch.
/// </param>
public sealed class AetherTestCandidates(
    Func<string, Task<SubItem?>> subscription,
    Func<string, Task<ByName<ProfileItem>>> profileNamed,
    Func<ProfileItem, Task<IEnumerable<ProfileItem>>> members,
    Func<ProfileItem, Task<bool>>? refused = null)
{
    private readonly Dictionary<string, SubscriptionChain> _subscriptions = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Neighbour> _names = new(StringComparer.Ordinal);

    /// <summary>The candidates of PattN's own database.</summary>
    public static AetherTestCandidates FromDatabase()
    {
        return new AetherTestCandidates(
            subId => ConfigDbQuery.GetSubItem(subId),
            CoreConfigContextBuilder.FindSubscriptionNeighbourAsync,
            async group => (await GroupProfileManager.GetAllChildProfileItems(group)).Values,
            // As the test's own checks (AetherTestHost.Build): a routing rule's target never refuses a test (E2).
            async profile => !(await CoreConfigContextBuilder.Build(ConfigTextHandler.Config, profile, refuseRuleTargets: false)).ValidatorResult.Success);
    }

    /// <summary>
    /// Takes the items that need an Aether core out of <paramref name="items" />, and returns them in their order: those of
    /// <see cref="NeedsAetherAsync" /> that Xray runs, or, for a TCP ping, which opens no tunnel, the Aether profiles
    /// alone, whose edge it probes (a group or a chain keeps PattN's TCP ping). A profile another core runs, which runs no
    /// Aether profile, leaves only when the checks a session start makes refuse it: a chain with an Aether hop is built
    /// whole or not at all (critique 4), and the test of a single profile of that core, which skips the checks, would
    /// measure it the shorter way, without the hop; the tester refuses it (-1) as its session is refused. A group of that
    /// core, which leaves its Aether member out as its session does, stays. The others stay, in their order, for the batch.
    /// <para>
    /// A profile whose subscription names a previous or a next profile that no profile has, or several have, leaves as
    /// well (N1): whether that one holds Aether cannot be told, and the chain is refused for it whatever it holds, where
    /// the batch, which skips the checks, would measure the profile without that hop; the tester refuses it (-1) as its
    /// session is refused, as PattNG fails the test of such a profile.
    /// </para>
    /// </summary>
    public async Task<List<ServerTestItem>> TakeAsync(ESpeedActionType actionType, List<ServerTestItem> items)
    {
        var taken = new List<ServerTestItem>();
        foreach (var item in items)
        {
            if (actionType == ESpeedActionType.Tcping
                    ? item.ConfigType == EConfigType.Aether
                    : await LeavesTheBatchAsync(item))
            {
                taken.Add(item);
            }
        }
        if (taken.Count > 0)
        {
            var leaving = new HashSet<ServerTestItem>(taken, ReferenceEqualityComparer.Instance);
            items.RemoveAll(leaving.Contains);
        }
        return taken;
    }

    /// <summary>
    /// Whether <paramref name="profile" /> needs an Aether core: it is an Aether profile, a group or a chain with one among
    /// its members, or its subscription chains it with one. A name that no profile has, or several have, holds none.
    /// </summary>
    public async Task<bool> NeedsAetherAsync(ProfileItem profile)
    {
        if (await HoldsAetherAsync(profile).ConfigureAwait(false))
        {
            return true;
        }
        return (await ChainOfAsync(profile).ConfigureAwait(false)).HoldsAether;
    }

    /// <summary>Whether a latency or speed test of <paramref name="item" /> is the Aether tester's, see <see cref="TakeAsync" />.</summary>
    private async Task<bool> LeavesTheBatchAsync(ServerTestItem item)
    {
        var xray = item.CoreType == ECoreType.Xray;
        if (!xray && refused == null)
        {
            return false;
        }
        var profile = item.Profile ?? new ProfileItem { ConfigType = item.ConfigType };
        if (!await NeedsAetherAsync(profile).ConfigureAwait(false)
            && !(await ChainOfAsync(profile).ConfigureAwait(false)).Unresolved)
        {
            return false;
        }
        return xray || await refused!(profile).ConfigureAwait(false);
    }

    /// <summary>Whether <paramref name="profile" /> is an Aether profile, or a group or a chain with one among its members.</summary>
    private async Task<bool> HoldsAetherAsync(ProfileItem profile)
    {
        if (profile.ConfigType == EConfigType.Aether)
        {
            return true;
        }
        if (!profile.ConfigType.IsGroupType())
        {
            return false;
        }
        return (await members(profile).ConfigureAwait(false)).Any(member => member.ConfigType == EConfigType.Aether);
    }

    /// <summary>The chain the subscription of <paramref name="profile" /> puts around it, looked at once per subscription.</summary>
    private async Task<SubscriptionChain> ChainOfAsync(ProfileItem profile)
    {
        if (profile.Subid.IsNullOrEmpty() || profile.ConfigType == EConfigType.Custom)
        {
            return default;
        }
        if (!_subscriptions.TryGetValue(profile.Subid, out var chain))
        {
            chain = await SubscriptionChainAsync(profile.Subid).ConfigureAwait(false);
            _subscriptions[profile.Subid] = chain;
        }
        return chain;
    }

    /// <summary>
    /// What the previous and the next profile the subscription <paramref name="subId" /> names give: one that holds Aether,
    /// or a name that no profile has, or several have. A blank name names none, as the chain reads it.
    /// </summary>
    private async Task<SubscriptionChain> SubscriptionChainAsync(string subId)
    {
        var sub = await subscription(subId).ConfigureAwait(false);
        if (sub == null)
        {
            return default;
        }
        var unresolved = false;
        foreach (var name in new[] { sub.PrevProfile, sub.NextProfile })
        {
            var wanted = KotlinText.TrimOrNull(name);
            if (wanted.IsNullOrEmpty())
            {
                continue;
            }
            if (!_names.TryGetValue(wanted, out var neighbour))
            {
                neighbour = await profileNamed(wanted).ConfigureAwait(false) is ByName<ProfileItem>.One one
                    ? await HoldsAetherAsync(one.Value).ConfigureAwait(false) ? Neighbour.HoldsAether : Neighbour.Plain
                    : Neighbour.Unresolved;
                _names[wanted] = neighbour;
            }
            if (neighbour == Neighbour.HoldsAether)
            {
                // The profile leaves the batch whatever the other name finds.
                return new SubscriptionChain(true, unresolved);
            }
            unresolved |= neighbour == Neighbour.Unresolved;
        }
        return new SubscriptionChain(false, unresolved);
    }

    /// <summary>What a previous or next profile name finds: one profile, holding Aether or not, or none or several.</summary>
    private enum Neighbour
    {
        Plain,
        HoldsAether,
        Unresolved,
    }

    /// <summary>
    /// The chain a subscription puts around its profiles: whether a previous or next profile it names holds Aether, and
    /// whether one of the names finds no profile, or several (N1).
    /// </summary>
    private readonly record struct SubscriptionChain(bool HoldsAether, bool Unresolved);
}
