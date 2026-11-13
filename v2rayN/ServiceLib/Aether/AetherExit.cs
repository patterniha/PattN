using System.Globalization;

namespace ServiceLib.Aether;

/// <summary>
/// The exit-node of an Aether core (PattNG core/AetherCore.kt), the outbound that what the core dials out through
/// leaves Xray by. As a rule it is a plain freedom outbound with the finalMask, the dialMode and the tcpUserTimeout of
/// the core's Aether profile, as an ordinary profile sets them on its own outbound: an Aether profile's outbound only
/// reaches the core on the loopback address, where they would do nothing.
/// <para>
/// In a proxy chain where the Aether profile is not the entry hop, the core dials out through the hop on its entry side
/// instead: that hop's outbound, as the chain builds it, is the exit-node, and <see cref="Hops" /> tells those hops
/// apart. The profile's finalMask and dialMode do not count then, nor does its <see cref="Node" />.
/// </para>
/// <para>
/// Without a chain, the profile, or the WARP keys window, can name a profile of its own as the exit-node, one Xray can
/// build as a chain hop: <see cref="Node" />, by its name, as a chain names its hops. That profile's outbound is the
/// exit-node then, changed in its tag alone, and the finalMask and the dialMode do not count either. A name no profile
/// has any more, or several have, gives none (see <see cref="ExitNodeLookup" />).
/// </para>
/// </summary>
/// <param name="NodeContent">
/// A digest of the profile <see cref="Node" /> names, as <see cref="ContentOf" /> makes it, where it was looked up: as
/// <see cref="Hops" /> does for the hops of a chain, it tells the profile the core dials out through from the one that
/// has the name by now, which an update of its subscription may have changed. See <see cref="WithNodeContent" />.
/// </param>
/// <param name="TcpUserTimeout">
/// PattN: the tcpUserTimeout of the freedom exit-node, in milliseconds: the profile's where its core connects out over
/// TCP (TcpUserTimeoutRule.ValueOf), else null. The WARP keys window sets none.
/// </param>
public sealed record AetherExit(
    string? FinalMask = null,
    string? DialMode = null,
    string? Hops = null,
    string? Node = null,
    string? NodeContent = null,
    int? TcpUserTimeout = null)
{
    /// <summary>An exit-node with nothing set: a freedom outbound with neither finalMask nor dialMode.</summary>
    public static readonly AetherExit Plain = new();

    /// <summary>
    /// What tells this exit-node from another without what it is made of: a SHA-256 digest of it (lowercase hex). A
    /// node and its content join only where there are some, and so does a tcpUserTimeout, named, so that the key of any
    /// other exit-node stays what it was.
    /// </summary>
    public string Key
    {
        get
        {
            var parts = new[] { FinalMask, DialMode, Hops }.Concat(new[] { Node, NodeContent }.Where(part => part != null));
            if (TcpUserTimeout is { } tcpUserTimeout)
            {
                parts = parts.Append($"tcpUserTimeout={tcpUserTimeout.ToString(CultureInfo.InvariantCulture)}");
            }
            return Digest(string.Join('\u0000', parts.Select(part => part ?? string.Empty)));
        }
    }

    /// <summary>
    /// This exit-node with the content of the profile its <see cref="Node" /> names, as <paramref name="find" /> finds
    /// it, see <see cref="NodeContent" />: as it is without a node, or with one no profile, or several, have the name
    /// of, which no core dials out through. <paramref name="outboundText" /> reads the outbound of a custom outbound
    /// profile, see <see cref="ContentOf" />.
    /// </summary>
    public AetherExit WithNodeContent(Func<string, ByName<ProfileItem>> find, Func<ProfileItem, string?>? outboundText = null)
    {
        if (Node == null)
        {
            return this;
        }
        return find(Node) is ByName<ProfileItem>.One one ? this with { NodeContent = ContentOf(one.Value, outboundText) } : this;
    }

    /// <summary>
    /// The exit-node of the core of <paramref name="profile" />: the profile it names as its node, or else a plain one
    /// with its finalMask and dialMode, and its tcpUserTimeout where the core connects out over TCP.
    /// </summary>
    public static AetherExit Of(ProfileItem profile)
    {
        var node = KotlinText.NullIfBlank(profile.GetProtocolExtra().AetherExitNode);
        if (node != null)
        {
            return new AetherExit(Node: KotlinText.Trim(node));
        }
        return new AetherExit(KotlinText.NullIfBlank(profile.Finalmask), KotlinText.NullIfBlank(profile.DialMode),
            TcpUserTimeout: TcpUserTimeoutRule.ValueOf(profile));
    }

    /// <summary>
    /// Whether <paramref name="profile" /> can be an exit-node: a single profile Xray builds, as a proxy chain takes it
    /// for a hop, and no Aether one, whose core is the one that dials out. PattN: a type Xray supports, or a custom
    /// outbound made for Xray; never a group, a chain, a custom configuration or a type sing-box alone runs, which would
    /// give no outbound.
    /// </summary>
    public static bool TakesAsNode(ProfileItem profile)
    {
        if (profile.ConfigType == EConfigType.Aether)
        {
            return false;
        }
        if (profile.ConfigType == EConfigType.Outbound)
        {
            return profile.CoreType == ECoreType.Xray;
        }
        return Global.XraySupportConfigType.Contains(profile.ConfigType);
    }

    /// <summary>What <paramref name="name" /> finds among those of <paramref name="profiles" /> that can be an exit-node, see <see cref="ByName{T}" />.</summary>
    public static ByName<ProfileItem> NodeProfile(string? name, IEnumerable<ProfileItem> profiles)
    {
        return ByName.Find(name, profiles.Where(TakesAsNode), profile => profile.Remarks);
    }

    /// <summary>
    /// The names those of <paramref name="profiles" /> that can be an exit-node have, each once, in their order, with
    /// how many have it: a name several have names none of them, see <see cref="ByName{T}" />. A profile without a
    /// name is left out, for none names it.
    /// </summary>
    public static List<AetherExitNode> NodesOf(IEnumerable<ProfileItem> profiles)
    {
        var counts = new Dictionary<string, int>();
        var names = new List<string>();
        foreach (var profile in profiles.Where(TakesAsNode))
        {
            var name = KotlinText.TrimOrNull(profile.Remarks) ?? string.Empty;
            if (name.Length == 0)
            {
                continue;
            }
            if (counts.TryGetValue(name, out var count))
            {
                counts[name] = count + 1;
            }
            else
            {
                counts[name] = 1;
                names.Add(name);
            }
        }
        return names.Select(name => new AetherExitNode(name, counts[name])).ToList();
    }

    /// <summary>
    /// Whether an exit-node takes <paramref name="finalMask" />: blank, or a JSON object, read by the parser JsonUtils
    /// uses, which logs nothing for text that is not one, since a typing mistake is no failure. The Aether editor and
    /// the WARP keys window check theirs alike.
    /// </summary>
    public static bool TakesFinalMask(string? finalMask)
    {
        return KotlinText.IsBlank(finalMask) || JsonUtils.ParseJson(finalMask) is JsonObject;
    }

    /// <summary>
    /// The exit-node of an Aether hop of a proxy chain that dials out through <paramref name="hops" />: the hops on its
    /// entry side, in the order a chain lists its profiles, from the one it dials out through, which is the exit-node,
    /// to the entry hop. They are told apart by a digest of their profiles, which hold secrets, see
    /// <see cref="ContentOf" />, which <paramref name="outboundText" /> is for as well.
    /// </summary>
    public static AetherExit Through(IEnumerable<ProfileItem> hops, Func<ProfileItem, string?>? outboundText = null)
    {
        return new AetherExit(Hops: Digest(JsonUtils.Serialize(hops.Select(hop => IdentityOf(hop, outboundText)).ToList(), false)));
    }

    /// <summary>
    /// The digest <see cref="NodeContent" /> holds of <paramref name="profile" />, the exit-node a <see cref="Node" />
    /// names; it holds secrets as well. Like the digest of hops, see <see cref="Through" />, it covers what the profile
    /// connects with, not its name, its id or its subscription, which every update of its subscription renews: a node
    /// an update leaves as it was is the same node. The digests are compared inside PattN alone.
    /// <para>
    /// PattN: a custom outbound profile holds no more than the name of the file its outbound is in, which every import
    /// of a subscription copies under a new name, and which can be edited in place. What it connects with is that
    /// outbound, which <paramref name="outboundText" /> reads for such a profile as the configuration reads it
    /// (CoreConfigContext.CustomOutboundContent); without it, or without the file, the file name tells it apart. Digests
    /// that are compared with each other have to be taken the same way.
    /// </para>
    /// </summary>
    public static string ContentOf(ProfileItem profile, Func<ProfileItem, string?>? outboundText = null)
    {
        return Digest(JsonUtils.Serialize(IdentityOf(profile, outboundText), false));
    }

    /// <summary>
    /// <paramref name="profile" /> without what a subscription's update renews (PattNG ProfileItem.duplicateIdentity):
    /// a copy with the id, the name, the subscription, the version and PattN's per-row settings cleared, and for a custom
    /// outbound profile the outbound <paramref name="outboundText" /> reads in place of its file name.
    /// </summary>
    private static ProfileItem IdentityOf(ProfileItem profile, Func<ProfileItem, string?>? outboundText)
    {
        var identity = JsonUtils.DeepCopy(profile) ?? new ProfileItem();
        identity.IndexId = string.Empty;
        identity.Remarks = string.Empty;
        identity.Subid = string.Empty;
        identity.IsSub = false;
        identity.ConfigVersion = 0;
        identity.PreSocksPort = null;
        identity.DisplayLog = false;
        if (profile.ConfigType == EConfigType.Outbound && outboundText?.Invoke(profile) is { } text)
        {
            identity.Address = OutboundIdentity(text);
        }
        return identity;
    }

    /// <summary>
    /// The outbound <paramref name="text" /> holds, without the tag the configuration gives it anew and on one line, so
    /// that an edit of its layout alone leaves it the same outbound; text that is no JSON object counts as it is written.
    /// </summary>
    private static string OutboundIdentity(string text)
    {
        if (JsonUtils.ParseJson(text) is not JsonObject outbound)
        {
            return text;
        }
        outbound.Remove("tag");
        return outbound.ToJsonString();
    }

    private static string Digest(string text)
    {
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
    }
}

/// <summary>
/// A <paramref name="Name" /> the profiles that can be the exit-node of an Aether core have, see
/// <see cref="AetherExit.Node" />, and how many <paramref name="Profiles" /> have it; with more than one, it names none
/// of them.
/// </summary>
public sealed record AetherExitNode(string Name, int Profiles);

/// <summary>
/// What a profile name finds (PattNG dto/ByName.kt), as a proxy chain names its hops, and an Aether profile and the
/// WARP keys window their exit-node: the <see cref="One" /> profile that has it, <see cref="None" />, when none has it
/// any more, as after it was renamed or deleted, or <see cref="Several" />, among which the name cannot tell the one
/// meant. Names are told apart without the spaces around them, as the lists that offer them show them: the spaces
/// PattNG trims, see <see cref="KotlinText" />.
/// </summary>
public abstract record ByName<T>
{
    private ByName()
    {
    }

    public sealed record One(T Value) : ByName<T>;

    public sealed record None : ByName<T>
    {
        public static readonly None Instance = new();
    }

    public sealed record Several : ByName<T>
    {
        public static readonly Several Instance = new();
    }
}

/// <summary>The search behind <see cref="ByName{T}" />.</summary>
public static class ByName
{
    /// <summary>
    /// What <paramref name="name" /> finds among <paramref name="items" />, whose names <paramref name="nameOf" />
    /// gives; a blank name finds none. The items are read as the search goes, and it ends at the second one with the
    /// name.
    /// </summary>
    public static ByName<T> Find<T>(string? name, IEnumerable<T> items, Func<T, string?> nameOf)
    {
        var wanted = KotlinText.TrimOrNull(name) ?? string.Empty;
        if (wanted.Length == 0)
        {
            return ByName<T>.None.Instance;
        }
        ByName<T>.One? found = null;
        foreach (var item in items)
        {
            if ((KotlinText.TrimOrNull(nameOf(item)) ?? string.Empty) != wanted)
            {
                continue;
            }
            if (found != null)
            {
                return ByName<T>.Several.Instance;
            }
            found = new ByName<T>.One(item);
        }
        return found ?? (ByName<T>)ByName<T>.None.Instance;
    }
}

/// <summary>
/// What the name of the profile an Aether core dials out through gives (PattNG ExitNodeOutbound), see
/// <see cref="AetherExit.Node" />: the <see cref="One" /> profile that has it, which the configuration builds as a
/// chain builds a hop, or the <see cref="Problem" /> that leaves the core without an exit-node.
/// </summary>
public abstract record ExitNodeLookup
{
    private ExitNodeLookup()
    {
    }

    /// <summary>
    /// The lookup <paramref name="found" /> gives: the one profile, with its digest taken as
    /// <see cref="AetherExit.ContentOf" /> takes it with <paramref name="outboundText" />, or why there is none.
    /// </summary>
    public static ExitNodeLookup Of(ByName<ProfileItem> found, Func<ProfileItem, string?>? outboundText = null)
    {
        return found switch
        {
            ByName<ProfileItem>.One one => new One(one.Value, AetherExit.ContentOf(one.Value, outboundText)),
            ByName<ProfileItem>.Several => SameName.Instance,
            _ => NotFound.Instance,
        };
    }

    /// <summary>
    /// The one <paramref name="Profile" /> that has the name, and its <paramref name="Content" />: the digest of the
    /// profile, see <see cref="AetherExit.ContentOf" />, taken when it was found.
    /// </summary>
    public sealed record One(ProfileItem Profile, string Content) : ExitNodeLookup;

    /// <summary>Why there is no exit-node, with the ResUI key of the message that tells it, whose argument is the name.</summary>
    public abstract record Problem : ExitNodeLookup
    {
        private protected Problem()
        {
        }

        /// <summary>The ResUI key of the message (the keys come with the strings of the Xray configuration stage).</summary>
        public abstract string MessageKey { get; }
    }

    /// <summary>No profile that can be an exit-node has the name any more: it was renamed or deleted.</summary>
    public sealed record NotFound : Problem
    {
        public static readonly NotFound Instance = new();

        public override string MessageKey => "MsgAetherExitNodeNotFound";
    }

    /// <summary>Several have it, and the name cannot tell the one meant.</summary>
    public sealed record SameName : Problem
    {
        public static readonly SameName Instance = new();

        public override string MessageKey => "MsgAetherExitNodeDuplicate";
    }

    /// <summary>The one that has it gives no outbound.</summary>
    public sealed record NoOutbound : Problem
    {
        public static readonly NoOutbound Instance = new();

        public override string MessageKey => "MsgAetherExitNodeUnusable";
    }

    /// <summary>
    /// The one that has it has an ECH outbound that cannot go beside it: one no configuration takes, or one tagged
    /// exit-node, as the profile's own outbound is here.
    /// </summary>
    public sealed record EchUnusable : Problem
    {
        public static readonly EchUnusable Instance = new();

        public override string MessageKey => "MsgAetherExitNodeEchUnusable";
    }
}
