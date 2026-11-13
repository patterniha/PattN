using System.Globalization;

namespace ServiceLib.Aether;

/// <summary>
/// The Aether core a configuration runs on (PattNG core/AetherCore.kt), as the arguments its process is started with,
/// the listeners among them. The core of a profile is built from the profile's settings, or is the command line the
/// profile carries in their place. A command line is read as written and run as written, so that what the profile
/// says is what runs. Two cores with the same arguments are one core, which is how one process comes to serve several
/// outbounds, as long as they dial out through the same <see cref="Exit" /> as well: a process dials out through one.
/// </summary>
public sealed record AetherCore
{
    /// <summary>The name a command line starts with; the app runs its own copy of the core whatever the name says.</summary>
    public const string CommandName = "aether";

    /// <summary>
    /// The listeners a core may be told to bind: the core's own, Tor's, Psiphon's, and the HTTP proxies a command written
    /// by hand may open beside them.
    /// </summary>
    private static readonly string[] Listeners =
    [
        "--bind",
        AetherArguments.TorBind,
        AetherArguments.PsiphonBind,
        AetherArguments.HttpProxy,
        AetherArguments.TorHttp,
        AetherArguments.PsiphonHttp,
    ];

    /// <summary>The HTTP proxies among <see cref="Listeners" />, which a blank address or "off" turns off.</summary>
    private static readonly HashSet<string> HttpListeners = [AetherArguments.HttpProxy, AetherArguments.TorHttp, AetherArguments.PsiphonHttp];

    /// <summary>Whether the system opens an IPv6 socket to IPv4 as well, see <see cref="AetherArguments.ReachesLoopback" />: all but Windows.</summary>
    private static readonly bool DualStack = !OperatingSystem.IsWindows();

    private readonly IReadOnlyList<string> _arguments = [];

    public AetherCore(IReadOnlyList<string> arguments, AetherExit? exit = null)
    {
        Arguments = arguments;
        Exit = exit ?? AetherExit.Plain;
    }

    /// <summary>The arguments the process is started with, without the program name; a copy of what was given.</summary>
    public IReadOnlyList<string> Arguments
    {
        get => _arguments;
        init => _arguments = Array.AsReadOnly(value.ToArray());
    }

    /// <summary>The exit-node what the core dials out through leaves Xray by.</summary>
    public AetherExit Exit { get; init; }

    /// <summary>
    /// The loopback port the app dials: Psiphon's or Tor's listener when one of them runs inside the tunnel and is what
    /// the app reaches, the core's own listener otherwise. Every core <see cref="Of" /> and <see cref="OfCommand" />
    /// give names one; arguments that name none give the default listen port.
    /// </summary>
    public int Port => AetherArguments.ListenerPortOf(Arguments) ?? AetherPorts.DefaultListenPort;

    /// <summary>
    /// Every port the core listens on as its modes run, its HTTP proxies' too, see <see cref="ListenerGroups" />: the
    /// ports it is told, and its defaults for the listeners it is not told about (PattNG AetherCore.ports); an inbound of
    /// the configuration cannot share one.
    /// </summary>
    public List<int> Ports => PortsOf(BoundListeners()).Distinct().ToList();

    /// <summary>
    /// The first port two of the listeners the core holds at one time share, as a command written by hand may name; null
    /// when each has a port of its own (PattNG AetherCore.sharedPort). The core would bind one of them and fail on the
    /// other. Ports are told apart by number, as everywhere else in the app. Tor or Psiphon alone lets the core's own HTTP
    /// proxy go before that carrier's is bound, so those two may share a port, see <see cref="ListenerGroups" />.
    /// </summary>
    public int? SharedPort
    {
        get
        {
            foreach (var group in ListenerGroups())
            {
                var seen = new HashSet<int>();
                foreach (var port in PortsOf(group))
                {
                    if (!seen.Add(port))
                    {
                        return port;
                    }
                }
            }
            return null;
        }
    }

    /// <summary>
    /// The first option of a listener the core binds whose address the core does not take; null when it takes each
    /// (PattNG AetherCore.invalidListener). The core reads each as an IP address and a port, and where it cannot read one
    /// it quietly listens on its default, for its own, Tor's or Psiphon's listener, or not at all, for an HTTP proxy,
    /// while the app would go by the address written (aether lib.rs, tor.rs and psiphon.rs). A blank address, or "off",
    /// turns an HTTP proxy off. A message names the option, not the address, which is free text the log must not carry.
    /// </summary>
    public string? InvalidListener => BoundListeners().FirstOrDefault(flag =>
        AetherArguments.ListenerAddressAfter(Arguments, flag) is { } address
        && !AetherArguments.IsSocketAddress(address)
        && !(HttpListeners.Contains(flag) && address is "" or "off"));

    /// <summary>
    /// The option of the listener the app dials, see <see cref="AetherArguments.ListenerFlagOf" />, when the core takes its
    /// address but the app does not reach it there (PattNG AetherCore.unreachableListener); null when it does, or when the
    /// command names none and the app gives it one. The app dials the core on 127.0.0.1 (the Xray outbound, the readiness
    /// probe, the port checks), which a listener on 0.0.0.0 answers as well, and one on :: outside Windows, see
    /// <see cref="AetherArguments.ReachesLoopback" />, but one on 127.0.0.2, ::1 or a network's address does not: the
    /// session would stay connecting.
    /// </summary>
    public string? UnreachableListener
    {
        get
        {
            var flag = AetherArguments.ListenerFlagOf(Arguments);
            if (AetherArguments.ListenerAddressAfter(Arguments, flag) is not { } address || !AetherArguments.IsSocketAddress(address))
            {
                return null;
            }
            return AetherArguments.ReachesLoopback(address[..address.LastIndexOf(':')], DualStack) ? null : flag;
        }
    }

    /// <summary>
    /// The ports of <paramref name="listeners" />, in their order, but 0, which asks for any port: the port the arguments
    /// name, or the core's default for a listener they leave out, see <see cref="AetherArguments.DefaultListenerPorts" />.
    /// A command written by hand that names only Tor's listener still has the core's own on 1819.
    /// </summary>
    private IEnumerable<int> PortsOf(IEnumerable<string> listeners)
    {
        foreach (var flag in listeners)
        {
            int? port = Arguments.Contains(flag)
                ? AetherArguments.PortAfter(Arguments, flag)
                : AetherArguments.DefaultListenerPorts.TryGetValue(flag, out var fallback) ? fallback : null;
            if (port is { } value and not 0)
            {
                yield return value;
            }
        }
    }

    /// <summary>Every listener option the core binds as its arguments run it, in the order of <see cref="Listeners" />, see <see cref="ListenerGroups" />.</summary>
    private IEnumerable<string> BoundListeners()
    {
        var bound = ListenerGroups().SelectMany(group => group).ToHashSet();
        return Listeners.Where(bound.Contains);
    }

    /// <summary>
    /// The listener options the core binds as its arguments run it, in the groups it holds at one time (PattNG
    /// AetherCore.listenerGroups): its own and its HTTP proxy always, Tor's listener with Tor inside or around the tunnel
    /// and Tor's HTTP proxy with Tor run in any way, and the same for Psiphon, all of them for the whole run. An option of
    /// a mode that does not run binds nothing (aether lib.rs, tor.rs and psiphon.rs). Tor or Psiphon alone, see
    /// <see cref="AetherArguments.AloneOf" />: the core binds its own listener and its own HTTP proxy as it starts, then
    /// lets that HTTP proxy go and serves its own listener with Tor or Psiphon, which binds that carrier's HTTP proxy
    /// (lib.rs, Listeners::bind and into_socks). A registration of keys serves no proxy of its own, and binds only the
    /// listeners of a carrier around the tunnel, which carries its requests: that carrier's own and its HTTP proxy (lib.rs,
    /// register_identities; tor.rs and psiphon.rs, start_reverse).
    /// </summary>
    private List<List<string>> ListenerGroups()
    {
        var tor = AetherArguments.TorModeOf(Arguments);
        var psiphon = AetherArguments.PsiphonModeOf(Arguments);
        if (Arguments.Contains(AetherKeys.RegisterFlag))
        {
            return
            [
                Listeners.Where(flag =>
                    (tor == AetherTor.Reverse && flag is AetherArguments.TorBind or AetherArguments.TorHttp)
                    || (psiphon == AetherPsiphon.Reverse && flag is AetherArguments.PsiphonBind or AetherArguments.PsiphonHttp)).ToList(),
            ];
        }
        if (AetherArguments.AloneOf(Arguments) != null)
        {
            var aloneHttp = tor == AetherTor.Only ? AetherArguments.TorHttp : AetherArguments.PsiphonHttp;
            return [["--bind", AetherArguments.HttpProxy], ["--bind", aloneHttp]];
        }
        return
        [
            Listeners.Where(flag => flag switch
            {
                AetherArguments.TorBind => tor == AetherTor.Chain || tor == AetherTor.Reverse,
                AetherArguments.TorHttp => tor != AetherTor.Off,
                AetherArguments.PsiphonBind => psiphon == AetherPsiphon.Chain || psiphon == AetherPsiphon.Reverse,
                AetherArguments.PsiphonHttp => psiphon != AetherPsiphon.Off,
                _ => true,
            }).ToList(),
        ];
    }

    /// <summary>The protocol, which tells whose identity files the core uses.</summary>
    public AetherProtocol Protocol => AetherArguments.ProtocolOf(Arguments);

    /// <summary>The tunnel as the names of its parts from the outside in, carriers included; see <see cref="AetherArguments.PathOf" />.</summary>
    public List<string> Path => AetherArguments.PathOf(Arguments);

    /// <summary>The command line a profile carries for this core; <see cref="OfCommand" /> reads it back.</summary>
    public string Command => string.Join(' ', new[] { CommandName }.Concat(Arguments).Select(Quoted));

    /// <summary>True when the core is told which proxy to dial out through, as a command written by hand may be.</summary>
    public bool HasUpstream => Arguments.Contains(AetherArguments.Upstream);

    /// <summary><see cref="Path" />, with the WARP protocol named by <paramref name="label" />, as a screen names it.</summary>
    public List<string> LabeledPath(Func<AetherProtocol, string> label)
    {
        return AetherArguments.PathOf(Arguments, label);
    }

    /// <summary>
    /// The tunnel as a row of the profile list names it (PattNG MainServerRowModels): the parts of the path from the
    /// outside in, joined by arrows, the WARP protocol named by <paramref name="label" /> when given.
    /// </summary>
    public string PathLabel(Func<AetherProtocol, string>? label = null)
    {
        return string.Join(" → ", AetherArguments.PathOf(Arguments, label));
    }

    /// <summary>True when a process started with <paramref name="processArguments" /> runs this core, on whatever SOCKS ports and at whatever log level.</summary>
    public bool RunsAs(IReadOnlyList<string> processArguments)
    {
        return AetherArguments.TunnelArguments(processArguments).SequenceEqual(AetherArguments.TunnelArguments(Arguments));
    }

    /// <summary>
    /// This core dialling out through the SOCKS inbound on <paramref name="port" /> of the loopback address, which Xray
    /// serves so that what the core sends leaves through Xray. A core told an upstream of its own keeps it.
    /// </summary>
    public AetherCore Through(int port)
    {
        if (HasUpstream)
        {
            return this;
        }
        var upstream = string.Create(CultureInfo.InvariantCulture, $"socks5://{Global.Loopback}:{port}");
        return this with { Arguments = [.. Arguments, AetherArguments.Upstream, upstream] };
    }

    /// <summary>Two cores are one when their arguments are the same words in the same order and they dial out through the same exit-node.</summary>
    public bool Equals(AetherCore? other)
    {
        return other is not null && Exit == other.Exit && Arguments.SequenceEqual(other.Arguments);
    }

    public override int GetHashCode()
    {
        var hash = new HashCode();
        foreach (var argument in Arguments)
        {
            hash.Add(argument);
        }
        hash.Add(Exit);
        return hash.ToHashCode();
    }

    private bool PrintMembers(StringBuilder builder)
    {
        builder.Append("Arguments = [").AppendJoin(", ", Arguments).Append("], Exit = ").Append(Exit);
        return true;
    }

    /// <summary>
    /// The core of <paramref name="profile" />: the command line it carries, or its settings as arguments on
    /// <paramref name="listenPort" />, the Aether listen port of the app, dialling out through the exit-node of its
    /// settings. The log level is the session's to add. A command the app cannot read is left aside for the settings;
    /// the profile editor refuses to store one. A command naming no listener gets one on <paramref name="listenPort" />.
    /// </summary>
    public static AetherCore Of(ProfileItem profile, int listenPort)
    {
        var command = profile.GetProtocolExtra().AetherCommand;
        var core = (KotlinText.IsBlank(command) ? null : OfCommand(command!, listenPort))
                   ?? new AetherCore(AetherArguments.WithoutOption(AetherArguments.Build(profile, listenPort), "--log-level"));
        return core with { Exit = AetherExit.Of(profile) };
    }

    /// <summary>
    /// The core <paramref name="command" /> describes, or null when it names nothing the app can run: no argument at
    /// all, or a listener whose port cannot be read. Words are split on whitespace, quotes keep a word together, and a
    /// program name in front is dropped. A command that names no listener for the app to dial gets one on
    /// <paramref name="listenPort" />, the port the Aether outbounds of the app dial; the core's own defaults are other
    /// ports, which nothing in the app dials.
    /// </summary>
    public static AetherCore? OfCommand(string command, int listenPort)
    {
        var arguments = ReadableArguments(command);
        if (arguments == null)
        {
            return null;
        }
        var listener = AetherArguments.ListenerFlagOf(arguments);
        if (!arguments.Contains(listener))
        {
            return new AetherCore(AetherArguments.WithListener(arguments, listener, listenPort));
        }
        return new AetherCore(arguments);
    }

    /// <summary>
    /// Whether what the app sends through the core of <paramref name="profile" /> leaves it through WARP, rather than
    /// through Tor or Psiphon, see <see cref="AetherArguments.LeavesThroughWarp(IReadOnlyList{string})" />: as the
    /// command line the profile carries says, or else, as for <see cref="Of" />, as its settings say.
    /// </summary>
    public static bool LeavesThroughWarp(ProfileItem profile)
    {
        var extra = profile.GetProtocolExtra();
        var arguments = KotlinText.IsBlank(extra.AetherCommand) ? null : ReadableArguments(extra.AetherCommand!);
        if (arguments != null)
        {
            return AetherArguments.LeavesThroughWarp(arguments);
        }
        return AetherArguments.LeavesThroughWarp(AetherTor.FromString(extra.AetherTor), AetherPsiphon.FromString(extra.AetherPsiphon));
    }

    /// <summary>
    /// Whether the core of <paramref name="profile" /> connects out over TCP, see
    /// <see cref="AetherArguments.ConnectsOverTcp(IReadOnlyList{string})" />: as the command line the profile carries says,
    /// or else, as for <see cref="Of" />, as its settings say.
    /// </summary>
    public static bool ConnectsOverTcp(ProfileItem profile)
    {
        var extra = profile.GetProtocolExtra();
        var arguments = KotlinText.IsBlank(extra.AetherCommand) ? null : ReadableArguments(extra.AetherCommand!);
        if (arguments != null)
        {
            return AetherArguments.ConnectsOverTcp(arguments);
        }
        return AetherArguments.ConnectsOverTcp(AetherProtocol.FromString(extra.AetherProtocol), AetherTransport.FromString(extra.AetherTransport),
            AetherTor.FromString(extra.AetherTor), AetherPsiphon.FromString(extra.AetherPsiphon));
    }

    /// <summary>The arguments of <paramref name="command" />: its <see cref="Words" />, without a program name in front.</summary>
    public static List<string> ArgumentsOf(string command)
    {
        var words = Words(command);
        if (words.Count > 0 && !words[0].StartsWith('-'))
        {
            words.RemoveAt(0);
        }
        return words;
    }

    /// <summary>
    /// The words of a command line: split on whitespace as PattNG splits it (see <see cref="KotlinText" />), with single
    /// or double quotes keeping a word together. There
    /// are no escapes, a quote opens a word even when nothing follows it ("" is an empty word), and an unclosed quote
    /// runs to the end. The words are passed to the process one by one, so no shell or Windows quoting rule changes one.
    /// </summary>
    public static List<string> Words(string command)
    {
        var words = new List<string>();
        var word = new StringBuilder();
        char? quote = null;
        var open = false;
        foreach (var c in command)
        {
            if (quote != null)
            {
                if (c == quote)
                {
                    quote = null;
                }
                else
                {
                    word.Append(c);
                }
            }
            else if (c is '"' or '\'')
            {
                quote = c;
                open = true;
            }
            else if (KotlinText.IsWhitespace(c))
            {
                if (open)
                {
                    words.Add(word.ToString());
                    word.Clear();
                    open = false;
                }
            }
            else
            {
                word.Append(c);
                open = true;
            }
        }
        if (open)
        {
            words.Add(word.ToString());
        }
        return words;
    }

    /// <summary>
    /// The arguments of <paramref name="command" /> when it names something the app can run, see
    /// <see cref="OfCommand" />: not no argument at all, nor a listener whose port cannot be read. Null otherwise.
    /// </summary>
    private static List<string>? ReadableArguments(string command)
    {
        var arguments = ArgumentsOf(command);
        if (arguments.Count == 0)
        {
            return null;
        }
        var listener = AetherArguments.ListenerFlagOf(arguments);
        return !arguments.Contains(listener) || AetherArguments.PortAfter(arguments, listener) != null ? arguments : null;
    }

    /// <summary><paramref name="word" /> as a command line carries it: quoted when whitespace would split it.</summary>
    private static string Quoted(string word)
    {
        return word.Length == 0 || word.Any(KotlinText.IsWhitespace) ? $"\"{word}\"" : word;
    }
}
