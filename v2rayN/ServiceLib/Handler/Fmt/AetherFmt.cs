using System.Globalization;

namespace ServiceLib.Handler.Fmt;

// PattN: aether:// links and the reading of Aether settings (PattNG fmt/AetherFmt.kt).
public partial class AetherFmt : BaseFmt
{
    /// <summary>The scheme of an Aether link (PattNG EConfigType.AETHER), the one FmtHandler dispatches by.</summary>
    private static string Scheme => Global.ProtocolShares[EConfigType.Aether];

    /// <summary>The name a link without one gives its profile.</summary>
    private const string DefaultRemarks = "Aether";

    /// <summary>
    /// The profile an aether:// link describes, or null when it is no URI. Only what the core would take is kept of the
    /// MASQUE SNI, the ECH resolver and domain, the fragment ranges, the endpoint and the hops; every other value is taken
    /// as it comes, and the editor refuses a profile with a problem on its next save. A listen port an old link names
    /// counts no more, and no link names an exit-node.
    /// </summary>
    public static ProfileItem? Resolve(string str, out string msg)
    {
        msg = ResUI.ConfigurationFormatIncorrect;

        // The endpoint is read from the authority as the link writes it (see EndpointOf), not from .NET's Uri.
        var text = str.Trim();
        string? authority = null;
        if (text.StartsWith(Scheme, StringComparison.OrdinalIgnoreCase))
        {
            var end = text.IndexOfAny(['/', '?', '#'], Scheme.Length);
            authority = text[Scheme.Length..(end < 0 ? text.Length : end)];
        }
        var url = Utils.TryUri(str);
        if (url == null && authority != null && IsRegistryName(authority))
        {
            // java.net.URI, which PattNG reads a link with, takes an authority it cannot read as a host and a port for a
            // registry name, such as an IPv6 address without brackets or a port past 65535: the link stands without an
            // endpoint, and its profile scans. .NET's Uri refuses the whole link instead.
            url = Utils.TryUri(Scheme + text[(Scheme.Length + authority.Length)..]);
            authority = string.Empty;
        }
        if (url == null)
        {
            return null;
        }

        var query = Utils.ParseQueryString(url.Query);
        var protocol = AetherProtocol.FromString(query["protocol"]);
        var ech = query["ech"] == "1";

        var remarks = url.GetComponents(UriComponents.Fragment, UriFormat.Unescaped);
        ProfileItem item = new()
        {
            ConfigType = EConfigType.Aether,
            CoreType = ECoreType.Xray,
            Remarks = remarks.Length > 0 ? remarks : DefaultRemarks,
        };

        string? outer = null;
        string? inner = null;
        if (protocol.TwoHops)
        {
            var outerHop = AetherEndpoint.Parse(query["outer"]);
            var innerHop = AetherEndpoint.Parse(query["inner"]);
            if (innerHop != null && protocol.DistinctHops && innerHop.Host == outerHop?.Host)
            {
                innerHop = null;
            }
            outer = outerHop?.ToString();
            inner = innerHop?.ToString();
        }
        else
        {
            var endpoint = authority == null ? null : EndpointOf(authority);
            item.Address = endpoint?.Host ?? string.Empty;
            item.Port = endpoint?.Port ?? 0;
        }

        item.SetProtocolExtra(item.GetProtocolExtra() with
        {
            AetherProtocol = protocol.Type,
            AetherTransport = AetherTransport.FromString(query["transport"]).Type,
            // A name the core would not take is left out; the profile then follows the default.
            AetherMasqueSni = KotlinText.TrimOrNull(query["sni"]) is { } sni && protocol.OverMasque && IsMasqueSni(sni) ? sni : null,
            AetherScanMode = AetherScanMode.FromString(query["scan"]).Type,
            AetherObfuscation = AetherObfuscation.FromString(query["noize"]).Type,
            AetherIpVersion = AetherIpVersion.FromString(query["ip"]).Type,
            AetherFragment = query["fragment"] == "1",
            AetherFragmentSize = AetherRange.Parse(query["fragment_size"], AetherRange.FragmentSize)?.ToString(),
            AetherFragmentDelay = AetherRange.Parse(query["fragment_delay"], AetherRange.FragmentDelay)?.ToString(),
            AetherEch = ech,
            // A value the core would not take is left out; the profile then follows the default.
            AetherEchDns = KotlinText.TrimOrNull(query["ech_dns"]) is { } echDns && ech && IsEchDns(echDns) ? echDns : null,
            AetherEchDomain = KotlinText.TrimOrNull(query["ech_domain"]) is { } echDomain && ech && IsEchDomain(echDomain) ? echDomain : null,
            AetherFingerprint = query["fingerprint"] is { } fingerprint ? AetherFingerprint.FromString(fingerprint).Type : null,
            AetherDns = query["dns"],
            AetherExitLoc = query["exit_loc"],
            // A link from before the Aether listen port was one setting for every profile may name a port of its own
            // (listen), which counts no more.
            AetherPsiphon = OffAsNull(AetherPsiphon.FromString(query["psiphon"]).Type, AetherPsiphon.Off.Type),
            AetherPsiphonMode = query["psiphon_mode"] is { } psiphonMode ? AetherPsiphonMode.FromString(psiphonMode).Type : null,
            AetherPsiphonCdnIps = query["cdn_ips"],
            AetherPsiphonCdnSni = query["cdn_sni"],
            AetherPsiphonCdnSets = query["cdn_sets"],
            AetherPsiphonRegion = query["region"],
            AetherPsiphonBundledList = query["psiphon_bundled"] == "0" ? false : null,
            AetherTor = OffAsNull(AetherTor.FromString(query["tor"]).Type, AetherTor.Off.Type),
            AetherTorBridges = query["tor_bridges"] is { } bridges ? AetherTorBridges.FromString(bridges).Type : null,
            AetherTorBridgeLines = query["bridges"]?.Replace(';', '\n'),
            AetherTorRelays = query["tor_relays"] is { } relays ? AetherTorRelays.FromString(relays).Type : null,
            AetherWiwOuter = outer,
            AetherWiwInner = inner,
        });

        // The exit-node's, under the names the link of an ordinary profile gives its own outbound's.
        item.Finalmask = query["fm"] ?? string.Empty;
        item.DialMode = query["dialMode"] ?? string.Empty;
        item.TcpUserTimeout = TcpUserTimeoutRule.Parse(query["tut"]);

        return item;
    }

    /// <summary>
    /// The endpoint <paramref name="authority" />, the authority of a link as it is written, names, read as java.net.URI
    /// reads a host and a port for PattNG: the host as written, its brackets dropped, after any user part, and the port as
    /// a number of ASCII digits. .NET's Uri would hand on a host it rewrote, an IPv4 address with leading zeros above all
    /// (010 read as octal 8, 08 as 255.255.255.255), where PattNG keeps it as written and AetherEndpoint refuses it. Null
    /// when no endpoint the core takes is named, for anything that is no IP literal and port included: a host name, a
    /// space, an escape or a digit of another script, none of which java.net.URI reads into an address.
    /// </summary>
    private static AetherEndpoint? EndpointOf(string authority)
    {
        var server = authority[(authority.IndexOf('@') + 1)..];
        if (!server.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or ':' or '[' or ']'))
        {
            return null;
        }
        string host;
        string port;
        if (server.StartsWith('['))
        {
            var close = server.IndexOf(']');
            if (close < 0)
            {
                return null;
            }
            host = server[1..close];
            var rest = server[(close + 1)..];
            if (rest.Length > 0 && rest[0] != ':')
            {
                return null;
            }
            port = rest.Length > 0 ? rest[1..] : string.Empty;
        }
        else
        {
            var colon = server.IndexOf(':');
            host = colon < 0 ? server : server[..colon];
            port = colon < 0 ? string.Empty : server[(colon + 1)..];
        }
        // java.net.URI reads the port as an int: none, or one past an int's range, leaves the host without a port.
        if (!int.TryParse(port, NumberStyles.None, CultureInfo.InvariantCulture, out var number) || number <= 0)
        {
            return null;
        }
        return AetherEndpoint.Of(host, number.ToString(CultureInfo.InvariantCulture));
    }

    /// <summary>
    /// Whether java.net.URI reads <paramref name="authority" /> as a registry name, as it does an authority it cannot
    /// read a host and a port from, once PattNG has escaped its spaces and '|': unreserved characters, escapes, the
    /// punctuation $,;:@&amp;=+ and visible characters past ASCII. Anything else has java.net.URI refuse the link.
    /// </summary>
    private static bool IsRegistryName(string authority)
    {
        var text = authority.Replace(" ", "%20").Replace("|", "%7C");
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (char.IsAsciiLetterOrDigit(c) || "-_.!~*'()$,;:@&=+".Contains(c))
            {
                continue;
            }
            if (c == '%' && i + 2 < text.Length && Uri.IsHexDigit(text[i + 1]) && Uri.IsHexDigit(text[i + 2]))
            {
                i += 2;
                continue;
            }
            if (c > 128 && !char.IsSeparator(c) && !char.IsControl(c))
            {
                continue;
            }
            return false;
        }
        return true;
    }

    /// <summary>
    /// The aether:// link of <paramref name="item" />: aether://[endpoint]?query#remarks, the query in PattNG's order. It
    /// carries no exit-node, whose name is that of a profile of this device, and no command of the profile's own.
    /// </summary>
    public static string? ToUri(ProfileItem? item)
    {
        if (item == null)
        {
            return null;
        }

        var extra = item.GetProtocolExtra();
        var protocol = AetherProtocol.FromString(extra.AetherProtocol);
        var transport = AetherTransport.FromString(extra.AetherTransport);
        var psiphon = AetherPsiphon.FromString(extra.AetherPsiphon);
        var tor = AetherTor.FromString(extra.AetherTor);
        var query = new List<(string Key, string Value)>
        {
            ("protocol", protocol.Type),
            ("scan", AetherScanMode.FromString(extra.AetherScanMode).Type),
        };
        // Automatic obfuscation is the core's own choice per protocol, and MASQUE over HTTP/2 takes none; a link says
        // nothing about either.
        var obfuscation = AetherObfuscation.FromString(extra.AetherObfuscation);
        if (obfuscation != AetherObfuscation.Auto && !AetherArguments.MasqueOverHttp2(protocol, transport, tor, psiphon))
        {
            query.Add(("noize", obfuscation.Type));
        }
        query.Add(("ip", AetherIpVersion.FromString(extra.AetherIpVersion).Type));
        AddUnlessBlank(query, "dns", extra.AetherDns);
        AddUnlessBlank(query, "exit_loc", extra.AetherExitLoc);
        if (protocol.OverMasque)
        {
            query.Add(("transport", transport.Type));
            // The default needs no word, and a name the core would not take goes nowhere.
            if (KotlinText.TrimOrNull(extra.AetherMasqueSni) is { } sni && sni != AetherArguments.DefaultMasqueSni && IsMasqueSni(sni))
            {
                query.Add(("sni", sni));
            }
            if (extra.AetherFragment == true)
            {
                query.Add(("fragment", "1"));
                if (AetherRange.Parse(extra.AetherFragmentSize, AetherRange.FragmentSize) is { } size)
                {
                    query.Add(("fragment_size", size.ToString()));
                }
                if (AetherRange.Parse(extra.AetherFragmentDelay, AetherRange.FragmentDelay) is { } delay)
                {
                    query.Add(("fragment_delay", delay.ToString()));
                }
            }
            // Only while ECH is in use, with a WARP tunnel, and only what the core would take: the resolver and the
            // domain are kept while ECH is off, as written, and a link carries what runs.
            var warpUsed = psiphon != AetherPsiphon.Only && tor != AetherTor.Only;
            if (extra.AetherEch == true && warpUsed)
            {
                query.Add(("ech", "1"));
                if (KotlinText.TrimOrNull(extra.AetherEchDns) is { Length: > 0 } echDns && IsEchDns(echDns))
                {
                    query.Add(("ech_dns", echDns));
                }
                if (KotlinText.TrimOrNull(extra.AetherEchDomain) is { Length: > 0 } echDomain && IsEchDomain(echDomain))
                {
                    query.Add(("ech_domain", echDomain));
                }
            }
            // Chrome's is the default and needs no word.
            var fingerprint = AetherFingerprint.FromString(extra.AetherFingerprint);
            if (fingerprint != AetherFingerprint.Chrome)
            {
                query.Add(("fingerprint", fingerprint.Type));
            }
        }
        if (protocol.TwoHops)
        {
            if (AetherEndpoint.Parse(extra.AetherWiwOuter) is { } outer)
            {
                query.Add(("outer", outer.ToString()));
            }
            if (AetherEndpoint.Parse(extra.AetherWiwInner) is { } inner)
            {
                query.Add(("inner", inner.ToString()));
            }
        }
        if (psiphon != AetherPsiphon.Off)
        {
            query.Add(("psiphon", psiphon.Type));
            query.Add(("psiphon_mode", AetherPsiphonMode.FromString(extra.AetherPsiphonMode).Type));
            AddUnlessBlank(query, "cdn_ips", extra.AetherPsiphonCdnIps);
            AddUnlessBlank(query, "cdn_sni", extra.AetherPsiphonCdnSni);
            AddUnlessBlank(query, "cdn_sets", extra.AetherPsiphonCdnSets);
            AddUnlessBlank(query, "region", extra.AetherPsiphonRegion);
            if (extra.AetherPsiphonBundledList == false)
            {
                query.Add(("psiphon_bundled", "0"));
            }
        }
        if (tor != AetherTor.Off)
        {
            query.Add(("tor", tor.Type));
            query.Add(("tor_bridges", AetherTorBridges.FromString(extra.AetherTorBridges).Type));
            query.Add(("tor_relays", AetherTorRelays.FromString(extra.AetherTorRelays).Type));
            // Bridge lines never hold a semicolon: the core itself separates them with one.
            var lines = BridgeLines(extra.AetherTorBridgeLines);
            if (lines.Count > 0)
            {
                query.Add(("bridges", string.Join(";", lines)));
            }
        }
        // On one line, as the other formats write fm; text that is not JSON goes as it is.
        if (!KotlinText.IsBlank(item.Finalmask))
        {
            query.Add(("fm", ToShareJson(item.Finalmask)));
        }
        AddUnlessBlank(query, "dialMode", item.DialMode);
        // tcpUserTimeout (tut), only where the core, as the link sets it up, connects out over TCP (TcpUserTimeoutRule).
        if (item.TcpUserTimeout is { } tcpUserTimeout && tcpUserTimeout > 0 && AetherArguments.ConnectsOverTcp(protocol, transport, tor, psiphon))
        {
            query.Add(("tut", tcpUserTimeout.ToString(CultureInfo.InvariantCulture)));
        }

        var endpoint = protocol.TwoHops ? null : AetherEndpoint.Of(item.Address, item.Port.ToString(CultureInfo.InvariantCulture));
        var queryText = string.Join("&", query.Select(it => $"{it.Key}={Utils.UrlEncode(it.Value)}"));
        return $"{Scheme}{endpoint}?{queryText}#{Utils.UrlEncode(item.Remarks ?? string.Empty)}";
    }

    /// <summary>
    /// Puts the Aether settings of <paramref name="config" /> the way the core and a save take them, in place, and
    /// returns the first problem, checked in PattNG's order; the steps before it have rewritten their settings by then.
    /// <paramref name="takenPorts" /> are loopback ports something else of the app listens on, the local proxy above all;
    /// the core of the profile cannot listen there as well; null or none when the caller knows of none.
    /// <paramref name="listenPort" /> is the Aether listen port of the settings, or the one a screen holds. It has no
    /// default: PattNG's reads the setting, which a constant here would silently stand in for.
    /// </summary>
    public static AetherProblem? Normalize(ProfileItem config, IEnumerable<int>? takenPorts, int listenPort)
    {
        HashSet<int> taken = takenPorts == null ? [] : [.. takenPorts];
        return NormalizeMasqueSni(config)
               ?? NormalizeFragment(config)
               ?? NormalizeEndpoints(config)
               ?? NormalizeDns(config)
               ?? NormalizeExitLoc(config)
               ?? NormalizeEch(config)
               ?? NormalizePsiphon(config)
               ?? NormalizeTor(config)
               ?? NormalizeListenPort(config, taken, listenPort)
               ?? NormalizeCommand(config, taken, listenPort);
    }

    /// <summary>
    /// The core of a profile built from its settings listens on the Aether listen port of the settings, the one port of
    /// every such core, which the local proxy may have been moved onto. A command written by hand names its own ports,
    /// which <see cref="NormalizeCommand" /> checks.
    /// </summary>
    private static AetherProblem? NormalizeListenPort(ProfileItem config, HashSet<int> taken, int listen)
    {
        var extra = config.GetProtocolExtra();
        if (!KotlinText.IsBlank(extra.AetherCommand))
        {
            return null;
        }
        if (taken.Contains(listen))
        {
            return AetherProblem.ListenPortTaken;
        }
        // Psiphon inside the tunnel, Tor inside it and Tor around it each take one more port after the one the app
        // dials, as AetherArguments.Build hands them out.
        var tor = AetherTor.FromString(extra.AetherTor);
        var more = new[]
        {
            AetherPsiphon.FromString(extra.AetherPsiphon) == AetherPsiphon.Chain,
            tor == AetherTor.Chain,
            tor == AetherTor.Reverse,
        }.Count(it => it);
        for (var offset = 1; offset <= more; offset++)
        {
            // long: a port past int's range is no port anything listens on, and must not throw here.
            var port = (long)listen + offset;
            if (port <= int.MaxValue && taken.Contains((int)port))
            {
                return AetherProblem.NextPortTaken;
            }
        }
        return null;
    }

    /// <summary>The resolvers, each an address with or without a port, as the core reads them; written back comma-separated.</summary>
    private static AetherProblem? NormalizeDns(ProfileItem config)
    {
        var extra = config.GetProtocolExtra();
        var resolvers = DnsSeparatorRegex().Split(extra.AetherDns ?? string.Empty).Where(it => it.Length > 0).ToList();
        if (resolvers.Any(it => AetherEndpoint.Parse(it) == null && AetherEndpoint.Of(it, "53") == null))
        {
            return AetherProblem.InvalidDns;
        }
        config.SetProtocolExtra(extra with { AetherDns = EmptyAsNull(string.Join(",", resolvers)) });
        return null;
    }

    /// <summary>The exit rule as the core reads it: country codes to allow, or with a leading ! to refuse, kept in capitals.</summary>
    private static AetherProblem? NormalizeExitLoc(ProfileItem config)
    {
        var extra = config.GetProtocolExtra();
        var rule = KotlinText.Uppercase(new string((extra.AetherExitLoc ?? string.Empty).Where(it => !KotlinText.IsWhitespace(it)).ToArray()));
        if (rule.Length == 0)
        {
            config.SetProtocolExtra(extra with { AetherExitLoc = null });
            return null;
        }
        if (!ExitRuleRegex().IsMatch(rule))
        {
            return AetherProblem.InvalidExitLoc;
        }
        config.SetProtocolExtra(extra with { AetherExitLoc = rule });
        return null;
    }

    /// <summary>
    /// Where the ECH key comes from, as the core reads it: the resolver and the domain, kept as written whether ECH is
    /// on or off, as the WARP keys window keeps its own, and left out when they are the defaults, so that a profile
    /// follows the defaults. They are refused only while ECH is in use, over MASQUE with a WARP tunnel; one the core
    /// would not take waits there, out of use, to be put right when ECH is next turned on. None reaches the core then,
    /// nor a link, which carries them only while ECH is on.
    /// </summary>
    private static AetherProblem? NormalizeEch(ProfileItem config)
    {
        var extra = config.GetProtocolExtra();
        var dns = KotlinText.TrimOrNull(extra.AetherEchDns) ?? string.Empty;
        var domain = KotlinText.TrimOrNull(extra.AetherEchDomain) ?? string.Empty;
        var inUse = extra.AetherEch == true
                    && AetherProtocol.FromString(extra.AetherProtocol).OverMasque
                    && AetherPsiphon.FromString(extra.AetherPsiphon) != AetherPsiphon.Only
                    && AetherTor.FromString(extra.AetherTor) != AetherTor.Only;
        if (inUse && dns.Length > 0 && !IsEchDns(dns))
        {
            return AetherProblem.InvalidEchDns;
        }
        if (inUse && domain.Length > 0 && !IsEchDomain(domain))
        {
            return AetherProblem.InvalidEchDomain;
        }
        config.SetProtocolExtra(extra with
        {
            AetherEchDns = dns.Length == 0 || dns == AetherArguments.DefaultEchDns ? null : dns,
            AetherEchDomain = domain.Length == 0 || domain == AetherArguments.DefaultEchDomain ? null : domain,
        });
        return null;
    }

    /// <summary>
    /// Whether <paramref name="value" /> names a resolver the core asks for the ECH key, as its --ech-dns takes it:
    /// udp:// or tcp:// and an IP address, on port 53 unless one is given, or the https:// URL of a DNS-over-HTTPS
    /// server, on port 443 unless it names one, with @address= and @sni= after it if need be, see
    /// <see cref="IsDohEndpoint" />.
    /// </summary>
    public static bool IsEchDns(string value)
    {
        // Quotes would not come back from the command line the editor shows, which is split into words.
        if (value.Any(it => KotlinText.IsWhitespace(it) || it == '"' || it == '\''))
        {
            return false;
        }
        var at = value.IndexOf("://", StringComparison.Ordinal);
        var scheme = at < 0 ? string.Empty : value[..at].ToLowerInvariant();
        var rest = at < 0 ? string.Empty : value[(at + 3)..];
        switch (scheme)
        {
            case "https":
                return IsDohEndpoint(rest);

            case "udp":
            case "tcp":
                var address = rest.TrimEnd('/');
                // As the core reads an address: ASCII digits only, and brackets around an IPv6 address alone.
                var close = address.IndexOf(']');
                var bracketed = close < 0 ? address : address[..close];
                return address.All(it => it < 0x80)
                       && !(address.StartsWith('[') && !bracketed.Contains(':'))
                       && (AetherEndpoint.Parse(address) ?? AetherEndpoint.Of(address, "53")) != null;

            default:
                return false;
        }
    }

    /// <summary>
    /// Whether <paramref name="rest" />, what follows https://, names a DNS-over-HTTPS server as the core reads one: a URL
    /// with a host, then @address= an IP address or a domain name, where the connection goes on the URL's port, and @sni=
    /// a domain name, which the ClientHello names, each at most once and in either order. Left out, the connection goes
    /// to the URL's host and the ClientHello names it, or names nothing when it is an IP address.
    /// </summary>
    private static bool IsDohEndpoint(string rest)
    {
        var pieces = rest.Split('@');
        if (!pieces[0].TakeWhile(it => it is not ('/' or '?' or '#')).Any())
        {
            return false;
        }
        var named = new HashSet<string>();
        foreach (var piece in pieces.Skip(1))
        {
            var equals = piece.IndexOf('=');
            if (equals < 0)
            {
                return false;
            }
            var name = piece[..equals].ToLowerInvariant();
            var setting = piece[(equals + 1)..];
            var isAddress = AetherEndpoint.Of(setting, "443") != null;
            var fits = name switch
            {
                "address" => isAddress || IsEchDomain(setting),
                "sni" => !isAddress && IsEchDomain(setting),
                _ => false,
            };
            if (!fits || !named.Add(name))
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// Whether <paramref name="value" /> is a domain whose HTTPS record can be asked for, as the core's --ech-domain
    /// takes it. A label cannot start or end with '-' either, so that no value reads as an option of the core's command
    /// line.
    /// </summary>
    public static bool IsEchDomain(string value)
    {
        var name = RemoveSuffix(value, ".");
        return name.Length > 0 && name.Length <= 253 && name.Split('.').All(it => EchDomainLabelRegex().IsMatch(it));
    }

    /// <summary>
    /// The server name the MASQUE handshakes put in their ClientHello, as the core reads it: left out when it is the
    /// default, so that a profile follows the default, and otherwise kept as written whatever the protocol, as the ECH
    /// settings are. It is refused only while a MASQUE tunnel takes it, over MASQUE with a WARP tunnel; one the core
    /// would not take waits there, out of use, as one of the ECH settings does.
    /// </summary>
    private static AetherProblem? NormalizeMasqueSni(ProfileItem config)
    {
        var extra = config.GetProtocolExtra();
        var name = KotlinText.TrimOrNull(extra.AetherMasqueSni) ?? string.Empty;
        var inUse = AetherProtocol.FromString(extra.AetherProtocol).OverMasque
                    && AetherPsiphon.FromString(extra.AetherPsiphon) != AetherPsiphon.Only
                    && AetherTor.FromString(extra.AetherTor) != AetherTor.Only;
        if (inUse && name.Length > 0 && !IsMasqueSni(name))
        {
            return AetherProblem.InvalidMasqueSni;
        }
        config.SetProtocolExtra(extra with
        {
            AetherMasqueSni = name.Length == 0 || name == AetherArguments.DefaultMasqueSni ? null : name,
        });
        return null;
    }

    /// <summary>
    /// Whether <paramref name="value" /> is a server name the core's --masque-sni takes, as do its --api-sni and
    /// --api-host, which it checks as it starts: a domain name, with a trailing dot or without, and no IP address, see
    /// <see cref="IsNetipAddress" />, which tells one as the core's Rust parser does for every text a domain name could be
    /// (PattNG AetherFmt.isMasqueSni). A label cannot start or end with '-' either, as for <see cref="IsEchDomain" />,
    /// which the core would take.
    /// </summary>
    public static bool IsMasqueSni(string value)
    {
        var name = RemoveSuffix(value, ".");
        return !name.EndsWith('.') && !IsNetipAddress(name) && IsEchDomain(name);
    }

    private static AetherProblem? NormalizePsiphon(ProfileItem config)
    {
        var extra = config.GetProtocolExtra();
        var psiphon = AetherPsiphon.FromString(extra.AetherPsiphon);
        if (psiphon == AetherPsiphon.Off)
        {
            config.SetProtocolExtra(extra with
            {
                AetherPsiphon = null,
                AetherPsiphonMode = null,
                AetherPsiphonCdnIps = null,
                AetherPsiphonCdnSni = null,
                AetherPsiphonCdnSets = null,
                AetherPsiphonRegion = null,
                AetherPsiphonBundledList = null,
            });
            return null;
        }
        // Psiphon carries TCP alone and WARP's WireGuard endpoints answer on UDP; the core refuses the pair. WireGuard
        // over MASQUE goes, as its WireGuard rides inside the MASQUE tunnel.
        if (psiphon == AetherPsiphon.Reverse && !AetherProtocol.FromString(extra.AetherProtocol).OverMasque)
        {
            return AetherProblem.PsiphonNeedsMasque;
        }
        config.SetProtocolExtra(extra with
        {
            AetherPsiphon = psiphon.Type,
            AetherPsiphonMode = AetherPsiphonMode.FromString(extra.AetherPsiphonMode).Type,
            AetherPsiphonCdnIps = CommaList(extra.AetherPsiphonCdnIps),
            AetherPsiphonCdnSni = CommaList(extra.AetherPsiphonCdnSni),
            AetherPsiphonCdnSets = AetherPsiphonCdnSet.Join(AetherPsiphonCdnSet.Parse(extra.AetherPsiphonCdnSets)),
            AetherPsiphonRegion = EmptyAsNull(KotlinText.TrimOrNull(extra.AetherPsiphonRegion) is { } region ? KotlinText.Uppercase(region) : null),
            // Stored only when it says no; yes is the default and needs no word.
            AetherPsiphonBundledList = extra.AetherPsiphonBundledList == false ? false : null,
        });
        return null;
    }

    private static AetherProblem? NormalizeTor(ProfileItem config)
    {
        var extra = config.GetProtocolExtra();
        var tor = AetherTor.FromString(extra.AetherTor);
        if (tor == AetherTor.Off)
        {
            config.SetProtocolExtra(extra with
            {
                AetherTor = null,
                AetherTorBridges = null,
                AetherTorBridgeLines = null,
                AetherTorRelays = null,
            });
            return null;
        }
        // Tor carries TCP alone and WARP's WireGuard endpoints answer on UDP; the core refuses the pair. WireGuard over
        // MASQUE goes, as its WireGuard rides inside the MASQUE tunnel.
        if (tor == AetherTor.Reverse && !AetherProtocol.FromString(extra.AetherProtocol).OverMasque)
        {
            return AetherProblem.TorNeedsMasque;
        }
        // Tor and Psiphon go together only nested, one inside the tunnel and the other around it: two around it the
        // core refuses, two inside it or one alone leaves the app nothing to dial the other on.
        var psiphon = AetherPsiphon.FromString(extra.AetherPsiphon);
        var nested = psiphon == AetherPsiphon.Off
                     || (tor == AetherTor.Chain && psiphon == AetherPsiphon.Reverse)
                     || (tor == AetherTor.Reverse && psiphon == AetherPsiphon.Chain);
        if (!nested)
        {
            return AetherProblem.TorPsiphonConflict;
        }
        var bridges = AetherTorBridges.FromString(extra.AetherTorBridges);
        var lines = BridgeLines(extra.AetherTorBridgeLines);
        if (bridges == AetherTorBridges.Own && lines.Count == 0)
        {
            return AetherProblem.TorBridgesMissing;
        }
        config.SetProtocolExtra(extra with
        {
            AetherTor = tor.Type,
            AetherTorBridges = bridges.Type,
            AetherTorBridgeLines = bridges == AetherTorBridges.Own ? string.Join("\n", lines) : null,
            AetherTorRelays = AetherTorRelays.FromString(extra.AetherTorRelays).Type,
        });
        return null;
    }

    /// <summary>
    /// The bridge lines in <paramref name="text" />, one per line the way torrc writes them, read as the core reads a
    /// bridge file: blank lines and comments dropped, a leading Bridge keyword taken off. Trimmed as PattNG trims them,
    /// by Kotlin's whitespace, before the core is given them.
    /// </summary>
    public static List<string> BridgeLines(string? text)
    {
        // Kotlin's lines(): a line ends at \r\n, \n or \r, and at nothing else.
        return (text ?? string.Empty).Split(["\r\n", "\n", "\r"], StringSplitOptions.None)
            .Select(KotlinText.Trim)
            .Where(line => line.Length > 0 && !line.StartsWith('#'))
            .Select(line => KotlinText.Trim(RemovePrefix(RemovePrefix(line, "Bridge "), "bridge ")))
            .Where(line => line.Length > 0)
            .ToList();
    }

    /// <summary>A list as the core reads it, entries separated by commas or spaces, written back with commas alone.</summary>
    private static string? CommaList(string? text)
    {
        return text == null ? null : EmptyAsNull(string.Join(",", CommaListSeparatorRegex().Split(text).Where(it => it.Length > 0)));
    }

    /// <summary>
    /// A command written in place of the settings has to be one the app can run, with a port of its own for each of its
    /// listeners, on ports nothing else of the app holds.
    /// </summary>
    private static AetherProblem? NormalizeCommand(ProfileItem config, HashSet<int> taken, int listenPort)
    {
        var extra = config.GetProtocolExtra();
        var text = KotlinText.TrimOrNull(extra.AetherCommand) ?? string.Empty;
        config.SetProtocolExtra(extra with { AetherCommand = EmptyAsNull(text) });
        if (text.Length == 0)
        {
            return null;
        }
        var core = AetherCore.OfCommand(text, listenPort);
        if (core == null)
        {
            return AetherProblem.InvalidCommand;
        }
        // As a start checks it (AetherCoreLoad.PortsProblem): a number that is no port, an address the core does not
        // take, one where the app does not reach the listener it dials, then ports.
        if (AetherCoreLoad.InvalidPort(core) != null)
        {
            return AetherProblem.ListenPortInvalid;
        }
        if (core.InvalidListener != null)
        {
            return AetherProblem.ListenAddressInvalid;
        }
        if (core.UnreachableListener != null)
        {
            return AetherProblem.ListenAddressUnreachable;
        }
        if (core.SharedPort != null)
        {
            return AetherProblem.ListenPortShared;
        }
        return core.Ports.Any(taken.Contains) ? AetherProblem.ListenPortTaken : null;
    }

    /// <summary>
    /// The port <see cref="AetherProblem.ListenPortTaken" /> is about, for its message (PattNG AetherFmt.takenListenPort):
    /// the Aether listen port of a profile built from its settings, or the first port of the command
    /// <paramref name="config" /> carries that <paramref name="takenPorts" /> holds, as <see cref="Normalize" /> finds them;
    /// null when none is taken.
    /// </summary>
    public static int? TakenListenPort(ProfileItem config, IEnumerable<int>? takenPorts, int listenPort)
    {
        HashSet<int> taken = takenPorts == null ? [] : [.. takenPorts];
        var command = KotlinText.TrimOrNull(config.GetProtocolExtra().AetherCommand);
        if (string.IsNullOrEmpty(command))
        {
            return taken.Contains(listenPort) ? listenPort : null;
        }
        return AetherCore.OfCommand(command, listenPort)?.Ports.Where(taken.Contains).Select(port => (int?)port).FirstOrDefault();
    }

    /// <summary>
    /// The port <see cref="AetherProblem.ListenPortShared" /> is about, for its message: the first port two listeners of
    /// the command <paramref name="config" /> carries share, as <see cref="Normalize" /> finds it; null when none is shared.
    /// </summary>
    public static int? SharedListenPort(ProfileItem config, int listenPort)
    {
        return CommandCore(config, listenPort)?.SharedPort;
    }

    /// <summary>
    /// The number <see cref="AetherProblem.ListenPortInvalid" /> is about, for its message: the first port of the command
    /// <paramref name="config" /> carries that is no port, as <see cref="Normalize" /> finds it; null when there is none.
    /// </summary>
    public static int? InvalidListenPort(ProfileItem config, int listenPort)
    {
        return CommandCore(config, listenPort) is { } core ? AetherCoreLoad.InvalidPort(core) : null;
    }

    /// <summary>
    /// The option <see cref="AetherProblem.ListenAddressInvalid" /> is about, for its message: the first listener option of
    /// the command <paramref name="config" /> carries whose address the core does not take, as <see cref="Normalize" />
    /// finds it; null when there is none.
    /// </summary>
    public static string? InvalidListener(ProfileItem config, int listenPort)
    {
        return CommandCore(config, listenPort)?.InvalidListener;
    }

    /// <summary>
    /// The option <see cref="AetherProblem.ListenAddressUnreachable" /> is about, for its message: the option of the
    /// listener the app dials, when the command <paramref name="config" /> carries puts it where the app does not reach
    /// it, as <see cref="Normalize" /> finds it; null when there is none.
    /// </summary>
    public static string? UnreachableListener(ProfileItem config, int listenPort)
    {
        return CommandCore(config, listenPort)?.UnreachableListener;
    }

    /// <summary>The core of the command <paramref name="config" /> carries in place of its settings, as <see cref="Normalize" /> reads it; null for none.</summary>
    private static AetherCore? CommandCore(ProfileItem config, int listenPort)
    {
        var command = KotlinText.TrimOrNull(config.GetProtocolExtra().AetherCommand);
        return string.IsNullOrEmpty(command) ? null : AetherCore.OfCommand(command, listenPort);
    }

    private static AetherProblem? NormalizeFragment(ProfileItem config)
    {
        var extra = config.GetProtocolExtra();
        var inUse = AetherProtocol.FromString(extra.AetherProtocol).OverMasque
                    && AetherTransport.FromString(extra.AetherTransport) == AetherTransport.Http2
                    && extra.AetherFragment == true;
        var sizeText = KotlinText.TrimOrNull(extra.AetherFragmentSize) ?? string.Empty;
        var delayText = KotlinText.TrimOrNull(extra.AetherFragmentDelay) ?? string.Empty;
        var size = AetherRange.Parse(sizeText, AetherRange.FragmentSize);
        var delay = AetherRange.Parse(delayText, AetherRange.FragmentDelay);
        if (inUse && ((sizeText.Length > 0 && size == null) || (delayText.Length > 0 && delay == null)))
        {
            return AetherProblem.InvalidFragment;
        }
        config.SetProtocolExtra(extra with
        {
            AetherFragmentSize = size?.ToString(),
            AetherFragmentDelay = delay?.ToString(),
        });
        return null;
    }

    private static AetherProblem? NormalizeEndpoints(ProfileItem config)
    {
        var extra = config.GetProtocolExtra();
        var protocol = AetherProtocol.FromString(extra.AetherProtocol);
        if (protocol.TwoHops)
        {
            var outerText = KotlinText.TrimOrNull(extra.AetherWiwOuter) ?? string.Empty;
            var innerText = KotlinText.TrimOrNull(extra.AetherWiwInner) ?? string.Empty;
            var outer = AetherEndpoint.Parse(outerText);
            var inner = AetherEndpoint.Parse(innerText);
            if ((outerText.Length > 0 && outer == null) || (innerText.Length > 0 && inner == null))
            {
                return AetherProblem.InvalidHop;
            }
            if (protocol.DistinctHops && outer != null && inner != null && outer.Host == inner.Host)
            {
                return AetherProblem.SharedHop;
            }
            config.SetProtocolExtra(extra with
            {
                AetherWiwOuter = outer?.ToString(),
                AetherWiwInner = inner?.ToString(),
            });
            config.Address = string.Empty;
            config.Port = 0;
            return null;
        }

        // Port 0 is no port: an address without one cannot be dialled, and no address at all means scanning.
        var address = KotlinText.TrimOrNull(config.Address) ?? string.Empty;
        var endpoint = AetherEndpoint.Of(address, config.Port.ToString(CultureInfo.InvariantCulture));
        if (address.Length > 0 && endpoint == null)
        {
            return AetherProblem.InvalidPeer;
        }
        config.Address = endpoint?.Host ?? string.Empty;
        config.Port = endpoint?.Port ?? 0;
        config.SetProtocolExtra(extra with
        {
            AetherWiwOuter = null,
            AetherWiwInner = null,
        });
        return null;
    }

    /// <summary>
    /// Whether Go's netip.ParseAddr takes <paramref name="text" />, as the core's parser reads an address (PattNG
    /// CoreOutboundBuilder.isNetipAddress): IPv4 in four decimal fields without leading zeros, or IPv6 with one :: at
    /// most, standing for one field or more, and a dotted IPv4 tail and a zone allowed; no brackets. Follows net/netip's
    /// ParseAddr, parseIPv4Fields and parseIPv6 step by step.
    /// </summary>
    private static bool IsNetipAddress(string text)
    {
        foreach (var c in text)
        {
            switch (c)
            {
                case '.':
                    return IsNetipIpv4(text);

                case ':':
                    return IsNetipIpv6(text);

                case '%':
                    return false;
            }
        }
        return false;
    }

    private static bool IsNetipIpv4(string text)
    {
        var fields = text.Split('.');
        return fields.Length == 4 && fields.All(field =>
            field.Length > 0 && field.Length <= 3 && field.All(it => it is >= '0' and <= '9')
            && (field.Length == 1 || field[0] != '0') && int.Parse(field, CultureInfo.InvariantCulture) <= 255);
    }

    private static bool IsNetipIpv6(string text)
    {
        var s = text;
        var zoneAt = s.IndexOf('%');
        if (zoneAt >= 0)
        {
            if (zoneAt == s.Length - 1)
            {
                return false;
            }
            s = s[..zoneAt];
        }
        var ellipsis = -1;
        if (s.StartsWith("::", StringComparison.Ordinal))
        {
            ellipsis = 0;
            s = s[2..];
            if (s.Length == 0)
            {
                return true;
            }
        }
        var i = 0;
        while (i < 16)
        {
            var off = 0;
            while (off < s.Length && Uri.IsHexDigit(s[off]))
            {
                if (off > 3)
                {
                    return false;
                }
                off++;
            }
            if (off == 0)
            {
                return false;
            }
            if (off < s.Length && s[off] == '.')
            {
                if (ellipsis < 0 && i != 12)
                {
                    return false;
                }
                if (i + 4 > 16)
                {
                    return false;
                }
                if (!IsNetipIpv4(s))
                {
                    return false;
                }
                s = string.Empty;
                i += 4;
                break;
            }
            i += 2;
            s = s[off..];
            if (s.Length == 0)
            {
                break;
            }
            if (s[0] != ':' || s.Length == 1)
            {
                return false;
            }
            s = s[1..];
            if (s[0] == ':')
            {
                if (ellipsis >= 0)
                {
                    return false;
                }
                ellipsis = i;
                s = s[1..];
                if (s.Length == 0)
                {
                    break;
                }
            }
        }
        if (s.Length > 0)
        {
            return false;
        }
        return i < 16 ? ellipsis >= 0 : ellipsis < 0;
    }

    private static void AddUnlessBlank(List<(string Key, string Value)> query, string key, string? value)
    {
        if (!KotlinText.IsBlank(value))
        {
            query.Add((key, value!));
        }
    }

    /// <summary>The type of an option, or null when it is <paramref name="off" />, which a profile stores as nothing.</summary>
    private static string? OffAsNull(string type, string off)
    {
        return type == off ? null : type;
    }

    private static string? EmptyAsNull(string? text)
    {
        return string.IsNullOrEmpty(text) ? null : text;
    }

    /// <summary>Kotlin's removePrefix: <paramref name="text" /> without <paramref name="prefix" /> when it starts with it.</summary>
    private static string RemovePrefix(string text, string prefix)
    {
        return text.StartsWith(prefix, StringComparison.Ordinal) ? text.Substring(prefix.Length) : text;
    }

    /// <summary>Kotlin's removeSuffix: <paramref name="text" /> without <paramref name="suffix" /> when it ends with it.</summary>
    private static string RemoveSuffix(string text, string suffix)
    {
        return text.EndsWith(suffix, StringComparison.Ordinal) ? text[..^suffix.Length] : text;
    }

    // PattNG splits the resolvers on [,;\s]+ and a list on [,\s]+, where \s is Java's: ASCII white space alone, which
    // .NET's \s is not.
    [GeneratedRegex("[,;\\t\\n\\x0B\\f\\r ]+", RegexOptions.CultureInvariant)]
    private static partial Regex DnsSeparatorRegex();

    [GeneratedRegex("[,\\t\\n\\x0B\\f\\r ]+", RegexOptions.CultureInvariant)]
    private static partial Regex CommaListSeparatorRegex();

    // PattNG matches the whole text: \A and \z, since $ would let a final line break through.
    [GeneratedRegex("\\A!?[A-Z]{2}(,[A-Z]{2})*\\z", RegexOptions.CultureInvariant)]
    private static partial Regex ExitRuleRegex();

    [GeneratedRegex("\\A[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\\z", RegexOptions.CultureInvariant)]
    private static partial Regex EchDomainLabelRegex();
}

/// <summary>Why <see cref="AetherFmt.Normalize" /> refuses the Aether settings of a profile (PattNG AetherFmt.Problem).</summary>
public enum AetherProblem
{
    InvalidMasqueSni,
    InvalidPeer,
    InvalidHop,
    SharedHop,
    InvalidFragment,
    InvalidDns,
    InvalidExitLoc,
    InvalidEchDns,
    InvalidEchDomain,
    ListenPortTaken,
    ListenPortShared,
    ListenPortInvalid,
    ListenAddressInvalid,
    ListenAddressUnreachable,
    PsiphonNeedsMasque,
    NextPortTaken,
    TorNeedsMasque,
    TorPsiphonConflict,
    TorBridgesMissing,
    InvalidCommand,
}
