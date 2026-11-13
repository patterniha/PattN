namespace ServiceLib.Tests.Fmt;

public class FmtHandlerTests
{
    /// <summary>
    /// One profile factory per protocol that <see cref="FmtHandler.GetShareUri" /> can export.
    /// The suite below asserts that this map and <see cref="Global.ProtocolShares" /> agree, so a
    /// newly exportable protocol cannot be added without a round-trip case.
    /// </summary>
    private static readonly Dictionary<EConfigType, Func<ProfileItem>> ShareProfileFactories = new()
    {
        [EConfigType.VMess] = CreateVmessProfile,
        [EConfigType.Shadowsocks] = CreateShadowsocksProfile,
        [EConfigType.SOCKS] = CreateSocksProfile,
        [EConfigType.VLESS] = CreateVlessProfile,
        [EConfigType.Trojan] = CreateTrojanProfile,
        [EConfigType.Hysteria2] = CreateHysteria2Profile,
        [EConfigType.TUIC] = CreateTuicProfile,
        [EConfigType.WireGuard] = CreateWireguardProfile,
        [EConfigType.Anytls] = CreateAnytlsProfile,
        [EConfigType.Naive] = () => CreateNaiveProfile(false),
        // PattN: the fork's Aether profiles; AetherFmtHandlerTests checks the rest of their links
        [EConfigType.Aether] = CreateAetherProfile,
    };

    [Test]
    public async Task ShareUriSuite_ShouldCoverAndRoundTripEveryExportableProtocol()
    {
        var uncovered = string.Join(", ", Global.ProtocolShares.Keys.Except(ShareProfileFactories.Keys));
        var unexpected = string.Join(", ", ShareProfileFactories.Keys.Except(Global.ProtocolShares.Keys));

        await uncovered.Should().BeEqualTo(string.Empty);
        await unexpected.Should().BeEqualTo(string.Empty);

        foreach (var (configType, factory) in ShareProfileFactories)
        {
            var source = factory();

            var resolved = await ExportThenImport(source);

            await resolved.ConfigType.Should().BeEqualTo(configType);
            await resolved.Address.Should().BeEqualTo(source.Address);
            await resolved.Port.Should().BeEqualTo(source.Port);
        }
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_Vmess_ShouldRoundTripBasicFields()
    {
        var source = CreateVmessProfile();

        var resolved = await ExportThenImport(source);

        await resolved.ConfigType.Should().BeEqualTo(EConfigType.VMess);
        await resolved.Remarks.Should().BeEqualTo(source.Remarks);
        await resolved.Address.Should().BeEqualTo(source.Address);
        await resolved.Port.Should().BeEqualTo(source.Port);
        await resolved.Password.Should().BeEqualTo(source.Password);
        await resolved.GetProtocolExtra().AlterId.Should().BeEqualTo(source.GetProtocolExtra().AlterId);
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_Vless_ShouldRoundTripBasicFields()
    {
        var source = CreateVlessProfile();

        var resolved = await ExportThenImport(source);

        await resolved.ConfigType.Should().BeEqualTo(EConfigType.VLESS);
        await resolved.Remarks.Should().BeEqualTo(source.Remarks);
        await resolved.Address.Should().BeEqualTo(source.Address);
        await resolved.Port.Should().BeEqualTo(source.Port);
        await resolved.Password.Should().BeEqualTo(source.Password);
        await resolved.GetProtocolExtra().VlessEncryption.Should().BeEqualTo(Global.None);
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_Vless_ShouldRoundTripCipherSuitesAndUnsafeFingerprint()
    {
        var source = CreateVlessProfile();
        source.StreamSecurity = Global.StreamSecurity;
        source.Sni = "sni.vless.example";
        source.Fingerprint = "unsafe";
        source.CipherSuites = "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256";

        var resolved = await ExportThenImport(source);

        await resolved.StreamSecurity.Should().BeEqualTo(Global.StreamSecurity);
        await resolved.Fingerprint.Should().BeEqualTo(source.Fingerprint);
        await resolved.CipherSuites.Should().BeEqualTo(source.CipherSuites);

        // The suites list is colon-separated on the wire, so the exporter has to percent-encode
        // the value; the "cs" spelling and the encoded colon are pinned here because an exporter
        // and an importer that agreed on another spelling would still round-trip cleanly.
        await AssertExportContains(
            source,
            "fp=unsafe",
            "cs=TLS_AES_128_GCM_SHA256%3ATLS_CHACHA20_POLY1305_SHA256");
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_Vmess_ShouldRoundTripCipherSuitesAndUnsafeFingerprint()
    {
        // VMess does not go through the shared query string: the QR-code JSON carries its own
        // "fp" and "cs" members, so the VLESS case above cannot stand in for this path.
        var source = CreateVmessProfile();
        source.StreamSecurity = Global.StreamSecurity;
        source.Sni = "sni.vmess.example";
        source.Fingerprint = "unsafe";
        source.CipherSuites = "TLS_AES_256_GCM_SHA384";

        var resolved = await ExportThenImport(source);

        await resolved.StreamSecurity.Should().BeEqualTo(Global.StreamSecurity);
        await resolved.Fingerprint.Should().BeEqualTo(source.Fingerprint);
        await resolved.CipherSuites.Should().BeEqualTo(source.CipherSuites);
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_Vless_ShouldRoundTripCurvePreferencesAndSessionResumption()
    {
        // PattN: "cp" carries curvePreferences as the profile holds them, the comma percent-encoded as alpn's is, and
        // "esr=1" enableSessionResumption when it is on; both come after "cs" and neither is written when unset.
        var source = CreateVlessProfile();
        source.StreamSecurity = Global.StreamSecurity;
        source.Sni = "sni.vless.example";
        source.Fingerprint = "unsafe";
        source.CipherSuites = "TLS_AES_128_GCM_SHA256";
        source.CurvePreferences = "X25519MLKEM768,X25519";
        source.EnableSessionResumption = true;

        var resolved = await ExportThenImport(source);

        await resolved.CipherSuites.Should().BeEqualTo(source.CipherSuites);
        await resolved.CurvePreferences.Should().BeEqualTo(source.CurvePreferences);
        await resolved.EnableSessionResumption.Should().BeTrue();
        await AssertExportContains(source, "cp=X25519MLKEM768%2CX25519", "esr=1");

        source.CurvePreferences = string.Empty;
        source.EnableSessionResumption = false;
        var uri = FmtHandler.GetShareUri(source)!;
        var keys = uri[(uri.IndexOf('?') + 1)..].Split('#')[0].Split('&').Select(p => p.Split('=')[0]).ToList();
        await keys.Should().Contain("cs").Because(uri);
        await keys.Should().NotContain("cp").Because(uri);
        await keys.Should().NotContain("esr").Because(uri);
        var plain = await ExportThenImport(source);
        await plain.CurvePreferences.Should().BeEqualTo(string.Empty);
        await plain.EnableSessionResumption.Should().BeFalse();
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_Vmess_ShouldRoundTripCurvePreferencesAndSessionResumption()
    {
        // PattN: the QR-code JSON carries them as its own "cp" and "esr" members, after "cs".
        var source = CreateVmessProfile();
        source.StreamSecurity = Global.StreamSecurity;
        source.Sni = "sni.vmess.example";
        source.Fingerprint = "unsafe";
        source.CurvePreferences = "X25519";
        source.EnableSessionResumption = true;

        var resolved = await ExportThenImport(source);

        await resolved.CurvePreferences.Should().BeEqualTo("X25519");
        await resolved.EnableSessionResumption.Should().BeTrue();
        var uri = FmtHandler.GetShareUri(source)!;
        var json = JsonNode.Parse(Utils.Base64Decode(uri[Global.ProtocolShares[EConfigType.VMess].Length..]))!.AsObject();
        await json["cp"]!.GetValue<string>().Should().BeEqualTo("X25519");
        await json["esr"]!.GetValue<string>().Should().BeEqualTo("1");
        var members = json.Select(p => p.Key).ToList();
        await members.IndexOf("cp").Should().BeEqualTo(members.IndexOf("cs") + 1);
        await members.IndexOf("esr").Should().BeEqualTo(members.IndexOf("cs") + 2);

        source.EnableSessionResumption = false;
        await (await ExportThenImport(source)).EnableSessionResumption.Should().BeFalse();
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_Vless_ShouldRoundTripDialMode()
    {
        // dialMode is a sockopt option, so it has to travel even when the profile has no TLS.
        var source = CreateVlessProfile();
        source.DialMode = "code-1";

        var resolved = await ExportThenImport(source);

        await resolved.DialMode.Should().BeEqualTo(source.DialMode);
        await AssertExportContains(source, "dialMode=code-1");
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_Vmess_ShouldRoundTripDialMode()
    {
        // VMess uses the QR-code JSON, which carries its own "dialMode" member.
        var source = CreateVmessProfile();
        source.DialMode = "code-1";

        var resolved = await ExportThenImport(source);

        await resolved.DialMode.Should().BeEqualTo(source.DialMode);
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_Hysteria2_ShouldRoundTripDialMode()
    {
        // Hysteria2 exports through the lite query, which must carry dialMode as well.
        var source = CreateHysteria2Profile();
        source.DialMode = "code-1";

        var resolved = await ExportThenImport(source);

        await resolved.DialMode.Should().BeEqualTo(source.DialMode);
        await AssertExportContains(source, "dialMode=code-1");
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_Wireguard_ShouldRoundTripDialMode()
    {
        // WireGuard builds and reads its query by hand, so it needs its own dialMode handling.
        var source = CreateWireguardProfile();
        source.DialMode = "code-1";

        var resolved = await ExportThenImport(source);

        await resolved.DialMode.Should().BeEqualTo(source.DialMode);
        await AssertExportContains(source, "dialMode=code-1");
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_Vless_ShouldRoundTripTcpUserTimeout()
    {
        // PattN: a sockopt option like dialMode, carried where the outbound connects over TCP (TcpUserTimeoutRule).
        var source = CreateVlessProfile();
        source.DialMode = "code-1";
        source.TcpUserTimeout = 10000;

        var resolved = await ExportThenImport(source);

        await resolved.TcpUserTimeout.Should().BeEqualTo(10000);
        await resolved.DialMode.Should().BeEqualTo("code-1");
        await AssertExportContains(source, "dialMode=code-1", "tut=10000");
    }

    [Test]
    public async Task GetShareUri_TcpUserTimeoutStaysOutOfALinkWhoseConnectionIsUdp()
    {
        // PattN: mKCP runs over UDP, as do Hysteria2 and WireGuard: the profile keeps its value, no link carries it.
        var kcp = CreateVlessProfile();
        kcp.Network = nameof(ETransport.kcp);
        kcp.TcpUserTimeout = 10000;
        var hysteria2 = CreateHysteria2Profile();
        hysteria2.TcpUserTimeout = 10000;
        var wireguard = CreateWireguardProfile();
        wireguard.TcpUserTimeout = 10000;

        foreach (var source in new[] { kcp, hysteria2, wireguard })
        {
            var uri = FmtHandler.GetShareUri(source);
            await QueryKeys(uri!).Contains("tut").Should().BeFalse().Because(uri);
            var resolved = await ExportThenImport(source);
            await resolved.TcpUserTimeout.Should().BeNull();
        }
    }

    [Test]
    public async Task ResolveConfig_TcpUserTimeoutTakesAWholeNumberAboveZeroAlone()
    {
        // PattN: as a field takes it; anything else leaves the profile without one.
        const string link = "vless://5783a3e7-e373-51cd-8642-c83782b807c5@vless.example:8443?encryption=none&type=tcp&tut=";
        await (FmtHandler.ResolveConfig(link + "2500", out _)?.TcpUserTimeout).Should().BeEqualTo(2500);
        await (FmtHandler.ResolveConfig(link + "0", out _)?.TcpUserTimeout).Should().BeNull();
        await (FmtHandler.ResolveConfig(link + "-1", out _)?.TcpUserTimeout).Should().BeNull();
        await (FmtHandler.ResolveConfig(link + "2s", out _)?.TcpUserTimeout).Should().BeNull();
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_Vmess_ShouldRoundTripTcpUserTimeout()
    {
        // PattN: the QR-code JSON carries it in a member of its own, blank where it does not count.
        var source = CreateVmessProfile();
        source.TcpUserTimeout = 10000;

        var resolved = await ExportThenImport(source);

        await resolved.TcpUserTimeout.Should().BeEqualTo(10000);

        source.Network = nameof(ETransport.kcp);
        var kcp = await ExportThenImport(source);
        await kcp.TcpUserTimeout.Should().BeNull();
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_Aether_ShouldCarryTcpUserTimeoutWhereItsCoreConnectsOverTcp()
    {
        // PattN: the exit-node's, under the name of an ordinary link, only where the core of the link dials out over TCP.
        var source = CreateAetherProfile();
        source.TcpUserTimeout = 10000;
        source.SetProtocolExtra(source.GetProtocolExtra() with { AetherTransport = AetherTransport.Http2.Type });

        var resolved = await ExportThenImport(source);

        await resolved.TcpUserTimeout.Should().BeEqualTo(10000);
        await AssertExportContains(source, "tut=10000");

        source.SetProtocolExtra(source.GetProtocolExtra() with { AetherTransport = AetherTransport.Http3.Type });
        var overHttp3 = FmtHandler.GetShareUri(source)!;
        await QueryKeys(overHttp3).Contains("tut").Should().BeFalse().Because(overHttp3);
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_Shadowsocks_ShouldRoundTripBasicFields()
    {
        var source = CreateShadowsocksProfile();

        var resolved = await ExportThenImport(source);

        await resolved.ConfigType.Should().BeEqualTo(EConfigType.Shadowsocks);
        await resolved.Remarks.Should().BeEqualTo(source.Remarks);
        await resolved.Address.Should().BeEqualTo(source.Address);
        await resolved.Port.Should().BeEqualTo(source.Port);
        await resolved.Password.Should().BeEqualTo(source.Password);
        await resolved.GetProtocolExtra().SsMethod.Should().BeEqualTo(source.GetProtocolExtra().SsMethod);
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_Socks_ShouldRoundTripBasicFields()
    {
        var source = CreateSocksProfile();

        var resolved = await ExportThenImport(source);

        await resolved.ConfigType.Should().BeEqualTo(EConfigType.SOCKS);
        await resolved.Remarks.Should().BeEqualTo(source.Remarks);
        await resolved.Address.Should().BeEqualTo(source.Address);
        await resolved.Port.Should().BeEqualTo(source.Port);
        await resolved.Username.Should().BeEqualTo(source.Username);
        await resolved.Password.Should().BeEqualTo(source.Password);
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_Trojan_ShouldRoundTripBasicFields()
    {
        var source = CreateTrojanProfile();

        var resolved = await ExportThenImport(source);

        await AssertCommonShareFields(source, resolved);
        await AssertRawTransportFields(source, resolved);
        await resolved.Password.Should().BeEqualTo(source.Password);
        await resolved.Sni.Should().BeEqualTo(source.Sni);
        await resolved.GetProtocolExtra().Flow.Should().BeEqualTo(source.GetProtocolExtra().Flow);
        await resolved.GetAllowInsecure().Should().BeTrue();

        // Trojan is the one exporter that writes both spellings of the flag.
        await AssertExportContains(source, "allowInsecure=1", "insecure=1");
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_Tuic_ShouldRoundTripUserInfoAndCongestionControl()
    {
        var source = CreateTuicProfile();

        var resolved = await ExportThenImport(source);

        await AssertCommonShareFields(source, resolved);
        await resolved.Username.Should().BeEqualTo(source.Username);
        await resolved.Password.Should().BeEqualTo(source.Password);
        await resolved.Sni.Should().BeEqualTo(source.Sni);
        await resolved.Alpn.Should().BeEqualTo(source.Alpn);
        await resolved.GetProtocolExtra().CongestionControl.Should()
            .BeEqualTo(source.GetProtocolExtra().CongestionControl);
        await resolved.GetAllowInsecure().Should().BeTrue();

        await AssertExportContains(source, "allow_insecure=1");
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_Anytls_ShouldRoundTripBasicFields()
    {
        var source = CreateAnytlsProfile();

        var resolved = await ExportThenImport(source);

        await AssertCommonShareFields(source, resolved);
        await AssertRawTransportFields(source, resolved);
        await resolved.Password.Should().BeEqualTo(source.Password);
        await resolved.Sni.Should().BeEqualTo(source.Sni);
        await resolved.Alpn.Should().BeEqualTo(source.Alpn);
        await resolved.GetAllowInsecure().Should().BeTrue();

        await AssertExportContains(source, "insecure=1");
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_Hysteria2_ShouldRoundTripObfsAndNormalizePortRange()
    {
        var source = CreateHysteria2Profile();

        var resolved = await ExportThenImport(source);
        var sourceExtra = source.GetProtocolExtra();
        var resolvedExtra = resolved.GetProtocolExtra();

        await AssertCommonShareFields(source, resolved);
        await resolved.Password.Should().BeEqualTo(source.Password);
        await resolved.Sni.Should().BeEqualTo(source.Sni);
        await resolved.Alpn.Should().BeEqualTo(source.Alpn);
        await resolved.EchConfigList.Should().BeEqualTo(source.EchConfigList);
        await resolved.GetAllowInsecure().Should().BeTrue();
        await resolvedExtra.SalamanderPass.Should().BeEqualTo(sourceExtra.SalamanderPass);

        // Hysteria2Fmt stores a port range internally as "5000:6000" and emits the URI form.
        await resolvedExtra.Ports.Should().BeEqualTo("5000-6000");

        await AssertExportContains(source, "insecure=1", "obfs=salamander", "mport=5000-6000");
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_Vless_ShouldRoundTripEchOutbound()
    {
        // PattN: echOutbound travels next to ech as one-line JSON and is stored indented again, like fm.
        var source = CreateVlessProfile();
        source.StreamSecurity = Global.StreamSecurity;
        source.Sni = "vless.example";
        source.EchConfigList = "cloudflare-ech.com+https://1.1.1.1/dns-query";
        source.EchOutbound = """
            {
              "tag": "ech-out",
              "protocol": "freedom",
              "settings": { "domainStrategy": "UseIPv4" }
            }
            """;

        var resolved = await ExportThenImport(source);

        await JsonNode.DeepEquals(JsonNode.Parse(resolved.EchOutbound), JsonNode.Parse(source.EchOutbound)).Should().BeTrue();
        await resolved.EchOutbound.Should().Contain("\n");
        await AssertExportContains(source, "echOutbound=");
        await FmtHandler.GetShareUri(source)!.Contains("%0A", StringComparison.OrdinalIgnoreCase).Should().BeFalse();
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_Hysteria2_ShouldRoundTripEchOutbound()
    {
        // Hysteria2 exports ech through its own query, which has to carry echOutbound as well.
        var source = CreateHysteria2Profile();
        source.EchOutbound = """{"tag": "ech-out", "protocol": "freedom"}""";

        var resolved = await ExportThenImport(source);

        await JsonNode.DeepEquals(JsonNode.Parse(resolved.EchOutbound), JsonNode.Parse(source.EchOutbound)).Should().BeTrue();
        await AssertExportContains(source, "echOutbound=");
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_Hysteria2_ShouldRoundTripFinalmask()
    {
        // PattN: Hysteria2 links carry fm like the other links; it replaces the finalmask generated for Hysteria2.
        var source = CreateHysteria2Profile();
        source.Finalmask = """
            {
              "udp": [ { "type": "salamander", "settings": { "password": "fm-pass" } } ]
            }
            """;

        var resolved = await ExportThenImport(source);

        await JsonNode.DeepEquals(JsonNode.Parse(resolved.Finalmask), JsonNode.Parse(source.Finalmask)).Should().BeTrue();
        await AssertExportContains(source, "fm=");
        await FmtHandler.GetShareUri(source)!.Contains("%0A", StringComparison.OrdinalIgnoreCase).Should().BeFalse();
        await FmtHandler.GetShareUri(CreateHysteria2Profile())!.Contains("fm=", StringComparison.Ordinal).Should().BeFalse();
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_WithoutEchOutbound_ShouldLeaveItEmpty()
    {
        var source = CreateVlessProfile();

        var resolved = await ExportThenImport(source);

        await resolved.EchOutbound.Should().BeEqualTo(string.Empty);
        await FmtHandler.GetShareUri(source)!.Contains("echOutbound", StringComparison.Ordinal).Should().BeFalse();
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_Wireguard_ShouldRoundTripKeysAndInterface()
    {
        var source = CreateWireguardProfile();

        var resolved = await ExportThenImport(source);
        var extra = resolved.GetProtocolExtra();
        var sourceExtra = source.GetProtocolExtra();

        await AssertCommonShareFields(source, resolved);
        await resolved.Password.Should().BeEqualTo(source.Password);
        await extra.WgPublicKey.Should().BeEqualTo(sourceExtra.WgPublicKey);
        await extra.WgPresharedKey.Should().BeEqualTo(sourceExtra.WgPresharedKey);
        await extra.WgReserved.Should().BeEqualTo(sourceExtra.WgReserved);
        await extra.WgInterfaceAddress.Should().BeEqualTo(sourceExtra.WgInterfaceAddress);
        await extra.WgMtu.Should().BeEqualTo(sourceExtra.WgMtu);
    }

    [Test]
    public async Task GetShareUri_Wireguard_ShouldEncodeKeysAndBracketIpv6()
    {
        var source = CreateWireguardProfile();

        // Base64 keys carry '/', '+' and '=', and the address is an IPv6 literal: both have to
        // survive the wire form, which a round trip through the same encoder would not prove.
        await AssertExportContains(
            source,
            Uri.EscapeDataString(source.Password),
            Uri.EscapeDataString(source.GetProtocolExtra().WgPublicKey ?? string.Empty),
            "@[2001:db8::40]:51820");
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_Naive_ShouldRoundTripCredentialsOverHttps()
    {
        var source = CreateNaiveProfile(false);

        var resolved = await ExportThenImport(source, Global.NaiveHttpsProtocolShare);

        await AssertCommonShareFields(source, resolved);
        await AssertRawTransportFields(source, resolved);
        await resolved.Username.Should().BeEqualTo(source.Username);
        await resolved.Password.Should().BeEqualTo(source.Password);
        await resolved.GetProtocolExtra().InsecureConcurrency.Should()
            .BeEqualTo(source.GetProtocolExtra().InsecureConcurrency);

        // NaiveFmt only ever sets this flag on the quic branch, so the https branch leaves it
        // unset rather than false - assert "is not quic" instead of an explicit false.
        await (resolved.GetProtocolExtra().NaiveQuic == true).Should().BeFalse();
    }

    [Test]
    public async Task GetShareUriAndResolveConfig_NaiveQuic_ShouldRoundTripQuicScheme()
    {
        var source = CreateNaiveProfile(true);

        var resolved = await ExportThenImport(source, Global.NaiveQuicProtocolShare);

        await AssertCommonShareFields(source, resolved);
        await AssertRawTransportFields(source, resolved);
        await resolved.Username.Should().BeEqualTo(source.Username);
        await resolved.Password.Should().BeEqualTo(source.Password);
        await resolved.GetProtocolExtra().InsecureConcurrency.Should()
            .BeEqualTo(source.GetProtocolExtra().InsecureConcurrency);
        await resolved.GetProtocolExtra().NaiveQuic.Should().BeTrue();
    }

    [Test]
    [Arguments("p:a@ss#% +/=")]
    [Arguments("пароль 東京")]
    public async Task GetShareUriAndResolveConfig_Trojan_ShouldRoundTripEncodedCredentials(string password)
    {
        var source = CreateTrojanProfile();
        source.Password = password;
        source.Remarks = "Trojan — тест 東京 #1";

        var resolved = await ExportThenImport(source);

        await resolved.Password.Should().BeEqualTo(password);
        await resolved.Remarks.Should().BeEqualTo(source.Remarks);
    }

    [Test]
    public async Task ResolveConfig_UnsupportedProtocol_ShouldReturnNull()
    {
        var resolved = FmtHandler.ResolveConfig("not-a-share-uri", out var msg);

        await resolved.Should().BeNull();
        await msg.Should().NotBeNull();
        await msg.Should().NotBeEmpty();
    }

    [Test]
    public async Task GetShareUri_UnsupportedConfigType_ShouldReturnNull()
    {
        var item = new ProfileItem { ConfigType = EConfigType.PolicyGroup, Remarks = "group", };

        var uri = FmtHandler.GetShareUri(item);

        await uri.Should().BeNull();
    }

    private static async Task AssertCommonShareFields(ProfileItem source, ProfileItem resolved)
    {
        await resolved.ConfigType.Should().BeEqualTo(source.ConfigType);
        await resolved.Remarks.Should().BeEqualTo(source.Remarks);
        await resolved.Address.Should().BeEqualTo(source.Address);
        await resolved.Port.Should().BeEqualTo(source.Port);
    }

    /// <summary>
    /// Only for protocols whose exporter goes through the shared transport query
    /// (<c>security</c>, <c>type</c>, <c>headerType</c>). TUIC, Hysteria2 and WireGuard do not.
    /// </summary>
    private static async Task AssertRawTransportFields(ProfileItem source, ProfileItem resolved)
    {
        await resolved.Network.Should().BeEqualTo(source.Network);
        await resolved.StreamSecurity.Should().BeEqualTo(source.StreamSecurity);
        await resolved.GetTransportExtra().RawHeaderType.Should()
            .BeEqualTo(source.GetTransportExtra().RawHeaderType);
    }

    /// <summary>
    /// Asserts on the wire form itself. A round trip cannot catch an exporter and an importer that
    /// agree on the wrong spelling of a parameter, and the insecure flag is spelled differently by
    /// every protocol.
    /// </summary>
    // PattN: the keys of the query of a link.
    private static List<string> QueryKeys(string uri)
    {
        return uri.Split('#')[0].Split('?').Skip(1).FirstOrDefault()?.Split('&').Select(pair => pair.Split('=')[0]).ToList() ?? [];
    }

    private static async Task AssertExportContains(ProfileItem source, params string[] expectedFragments)
    {
        var uri = FmtHandler.GetShareUri(source);

        await uri.Should().NotBeNull();

        foreach (var fragment in expectedFragments)
        {
            await uri!.Contains(fragment, StringComparison.Ordinal).Should()
                .BeTrue().Because($"uri: {uri}, expected fragment: {fragment}");
        }
    }

    private static string ExpectedShareScheme(ProfileItem item)
    {
        if (item.ConfigType != EConfigType.Naive)
        {
            return Global.ProtocolShares[item.ConfigType];
        }

        // NaiveFmt never emits the "naive://" prefix that Global.ProtocolShares records for the
        // type; that entry is only read when importing.
        return item.GetProtocolExtra().NaiveQuic == true
            ? Global.NaiveQuicProtocolShare
            : Global.NaiveHttpsProtocolShare;
    }

    private static async Task<ProfileItem> ExportThenImport(ProfileItem source)
    {
        return await ExportThenImport(source, ExpectedShareScheme(source));
    }

    private static async Task<ProfileItem> ExportThenImport(ProfileItem source, string expectedPrefix)
    {
        var uri = FmtHandler.GetShareUri(source);

        await uri.Should().NotBeNull();
        await uri.Should().NotBeEmpty();
        await uri!.StartsWith(expectedPrefix, StringComparison.OrdinalIgnoreCase).Should().BeTrue();

        var resolved = FmtHandler.ResolveConfig(uri, out var msg);

        await resolved.Should().NotBeNull().Because($"uri: {uri}, msg: {msg}");
        return resolved!;
    }

    // PattN: an Aether profile pinned to an endpoint, as a link carries one.
    private static ProfileItem CreateAetherProfile()
    {
        var item = new ProfileItem
        {
            ConfigType = EConfigType.Aether,
            Remarks = "aether demo",
            Address = "162.159.198.1",
            Port = 443,
        };

        item.SetProtocolExtra(new ProtocolExtraItem { AetherProtocol = "masque", AetherScanMode = "verified", });

        return item;
    }

    private static ProfileItem CreateVmessProfile()
    {
        var item = new ProfileItem
        {
            ConfigType = EConfigType.VMess,
            Remarks = "vmess demo",
            Address = "example.com",
            Port = 443,
            Password = Guid.NewGuid().ToString(),
            Network = nameof(ETransport.raw),
            StreamSecurity = string.Empty,
        };

        item.SetProtocolExtra(new ProtocolExtraItem { AlterId = "0", VmessSecurity = Global.DefaultSecurity, });
        item.SetTransportExtra(new TransportExtraItem { RawHeaderType = Global.None, });

        return item;
    }

    private static ProfileItem CreateVlessProfile()
    {
        var item = new ProfileItem
        {
            ConfigType = EConfigType.VLESS,
            Remarks = "vless demo",
            Address = "vless.example",
            Port = 8443,
            Password = Guid.NewGuid().ToString(),
            Network = nameof(ETransport.raw),
            StreamSecurity = string.Empty,
        };

        item.SetProtocolExtra(new ProtocolExtraItem { VlessEncryption = Global.None, });
        item.SetTransportExtra(new TransportExtraItem { RawHeaderType = Global.None, });

        return item;
    }

    private static ProfileItem CreateShadowsocksProfile()
    {
        var item = new ProfileItem
        {
            ConfigType = EConfigType.Shadowsocks,
            Remarks = "ss demo",
            Address = "1.2.3.4",
            Port = 8388,
            Password = "pass123",
            Network = nameof(ETransport.raw),
            StreamSecurity = string.Empty,
        };

        item.SetProtocolExtra(new ProtocolExtraItem { SsMethod = "aes-128-gcm", });
        item.SetTransportExtra(new TransportExtraItem { RawHeaderType = Global.None, });

        return item;
    }

    private static ProfileItem CreateSocksProfile()
    {
        return new ProfileItem
        {
            ConfigType = EConfigType.SOCKS,
            Remarks = "socks demo",
            Address = "127.0.0.1",
            Port = 1080,
            Username = "user",
            Password = "pass",
        };
    }

    private static ProfileItem CreateTrojanProfile()
    {
        var item = new ProfileItem
        {
            ConfigType = EConfigType.Trojan,
            Remarks = "trojan demo",
            Address = "trojan.example",
            Port = 443,
            Password = "trojan-pass",
            Network = nameof(ETransport.raw),
            StreamSecurity = Global.StreamSecurity,
            Sni = "sni.trojan.example",
            AllowInsecure = Global.StringTrue,
        };

        item.SetProtocolExtra(new ProtocolExtraItem { Flow = Global.Flows[1], });
        item.SetTransportExtra(new TransportExtraItem { RawHeaderType = Global.None, });

        return item;
    }

    private static ProfileItem CreateTuicProfile()
    {
        var item = new ProfileItem
        {
            ConfigType = EConfigType.TUIC,
            Remarks = "tuic demo",
            Address = "tuic.example",
            Port = 8443,
            // A colon separates the two halves of the TUIC user info, so it cannot appear in the
            // uuid; a fixed value also keeps a failure reproducible.
            Username = "01234567-89ab-cdef-0123-456789abcdef",
            Password = "tuic-pass",
            Sni = "sni.tuic.example",
            Alpn = "h3",
            AllowInsecure = Global.StringTrue,
        };

        item.SetProtocolExtra(new ProtocolExtraItem { CongestionControl = "bbr", });

        return item;
    }

    private static ProfileItem CreateAnytlsProfile()
    {
        var item = new ProfileItem
        {
            ConfigType = EConfigType.Anytls,
            Remarks = "anytls demo",
            Address = "anytls.example",
            Port = 8443,
            Password = "anytls-pass",
            Network = nameof(ETransport.raw),
            StreamSecurity = Global.StreamSecurity,
            Sni = "sni.anytls.example",
            Alpn = "h2,http/1.1",
            AllowInsecure = Global.StringTrue,
        };

        item.SetTransportExtra(new TransportExtraItem { RawHeaderType = Global.None, });

        return item;
    }

    private static ProfileItem CreateHysteria2Profile()
    {
        // CertSha is deliberately left unset: the importer turns AllowInsecure on by itself when a
        // pinSHA256 is present, which would mask an exporter that stopped emitting insecure=1.
        var item = new ProfileItem
        {
            ConfigType = EConfigType.Hysteria2,
            Remarks = "hysteria2 demo",
            Address = "hy2.example",
            Port = 8443,
            Password = "demo-user:demo-pass",
            Sni = "sni.hy2.example",
            Alpn = "h3",
            EchConfigList = "AAj+DQAEAAAAAA==",
            AllowInsecure = Global.StringTrue,
        };

        item.SetProtocolExtra(new ProtocolExtraItem
        {
            SalamanderPass = "salamander-pass",
            Ports = "5000:6000",
        });

        return item;
    }

    private static string CreateWireguardKey(byte value)
    {
        return Convert.ToBase64String(Enumerable.Repeat(value, 32).ToArray());
    }

    private static ProfileItem CreateWireguardProfile()
    {
        var item = new ProfileItem
        {
            ConfigType = EConfigType.WireGuard,
            Remarks = "WireGuard — тест 東京 #1",
            Address = "2001:db8::40",
            Port = 51820,
            Password = CreateWireguardKey(0xFE),
        };

        item.SetProtocolExtra(new ProtocolExtraItem
        {
            WgPublicKey = CreateWireguardKey(0xFD),
            WgPresharedKey = CreateWireguardKey(0xFC),
            WgReserved = "1,2,255",
            WgInterfaceAddress = "10.0.0.2/32,fd00::2/128",
            WgMtu = 1420,
        });

        return item;
    }

    private static ProfileItem CreateNaiveProfile(bool quic)
    {
        var item = new ProfileItem
        {
            ConfigType = EConfigType.Naive,
            Remarks = quic ? "naive quic demo" : "naive https demo",
            Address = "naive.example",
            Port = 443,
            Username = "naive-user",
            Password = "päss:word@/?#&=+ 東京",
            Network = nameof(ETransport.raw),
            StreamSecurity = Global.None,
        };

        item.SetProtocolExtra(new ProtocolExtraItem { NaiveQuic = quic, InsecureConcurrency = 4, });
        item.SetTransportExtra(new TransportExtraItem { RawHeaderType = Global.None, });

        return item;
    }
}
