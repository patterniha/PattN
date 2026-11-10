namespace ServiceLib.Tests.Common;

/// <summary>
/// From PattNG TlsSettingsCheckTest: the TLS settings the server editor refuses to save, as the Xray-core fork would not
/// apply them or would not connect, and the alpn an imported WebSocket or HTTPUpgrade link gets. PattN fills an empty
/// fingerprint with the default of its settings, which the check is given, and reads alpn as its outbound offers it.
/// PattN: the cipherSuites and curvePreferences rules are for the profiles Xray runs (X1), the alpn rule for every core;
/// they apply to SOCKS and HTTP as well, whose editor shows these settings under TLS (R10-1).
/// </summary>
public class TlsSettingsCheckTests
{
    private const string Suites = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";

    private static ProfileItem Profile(
        string? fingerprint = null,
        string? cipherSuites = null,
        EConfigType type = EConfigType.VLESS,
        string security = Global.StreamSecurity,
        string network = "ws",
        string? alpn = null,
        string? curvePreferences = null)
    {
        return new ProfileItem
        {
            ConfigType = type,
            StreamSecurity = security,
            Fingerprint = fingerprint ?? string.Empty,
            CipherSuites = cipherSuites ?? string.Empty,
            CurvePreferences = curvePreferences ?? string.Empty,
            Network = network,
            Alpn = alpn!,
        };
    }

    private static bool CurvesNeedUnsafe(ProfileItem profile, string? defaultFingerprint = "chrome", ECoreType core = ECoreType.Xray)
    {
        return TlsSettingsCheck.CurvePreferencesNeedUnsafe(profile, defaultFingerprint, core);
    }

    // PattNG: an empty fingerprint is Chrome's; PattN's default fingerprint stands in for it, Chrome's here. Xray runs the
    // profile unless said otherwise.
    private static bool NeedUnsafe(ProfileItem profile, string? defaultFingerprint = "chrome", ECoreType core = ECoreType.Xray)
    {
        return TlsSettingsCheck.CipherSuitesNeedUnsafe(profile, defaultFingerprint, core);
    }

    private static ETlsSettingsError? Validate(ProfileItem profile, string? defaultFingerprint = "chrome", ECoreType core = ECoreType.Xray)
    {
        return TlsSettingsCheck.Validate(profile, defaultFingerprint, core);
    }

    [Test]
    public async Task CipherSuitesNeedTheUnsafeFingerprint()
    {
        await NeedUnsafe(Profile(fingerprint: "unsafe", cipherSuites: Suites)).Should().BeFalse();
        // The fork lowercases the fingerprint.
        await NeedUnsafe(Profile(fingerprint: "Unsafe", cipherSuites: Suites)).Should().BeFalse();
        await NeedUnsafe(Profile(fingerprint: "chrome", cipherSuites: Suites)).Should().BeTrue();
        // An empty fingerprint is the default one.
        await NeedUnsafe(Profile(fingerprint: "", cipherSuites: Suites)).Should().BeTrue();
        await NeedUnsafe(Profile(fingerprint: "randomized", cipherSuites: Suites)).Should().BeTrue();
        // No cipherSuites, nothing to refuse.
        await NeedUnsafe(Profile(fingerprint: "chrome", cipherSuites: "")).Should().BeFalse();
        await NeedUnsafe(Profile(fingerprint: "chrome", cipherSuites: " \n")).Should().BeFalse();
        await NeedUnsafe(Profile(fingerprint: "chrome")).Should().BeFalse();

        // The same through the whole check, which tells why it refuses.
        await Validate(Profile(fingerprint: "unsafe", cipherSuites: Suites)).Should().BeNull();
        await Validate(Profile(fingerprint: "Unsafe", cipherSuites: Suites)).Should().BeNull();
        await Validate(Profile(fingerprint: "chrome", cipherSuites: Suites)).Should().BeEqualTo(ETlsSettingsError.CipherSuitesNeedUnsafe);
        await Validate(Profile(fingerprint: "", cipherSuites: Suites)).Should().BeEqualTo(ETlsSettingsError.CipherSuitesNeedUnsafe);
        await Validate(Profile(fingerprint: "randomized", cipherSuites: Suites, network: "raw")).Should().BeEqualTo(ETlsSettingsError.CipherSuitesNeedUnsafe);
        await Validate(Profile(fingerprint: "chrome", cipherSuites: " \n")).Should().BeNull();
        await Validate(Profile(fingerprint: "chrome")).Should().BeNull();
    }

    [Test]
    public async Task TheCheckKeepsToTheEditorsThatShowTheseSettingsUnderTls()
    {
        // PattN: SOCKS and HTTP too, whose editor shows TLS with these settings, and whose outbound Xray gives them (R10-1).
        foreach (var type in new[] { EConfigType.VMess, EConfigType.VLESS, EConfigType.Shadowsocks, EConfigType.Trojan, EConfigType.SOCKS, EConfigType.HTTP })
        {
            await NeedUnsafe(Profile(fingerprint: "chrome", cipherSuites: Suites, type: type)).Should().BeTrue().Because(type.ToString());
            await Validate(Profile(fingerprint: "chrome", cipherSuites: Suites, type: type)).Should()
                .BeEqualTo(ETlsSettingsError.CipherSuitesNeedUnsafe).Because(type.ToString());
            await Validate(Profile(fingerprint: "chrome", type: type, alpn: "h2")).Should()
                .BeEqualTo(ETlsSettingsError.WebsocketAlpnNotHttp1).Because(type.ToString());
        }
        // Hysteria2's editor shows neither cipherSuites nor alpn, so a value an imported link left there is not refused.
        await NeedUnsafe(Profile(fingerprint: "chrome", cipherSuites: Suites, type: EConfigType.Hysteria2)).Should().BeFalse();
        await Validate(Profile(fingerprint: "chrome", cipherSuites: Suites, type: EConfigType.Hysteria2)).Should().BeNull();
        await Validate(Profile(fingerprint: "unsafe", type: EConfigType.Hysteria2, alpn: "h2")).Should().BeNull();
        // PattN: nor where the editor disables them or there is no TLS of its own, nor on the types sing-box alone runs.
        foreach (var type in new[] { EConfigType.MASQUE, EConfigType.WireGuard, EConfigType.Aether, EConfigType.TUIC, EConfigType.Anytls, EConfigType.Naive })
        {
            await Validate(Profile(fingerprint: "chrome", cipherSuites: Suites, type: type)).Should().BeNull().Because(type.ToString());
            await Validate(Profile(fingerprint: "chrome", type: type, alpn: "h2")).Should().BeNull().Because(type.ToString());
        }
        // Nor under REALITY or without security, where the editor hides them.
        await NeedUnsafe(Profile(fingerprint: "chrome", cipherSuites: Suites, security: Global.StreamSecurityReality)).Should().BeFalse();
        await NeedUnsafe(Profile(fingerprint: "chrome", cipherSuites: Suites, security: "")).Should().BeFalse();
        await Validate(Profile(fingerprint: "chrome", cipherSuites: Suites, security: Global.StreamSecurityReality)).Should().BeNull();
        await Validate(Profile(fingerprint: "unsafe", security: "", alpn: "h2")).Should().BeNull();
    }

    // PattN (X1): sing-box builds the ClientHello with Go's crypto/tls for an empty fingerprint, and applies the cipher
    // suites; the rule is for the profiles Xray runs. The alpn rule holds whatever the core.
    [Test]
    public async Task TheCipherSuitesRuleIsForTheProfilesXrayRuns()
    {
        foreach (var fingerprint in new[] { "", "chrome", "unsafe" })
        {
            await NeedUnsafe(Profile(fingerprint: fingerprint, cipherSuites: Suites), core: ECoreType.sing_box).Should().BeFalse().Because(fingerprint);
            await Validate(Profile(fingerprint: fingerprint, cipherSuites: Suites, network: "raw"), core: ECoreType.sing_box).Should().BeNull().Because(fingerprint);
        }
        await NeedUnsafe(Profile(fingerprint: "", cipherSuites: Suites), core: ECoreType.Xray).Should().BeTrue();
        await Validate(Profile(fingerprint: "", cipherSuites: Suites), core: ECoreType.Xray).Should().BeEqualTo(ETlsSettingsError.CipherSuitesNeedUnsafe);
        await NeedUnsafe(Profile(fingerprint: "chrome", cipherSuites: Suites, type: EConfigType.SOCKS), core: ECoreType.sing_box).Should().BeFalse();

        // WebSocket and HTTPUpgrade connect with http/1.1 alone under sing-box as well.
        foreach (var network in new[] { "ws", "httpupgrade" })
        {
            await Validate(Profile(network: network, alpn: "h2,http/1.1"), core: ECoreType.sing_box).Should()
                .BeEqualTo(ETlsSettingsError.WebsocketAlpnNotHttp1).Because(network);
            await Validate(Profile(network: network, alpn: "h2,http/1.1", cipherSuites: Suites), core: ECoreType.sing_box).Should()
                .BeEqualTo(ETlsSettingsError.WebsocketAlpnNotHttp1).Because(network);
            await Validate(Profile(network: network, alpn: "http/1.1", cipherSuites: Suites), core: ECoreType.sing_box).Should()
                .BeNull().Because(network);
        }
    }

    // PattN: an empty fingerprint is the one the settings give Xray in its place.
    [Test]
    public async Task AnEmptyFingerprintIsTheDefaultOneOfTheSettings()
    {
        await NeedUnsafe(Profile(cipherSuites: Suites), defaultFingerprint: "unsafe").Should().BeFalse();
        await NeedUnsafe(Profile(cipherSuites: Suites), defaultFingerprint: "UNSAFE").Should().BeFalse();
        await NeedUnsafe(Profile(cipherSuites: Suites), defaultFingerprint: "chrome").Should().BeTrue();
        // With no default either, the fork takes its own, which is not unsafe.
        await NeedUnsafe(Profile(cipherSuites: Suites), defaultFingerprint: "").Should().BeTrue();
        await NeedUnsafe(Profile(cipherSuites: Suites), defaultFingerprint: null).Should().BeTrue();
        // A fingerprint of the profile's own goes before the default.
        await NeedUnsafe(Profile(fingerprint: "chrome", cipherSuites: Suites), defaultFingerprint: "unsafe").Should().BeTrue();
        await NeedUnsafe(Profile(fingerprint: "unsafe", cipherSuites: Suites), defaultFingerprint: "chrome").Should().BeFalse();

        await Validate(Profile(cipherSuites: Suites), defaultFingerprint: "unsafe").Should().BeNull();
        await Validate(Profile(cipherSuites: Suites), defaultFingerprint: null).Should().BeEqualTo(ETlsSettingsError.CipherSuitesNeedUnsafe);
    }

    // PattN: the presets of the cipherSuites field are what the rule is for.
    [Test]
    public async Task EveryCipherSuitesPresetNeedsTheUnsafeFingerprint()
    {
        foreach (var (name, value) in Global.CipherSuitesPresets)
        {
            await NeedUnsafe(Profile(fingerprint: "chrome", cipherSuites: value)).Should().BeTrue().Because(name);
            await NeedUnsafe(Profile(fingerprint: "unsafe", cipherSuites: value)).Should().BeFalse().Because(name);
        }
    }

    // PattN: curvePreferences are weighed as cipherSuites are: the fork passes uTLS no curve preferences either.
    [Test]
    public async Task CurvePreferencesNeedTheUnsafeFingerprint()
    {
        const string Curves = "X25519MLKEM768,X25519";
        foreach (var fingerprint in new[] { "unsafe", "Unsafe" })
        {
            await CurvesNeedUnsafe(Profile(fingerprint: fingerprint, curvePreferences: Curves)).Should().BeFalse().Because(fingerprint);
            await Validate(Profile(fingerprint: fingerprint, curvePreferences: Curves, network: "raw")).Should().BeNull().Because(fingerprint);
        }
        foreach (var fingerprint in new[] { "chrome", "", "randomized" })
        {
            await CurvesNeedUnsafe(Profile(fingerprint: fingerprint, curvePreferences: Curves)).Should().BeTrue().Because(fingerprint);
            await Validate(Profile(fingerprint: fingerprint, curvePreferences: Curves, network: "raw")).Should()
                .BeEqualTo(ETlsSettingsError.CurvePreferencesNeedUnsafe).Because(fingerprint);
        }
        // No curvePreferences, nothing to refuse; an empty fingerprint is the default one of the settings.
        await CurvesNeedUnsafe(Profile(fingerprint: "chrome", curvePreferences: "")).Should().BeFalse();
        await CurvesNeedUnsafe(Profile(fingerprint: "chrome", curvePreferences: " \n")).Should().BeFalse();
        await CurvesNeedUnsafe(Profile(curvePreferences: Curves), defaultFingerprint: "unsafe").Should().BeFalse();
        await CurvesNeedUnsafe(Profile(curvePreferences: Curves), defaultFingerprint: null).Should().BeTrue();

        // Where cipherSuites are not weighed, neither are curvePreferences: under REALITY or no TLS, on Hysteria2, under
        // sing-box, which takes them as curve_preferences.
        await CurvesNeedUnsafe(Profile(fingerprint: "chrome", curvePreferences: Curves, security: Global.StreamSecurityReality)).Should().BeFalse();
        await CurvesNeedUnsafe(Profile(fingerprint: "chrome", curvePreferences: Curves, security: "")).Should().BeFalse();
        await CurvesNeedUnsafe(Profile(fingerprint: "chrome", curvePreferences: Curves, type: EConfigType.Hysteria2)).Should().BeFalse();
        await CurvesNeedUnsafe(Profile(fingerprint: "chrome", curvePreferences: Curves), core: ECoreType.sing_box).Should().BeFalse();
        foreach (var type in new[] { EConfigType.VMess, EConfigType.VLESS, EConfigType.Shadowsocks, EConfigType.Trojan, EConfigType.SOCKS, EConfigType.HTTP })
        {
            await CurvesNeedUnsafe(Profile(fingerprint: "chrome", curvePreferences: Curves, type: type)).Should().BeTrue().Because(type.ToString());
        }

        // cipherSuites are told first, then curvePreferences, then the alpn.
        await Validate(Profile(fingerprint: "chrome", cipherSuites: Suites, curvePreferences: Curves, alpn: "h2")).Should()
            .BeEqualTo(ETlsSettingsError.CipherSuitesNeedUnsafe);
        await Validate(Profile(fingerprint: "chrome", curvePreferences: Curves, alpn: "h2")).Should()
            .BeEqualTo(ETlsSettingsError.CurvePreferencesNeedUnsafe);
        await Validate(Profile(fingerprint: "unsafe", curvePreferences: Curves, alpn: "h2")).Should()
            .BeEqualTo(ETlsSettingsError.WebsocketAlpnNotHttp1);
    }

    // PattN: the lists the curvePreferences field offers, but none, are what the rule is for.
    [Test]
    public async Task EveryCurvePreferencesChoiceButNoneNeedsTheUnsafeFingerprint()
    {
        foreach (var value in Global.CurvePreferences)
        {
            await CurvesNeedUnsafe(Profile(fingerprint: "chrome", curvePreferences: value)).Should().BeEqualTo(value != "").Because(value);
            await CurvesNeedUnsafe(Profile(fingerprint: "unsafe", curvePreferences: value)).Should().BeFalse().Because(value);
        }
    }

    [Test]
    public async Task WebSocketAndHttpUpgradeTakeOnlyHttp1OrNoAlpnWhateverTheFingerprint()
    {
        foreach (var network in new[] { "ws", "httpupgrade" })
        {
            foreach (var fingerprint in new[] { "unsafe", "chrome", "", "firefox", null })
            {
                // PattN: " http/1.1 " too, as PattN's outbound offers it with its spaces (PattNG trims each name).
                foreach (var alpn in new[] { "h2", "h2,http/1.1", "h3,h2,http/1.1", "h3,h2", "h3", "http/1.1,h2", " h2 , http/1.1 ", "http/1.1,h3", " http/1.1 " })
                {
                    await Validate(Profile(fingerprint: fingerprint, network: network, alpn: alpn)).Should()
                        .BeEqualTo(ETlsSettingsError.WebsocketAlpnNotHttp1).Because($"{network} {fingerprint} {alpn}");
                }
                // Read as the outbound reads it (ProfileItem.GetAlpn): empty names skipped.
                foreach (var alpn in new[] { null, "", " ", "http/1.1", "http/1.1,", ",http/1.1" })
                {
                    await Validate(Profile(fingerprint: fingerprint, network: network, alpn: alpn)).Should()
                        .BeNull().Because($"{network} {fingerprint} {alpn}");
                }
            }
        }
    }

    [Test]
    public async Task TheAlpnRuleKeepsToWebSocketAndHttpUpgrade()
    {
        // PattN: an empty or unknown network is raw, as the outbound reads it (ProfileItem.GetNetwork).
        foreach (var network in new[] { "raw", "grpc", "xhttp", "kcp", "", "websocket" })
        {
            foreach (var alpn in new[] { "h2,http/1.1", "h3", "h2" })
            {
                await Validate(Profile(fingerprint: "chrome", network: network, alpn: alpn)).Should().BeNull().Because($"{network} {alpn}");
            }
        }
        // cipherSuites with the unsafe fingerprint still meet the alpn rule, and without it they are refused first.
        await Validate(Profile(fingerprint: "unsafe", cipherSuites: Suites, network: "ws", alpn: "h2")).Should()
            .BeEqualTo(ETlsSettingsError.WebsocketAlpnNotHttp1);
        await Validate(Profile(fingerprint: "chrome", cipherSuites: Suites, network: "ws", alpn: "h2")).Should()
            .BeEqualTo(ETlsSettingsError.CipherSuitesNeedUnsafe);
    }

    [Test]
    public async Task AnImportedWebSocketOrHttpUpgradeLinkGetsHttp1InPlaceOfAnyOtherAlpn()
    {
        foreach (var network in new[] { "ws", "httpupgrade" })
        {
            foreach (var fingerprint in new[] { "chrome", "unsafe", null })
            {
                foreach (var alpn in new[] { "h2,http/1.1", "h2", "h3", "h3,h2,http/1.1", "h3,h2", "http/1.1,h2", " http/1.1 " })
                {
                    var imported = Profile(fingerprint: fingerprint, network: network, alpn: alpn);
                    TlsSettingsCheck.FixImportedAlpn(imported);
                    await imported.Alpn.Should().BeEqualTo("http/1.1").Because($"{network} {fingerprint} {alpn}");
                    await Validate(imported).Should().BeNull().Because($"{network} {fingerprint} {alpn}");
                }
            }
            // A link without alpn, or with http/1.1 alone, stays as it came.
            foreach (var alpn in new[] { null, "", " ", "http/1.1", "http/1.1," })
            {
                var imported = Profile(fingerprint: "chrome", network: network, alpn: alpn);
                TlsSettingsCheck.FixImportedAlpn(imported);
                await imported.Alpn.Should().BeEqualTo(alpn).Because($"{network} {alpn}");
            }
        }
    }

    // PattN: the import fix is the alpn rule, which holds whatever core runs the profile (X1), and for SOCKS and HTTP too (R10-1).
    [Test]
    public async Task AnImportedLinkGetsHttp1WhateverItsCoreAndForSocksAndHttpToo()
    {
        foreach (var type in new[] { EConfigType.VLESS, EConfigType.SOCKS, EConfigType.HTTP })
        {
            foreach (ECoreType? core in new ECoreType?[] { null, ECoreType.Xray, ECoreType.sing_box })
            {
                var imported = Profile(fingerprint: "chrome", type: type, network: "ws", alpn: "h2,http/1.1");
                imported.CoreType = core;
                TlsSettingsCheck.FixImportedAlpn(imported);
                await imported.Alpn.Should().BeEqualTo("http/1.1").Because($"{type} {core}");
            }
        }
    }

    [Test]
    public async Task AnImportedLinkOfAnotherTransportOrOutsideTlsKeepsItsAlpn()
    {
        var kept = new[]
        {
            Profile(network: "raw", alpn: "h2,http/1.1"),
            Profile(network: "grpc", alpn: "h2"),
            Profile(network: "xhttp", alpn: "h3"),
            Profile(network: "ws", alpn: "h2,http/1.1", security: Global.StreamSecurityReality),
            Profile(network: "ws", alpn: "h2,http/1.1", security: ""),
            Profile(network: "ws", alpn: "h2,http/1.1", type: EConfigType.Hysteria2),
        };
        foreach (var imported in kept)
        {
            var alpn = imported.Alpn;
            TlsSettingsCheck.FixImportedAlpn(imported);
            await imported.Alpn.Should().BeEqualTo(alpn).Because($"{imported.ConfigType} {imported.Network} {imported.StreamSecurity}");
        }
    }
}
