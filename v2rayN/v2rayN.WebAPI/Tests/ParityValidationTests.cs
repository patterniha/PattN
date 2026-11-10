using ServiceLib;
using ServiceLib.Enums;
using ServiceLib.Handler;
using ServiceLib.Helper;
using ServiceLib.Manager;
using ServiceLib.Models.Configs;
using ServiceLib.Models.Entities;
using ServiceLib.Resx;
using v2rayN.WebAPI.Contracts;
using v2rayN.WebAPI.Services;

namespace v2rayN.WebAPI.Tests;

public class ParityValidationTests
{
    [Test]
    public async Task RestoredSubscriptionSelectionIsPreservedOnlyWhenItsSubItemExists()
    {
        var available = new[] { "subscription-a", "subscription-b" };
        await V2rayRuntime.NormalizeSelectedSubscriptionId("subscription-a", available).Should().BeEqualTo("subscription-a");
        await V2rayRuntime.NormalizeSelectedSubscriptionId("deleted-subscription", available).Should().BeEqualTo(string.Empty);
        await V2rayRuntime.NormalizeSelectedSubscriptionId(string.Empty, available).Should().BeEqualTo(string.Empty);
    }

    [Test]
    public async Task XrayShadowsocksPlainIsAcceptedAndSavedByServiceLib()
    {
        var profile = CreateShadowsocks(ECoreType.Xray, "plain");

        var valid = V2rayRuntime.TryValidateProfile(profile, out var code, out _);
        await valid.Should().BeTrue();
        await code.Should().BeEqualTo("ok");
        await profile.IsValid().Should().BeFalse();

        var result = await ConfigHandler.AddShadowsocksServer(new Config(), profile, toFile: false);

        await result.Should().BeEqualTo(0);
        await profile.ConfigVersion.Should().BeEqualTo(4);
    }

    [Test]
    public async Task SingboxShadowsocksMethodIsAcceptedAndSavedByServiceLib()
    {
        var method = "aes-128-gcm";
        var profile = CreateShadowsocks(ECoreType.sing_box, method);

        var valid = V2rayRuntime.TryValidateProfile(profile, out var code, out _);
        await valid.Should().BeTrue();
        await code.Should().BeEqualTo("ok");
        await profile.IsValid().Should().BeTrue();

        var result = await ConfigHandler.AddShadowsocksServer(new Config(), profile, toFile: false);

        await result.Should().BeEqualTo(0);
    }

    [Test]
    public async Task InvalidShadowsocksMethodIsLeftForServiceLibToReject()
    {
        var profile = CreateShadowsocks(ECoreType.Xray, "not-a-method");

        var valid = V2rayRuntime.TryValidateProfile(profile, out _, out _);
        await valid.Should().BeTrue();

        var result = await ConfigHandler.AddShadowsocksServer(new Config(), profile, toFile: false);

        await result.Should().BeEqualTo(-1);
    }

    [Test]
    public async Task ExistingProfileConfigTypeCannotChange()
    {
        var existing = CreateShadowsocks(ECoreType.Xray, "plain");
        var unchanged = CreateShadowsocks(ECoreType.Xray, "plain");
        var converted = new ProfileItem { ConfigType = EConfigType.VLESS };

        await V2rayRuntime.IsConfigTypeUnchanged(unchanged, existing).Should().BeTrue();
        await V2rayRuntime.IsConfigTypeUnchanged(converted, existing).Should().BeFalse();
    }

    [Test]
    public async Task HttpHeadersJsonUsesServiceLibParserOnlyForHttpProfiles()
    {
        var validHttp = CreateProfile(EConfigType.HTTP);
        validHttp.SetProtocolExtra(new ProtocolExtraItem { HttpHeaders = "{\"X-Test\":\"value\"}" });
        var emptyHttp = CreateProfile(EConfigType.HTTP);
        emptyHttp.SetProtocolExtra(new ProtocolExtraItem { HttpHeaders = string.Empty });
        var invalidHttp = CreateProfile(EConfigType.HTTP);
        invalidHttp.SetProtocolExtra(new ProtocolExtraItem { HttpHeaders = "{invalid" });
        var invalidNonHttp = CreateProfile(EConfigType.SOCKS);
        invalidNonHttp.SetProtocolExtra(new ProtocolExtraItem { HttpHeaders = "{invalid" });
        var originalInvalidHeaders = invalidHttp.ProtoExtra;

        await V2rayRuntime.TryValidateProfile(validHttp, out _, out _).Should().BeTrue();
        await V2rayRuntime.TryValidateProfile(emptyHttp, out _, out _).Should().BeTrue();
        await V2rayRuntime.TryValidateProfile(invalidHttp, out var code, out _).Should().BeFalse();
        await code.Should().BeEqualTo("profile_http_headers_invalid");
        await (invalidHttp.ProtoExtra == originalInvalidHeaders).Should().BeTrue();
        await V2rayRuntime.TryValidateProfile(invalidNonHttp, out _, out _).Should().BeTrue();
    }

    [Test]
    public async Task EchOutboundIsCheckedLikeTheServerEditor()
    {
        // PattN: NodeValidator.ValidateEchOutbound, which AddServerViewModel runs before saving
        static ProfileItem CreateEchProfile(string echConfigList, string echOutbound)
        {
            var profile = CreateProfile(EConfigType.VLESS);
            profile.Password = "id";
            profile.StreamSecurity = Global.StreamSecurity;
            profile.EchConfigList = echConfigList;
            profile.EchOutbound = echOutbound;
            return profile;
        }

        var valid = CreateEchProfile("ech-config-list", "{\"tag\":\"ech-out\",\"protocol\":\"freedom\"}");
        var withoutConfigList = CreateEchProfile(string.Empty, "{\"tag\":\"ech-out\",\"protocol\":\"freedom\"}");
        var proxyTag = CreateEchProfile("ech-config-list", "{\"tag\":\"proxy-ech\",\"protocol\":\"freedom\"}");
        var notAnObject = CreateEchProfile("ech-config-list", "[]");

        await V2rayRuntime.TryValidateProfile(valid, out _, out _).Should().BeTrue();
        await V2rayRuntime.TryValidateProfile(withoutConfigList, out var code, out _).Should().BeFalse();
        await code.Should().BeEqualTo("profile_ech_outbound_invalid");
        await V2rayRuntime.TryValidateProfile(proxyTag, out _, out _).Should().BeFalse();
        await V2rayRuntime.TryValidateProfile(notAnObject, out _, out _).Should().BeFalse();
    }

    // PattN (X2): the TLS settings the server editor refuses (TlsSettingsCheck): cipherSuites without the unsafe
    // fingerprint on a profile Xray runs, and an alpn other than http/1.1 for WebSocket or HTTPUpgrade, whatever the core.
    [Test]
    public async Task TlsSettingsAreCheckedLikeTheServerEditor()
    {
        foreach (var type in new[] { EConfigType.VMess, EConfigType.VLESS, EConfigType.Shadowsocks, EConfigType.Trojan, EConfigType.SOCKS, EConfigType.HTTP })
        {
            // cipherSuites with chrome, or with an empty fingerprint that the settings make chrome's, under Xray.
            await AssertTlsRefused(V2rayRuntime.TlsSettingsRefusal(CreateTlsProfile(type, fingerprint: "chrome", cipherSuites: CipherSuites), "chrome", ECoreType.Xray),
                "profile_cipher_suites_need_unsafe", ResUI.MsgCipherSuitesNeedUnsafe, $"{type} chrome");
            await AssertTlsRefused(V2rayRuntime.TlsSettingsRefusal(CreateTlsProfile(type, cipherSuites: CipherSuites), "chrome", ECoreType.Xray),
                "profile_cipher_suites_need_unsafe", ResUI.MsgCipherSuitesNeedUnsafe, $"{type} empty");
            foreach (var network in new[] { "ws", "httpupgrade" })
            {
                foreach (var alpn in new[] { "h2", "h3", "h2,http/1.1" })
                {
                    foreach (var core in new[] { ECoreType.Xray, ECoreType.sing_box })
                    {
                        await AssertTlsRefused(V2rayRuntime.TlsSettingsRefusal(CreateTlsProfile(type, network, "chrome", alpn), "chrome", core),
                            "profile_websocket_alpn_http1_only", ResUI.MsgWebsocketAlpnHttp1Only, $"{type} {network} {alpn} {core}");
                    }
                }
            }
        }

        // What the editor saves passes: unsafe, an unsafe default, no cipherSuites, sing-box, http/1.1 or no alpn, grpc with h2.
        await V2rayRuntime.TlsSettingsRefusal(CreateTlsProfile(EConfigType.VLESS, fingerprint: "unsafe", cipherSuites: CipherSuites), "chrome", ECoreType.Xray).Should().BeNull();
        await V2rayRuntime.TlsSettingsRefusal(CreateTlsProfile(EConfigType.VLESS, cipherSuites: CipherSuites), "unsafe", ECoreType.Xray).Should().BeNull();
        await V2rayRuntime.TlsSettingsRefusal(CreateTlsProfile(EConfigType.VLESS, fingerprint: "chrome"), "chrome", ECoreType.Xray).Should().BeNull();
        await V2rayRuntime.TlsSettingsRefusal(CreateTlsProfile(EConfigType.VLESS, cipherSuites: CipherSuites), "chrome", ECoreType.sing_box).Should().BeNull();
        await V2rayRuntime.TlsSettingsRefusal(CreateTlsProfile(EConfigType.VLESS, fingerprint: "chrome", cipherSuites: CipherSuites), "chrome", ECoreType.sing_box).Should().BeNull();
        await V2rayRuntime.TlsSettingsRefusal(CreateTlsProfile(EConfigType.VLESS, "ws", "chrome", "http/1.1"), "chrome", ECoreType.Xray).Should().BeNull();
        await V2rayRuntime.TlsSettingsRefusal(CreateTlsProfile(EConfigType.VLESS, "ws", "chrome"), "chrome", ECoreType.Xray).Should().BeNull();
        await V2rayRuntime.TlsSettingsRefusal(CreateTlsProfile(EConfigType.VLESS, "grpc", "chrome", "h2"), "chrome", ECoreType.Xray).Should().BeNull();
        // Outside TLS, and on Hysteria2, whose editor shows neither, nothing is refused.
        var noTls = CreateTlsProfile(EConfigType.VLESS, "ws", "chrome", "h2", CipherSuites);
        noTls.StreamSecurity = string.Empty;
        await V2rayRuntime.TlsSettingsRefusal(noTls, "chrome", ECoreType.Xray).Should().BeNull();
        await V2rayRuntime.TlsSettingsRefusal(CreateTlsProfile(EConfigType.Hysteria2, "ws", "chrome", "h2", CipherSuites), "chrome", ECoreType.Xray).Should().BeNull();
    }

    // PattN (X2): curvePreferences without the unsafe fingerprint on a profile Xray runs are refused as cipherSuites are,
    // with a code of their own, after the cipherSuites one.
    [Test]
    public async Task CurvePreferencesAreCheckedLikeTheServerEditor()
    {
        foreach (var type in new[] { EConfigType.VMess, EConfigType.VLESS, EConfigType.Shadowsocks, EConfigType.Trojan, EConfigType.SOCKS, EConfigType.HTTP })
        {
            var chrome = CreateTlsProfile(type, fingerprint: "chrome");
            chrome.CurvePreferences = "X25519MLKEM768,X25519";
            await AssertTlsRefused(V2rayRuntime.TlsSettingsRefusal(chrome, "chrome", ECoreType.Xray),
                "profile_curve_preferences_need_unsafe", ResUI.MsgCurvePreferencesNeedUnsafe, $"{type} chrome");
            var empty = CreateTlsProfile(type);
            empty.CurvePreferences = "X25519";
            await AssertTlsRefused(V2rayRuntime.TlsSettingsRefusal(empty, "chrome", ECoreType.Xray),
                "profile_curve_preferences_need_unsafe", ResUI.MsgCurvePreferencesNeedUnsafe, $"{type} empty");
        }

        var both = CreateTlsProfile(EConfigType.VLESS, fingerprint: "chrome", cipherSuites: CipherSuites);
        both.CurvePreferences = "X25519";
        await AssertTlsRefused(V2rayRuntime.TlsSettingsRefusal(both, "chrome", ECoreType.Xray),
            "profile_cipher_suites_need_unsafe", ResUI.MsgCipherSuitesNeedUnsafe, "both");

        // unsafe, an unsafe default, sing-box and enableSessionResumption alone pass.
        var unsafeOne = CreateTlsProfile(EConfigType.VLESS, fingerprint: "unsafe");
        unsafeOne.CurvePreferences = "X25519";
        unsafeOne.EnableSessionResumption = true;
        await V2rayRuntime.TlsSettingsRefusal(unsafeOne, "chrome", ECoreType.Xray).Should().BeNull();
        var unsafeDefault = CreateTlsProfile(EConfigType.VLESS);
        unsafeDefault.CurvePreferences = "X25519";
        await V2rayRuntime.TlsSettingsRefusal(unsafeDefault, "unsafe", ECoreType.Xray).Should().BeNull();
        var singBox = CreateTlsProfile(EConfigType.VLESS, fingerprint: "chrome");
        singBox.CurvePreferences = "X25519";
        await V2rayRuntime.TlsSettingsRefusal(singBox, "chrome", ECoreType.sing_box).Should().BeNull();
        var resumption = CreateTlsProfile(EConfigType.VLESS, fingerprint: "chrome");
        resumption.EnableSessionResumption = true;
        await V2rayRuntime.TlsSettingsRefusal(resumption, "chrome", ECoreType.Xray).Should().BeNull();
    }

    // PattN (X2): a save through the API runs the TLS checks with the default fingerprint of the settings and the core
    // that runs the profile, the one it names or the one the settings give its type; a refused save writes nothing.
    [Test]
    [NotInParallel]
    public async Task TheApiRefusesToSaveTheTlsSettingsTheServerEditorRefuses()
    {
        var manager = AppManager.Instance;
        var configField = typeof(AppManager).GetField("_config", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
            ?? throw new MissingFieldException(typeof(AppManager).FullName, "_config");
        var previousConfig = configField.GetValue(manager);
        var remarks = $"tls-{Guid.NewGuid():N}";
        static Config Settings(ECoreType vlessCore) => new()
        {
            SubIndexId = string.Empty,
            CoreBasicItem = new CoreBasicItem { DefFingerprint = "chrome" },
            CoreTypeItem = [new CoreTypeItem { ConfigType = EConfigType.VLESS, CoreType = vlessCore }],
        };
        ProfileItem Tls(string network, string fingerprint, string alpn, string cipherSuites, ECoreType? core = null)
        {
            var profile = CreateTlsProfile(EConfigType.VLESS, network, fingerprint, alpn, cipherSuites);
            profile.Remarks = remarks;
            profile.Password = "5783a3e7-e373-51cd-8642-c83782b807c5";
            profile.CoreType = core;
            return profile;
        }
        try
        {
            configField.SetValue(manager, Settings(ECoreType.Xray));
            SQLiteHelper.Instance.CreateTable<ProfileItem>();
            var runtime = new V2rayRuntime(null!, null!, null!, null!, null!);

            // An empty fingerprint is the default one of the settings, chrome's.
            var cipherSuites = await runtime.SaveProfileAsync(Tls("raw", string.Empty, string.Empty, CipherSuites));
            await AssertTlsRefused(cipherSuites, "profile_cipher_suites_need_unsafe", ResUI.MsgCipherSuitesNeedUnsafe, "settings Xray");

            // The settings give VLESS sing-box: a profile that names Xray is refused all the same, and the alpn rule holds.
            configField.SetValue(manager, Settings(ECoreType.sing_box));
            var namedXray = await runtime.SaveProfileAsync(Tls("raw", "chrome", string.Empty, CipherSuites, ECoreType.Xray));
            await AssertTlsRefused(namedXray, "profile_cipher_suites_need_unsafe", ResUI.MsgCipherSuitesNeedUnsafe, "named Xray");
            var alpn = await runtime.SaveProfileAsync(Tls("ws", "chrome", "h2,http/1.1", CipherSuites));
            await AssertTlsRefused(alpn, "profile_websocket_alpn_http1_only", ResUI.MsgWebsocketAlpnHttp1Only, "settings sing-box");

            await (await manager.GetProfileItemViaRemarks(remarks)).Should().BeNull();
        }
        finally
        {
            configField.SetValue(manager, previousConfig);
        }
    }

    private const string CipherSuites = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";

    private static ProfileItem CreateTlsProfile(EConfigType type, string network = "raw", string fingerprint = "", string alpn = "", string cipherSuites = "")
    {
        var profile = CreateProfile(type);
        profile.Password = "id";
        profile.StreamSecurity = Global.StreamSecurity;
        profile.Network = network;
        profile.Fingerprint = fingerprint;
        profile.Alpn = alpn;
        profile.CipherSuites = cipherSuites;
        return profile;
    }

    private static async Task AssertTlsRefused(OperationView? refusal, string code, string detail, string because)
    {
        await (refusal?.Success).Should().BeEqualTo(false).Because(because);
        await refusal!.Code.Should().BeEqualTo(code).Because(because);
        await refusal.MessageKey.Should().BeEqualTo(ApiMessageKeys.ProfileInvalid).Because(because);
        await System.Text.Json.JsonSerializer.Serialize(refusal.Data).Should().Contain(System.Text.Json.JsonSerializer.Serialize(new { detail })).Because(because);
    }

    [Test]
    public async Task WebCoreMappingsAreLimitedToUpstreamEditableTypes()
    {
        var editableTypes = Enum.GetValues<EConfigType>()
            .Where(V2rayRuntime.IsWebEditableCoreType)
            .ToArray();
        var expected = new[]
        {
            EConfigType.VMess,
            EConfigType.Custom,
            EConfigType.Shadowsocks,
            EConfigType.SOCKS,
            EConfigType.VLESS,
            EConfigType.Trojan,
            EConfigType.Hysteria2,
            EConfigType.WireGuard,
        };
        await (editableTypes.SequenceEqual(expected)).Should().BeTrue();

        var validMappings = expected.Select(configType => new CoreTypeMapping(configType, ECoreType.Xray)).ToArray();
        await V2rayRuntime.AreWebCoreTypeMappingsValid(validMappings).Should().BeTrue();
        foreach (var configType in new[]
                 {
                     EConfigType.TUIC, EConfigType.HTTP, EConfigType.Anytls, EConfigType.Naive,
                     EConfigType.Outbound, EConfigType.PolicyGroup, EConfigType.ProxyChain,
                 })
        {
            await V2rayRuntime.AreWebCoreTypeMappingsValid([new(configType, ECoreType.Xray)]).Should().BeFalse();
        }
    }

    [Test]
    public async Task FixedCoreSettingsOptionsRejectUnknownValuesAndAllowEmptyValues()
    {
        await V2rayRuntime.AreCoreSettingsOptionsValid(CreateCoreSettings(
            fingerprint: "chrome", userAgent: "chrome", mux4SboxProtocol: "h2mux",
            xudpProxyUDP443: "reject", fragmentPackets: "tlshello")).Should().BeTrue();
        await V2rayRuntime.AreCoreSettingsOptionsValid(CreateCoreSettings(
            fingerprint: string.Empty, userAgent: string.Empty, mux4SboxProtocol: string.Empty,
            xudpProxyUDP443: null, fragmentPackets: null)).Should().BeTrue();
        await V2rayRuntime.AreCoreSettingsOptionsValid(CreateCoreSettings(
            fingerprint: "random-user-value", userAgent: "random-user-value", mux4SboxProtocol: "random-user-value",
            xudpProxyUDP443: "random-user-value", fragmentPackets: "random-user-value")).Should().BeFalse();
    }

    [Test]
    public async Task DestOverrideOnlyAcceptsUpstreamProtocols()
    {
        await V2rayRuntime.AreDestOverrideProtocolsValid(["http", "tls"]).Should().BeTrue();
        await V2rayRuntime.AreDestOverrideProtocolsValid([]).Should().BeTrue();
        await V2rayRuntime.AreDestOverrideProtocolsValid(null).Should().BeTrue();
        await V2rayRuntime.AreDestOverrideProtocolsValid(["http", "arbitrary"]).Should().BeFalse();
    }

    [Test]
    public async Task RootCertificateProviderAcceptsOnlyDesktopOptionsOrAnEmptyValue()
    {
        await V2rayRuntime.IsRootCertProviderValid(null).Should().BeTrue();
        await V2rayRuntime.IsRootCertProviderValid(string.Empty).Should().BeTrue();
        foreach (var provider in Global.RootCertProviders)
        {
            await V2rayRuntime.IsRootCertProviderValid(provider).Should().BeTrue();
        }
        await V2rayRuntime.IsRootCertProviderValid("not-a-desktop-provider").Should().BeFalse();
    }

    [Test]
    public async Task SettingsApiDoesNotInventDesktopEditorFieldsForHiddenServiceLibValues()
    {
        await (typeof(CoreSettingsView).GetProperty("Mux4SboxMaxConnections") is null).Should().BeTrue();
        await (typeof(CoreSettingsInput).GetProperty("Mux4SboxMaxConnections") is null).Should().BeTrue();
        await (typeof(SpeedTestSettingsView).GetProperty("SpeedTestPageSize") is null).Should().BeTrue();
        await (typeof(SpeedTestSettingsInput).GetProperty("SpeedTestDelayInterval") is null).Should().BeTrue();
    }

    [Test]
    public async Task RoutingProfileStrategiesUseTheTwoUpstreamOptionSets()
    {
        foreach (var strategy in new[] { string.Empty, "AsIs", "IPIfNonMatch", "IPOnDemand" })
        {
            await V2rayRuntime.AreRoutingProfileStrategiesValid(strategy, string.Empty).Should().BeTrue();
        }
        foreach (var strategy in new[] { "", "prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only" })
        {
            await V2rayRuntime.AreRoutingProfileStrategiesValid("AsIs", strategy).Should().BeTrue();
        }
        await V2rayRuntime.AreRoutingProfileStrategiesValid("UseIP", "random-value").Should().BeFalse();
    }

    [Test]
    public async Task FullConfigTemplateTunConfigCanBeEditedSavedAndReloadedWithoutLoss()
    {
        var current = new FullConfigTemplateItem
        {
            Id = "template-id",
            Remarks = "custom template",
            Enabled = true,
            CoreType = ECoreType.Xray,
            Config = "main-template",
            TunConfig = "old-tun-template",
            AddProxyOnly = true,
            ProxyDetour = "upstream",
        };
        var saved = V2rayRuntime.ApplyCoreConfigTemplateInput(current, ECoreType.Xray,
            new CoreConfigTemplateInput(current.Remarks, current.Enabled, current.Config, "new-tun-template", current.AddProxyOnly, current.ProxyDetour));
        var reloaded = V2rayRuntime.ToCoreConfigTemplateView(saved);

        await reloaded.Config.Should().BeEqualTo("main-template");
        await reloaded.TunConfig.Should().BeEqualTo("new-tun-template");
        await reloaded.AddProxyOnly.Should().BeEqualTo(true);
        await reloaded.ProxyDetour.Should().BeEqualTo("upstream");
    }

    private static ProfileItem CreateShadowsocks(ECoreType coreType, string method)
    {
        var profile = CreateProfile(EConfigType.Shadowsocks);
        profile.CoreType = coreType;
        profile.Password = "password";
        profile.ConfigVersion = 3;
        profile.SetProtocolExtra(new ProtocolExtraItem { SsMethod = method });
        return profile;
    }

    private static ProfileItem CreateProfile(EConfigType configType) => new()
    {
        ConfigType = configType,
        Remarks = "test profile",
        Address = "example.test",
        Port = 443,
    };

    private static CoreSettingsInput CreateCoreSettings(
        string? fingerprint,
        string? userAgent,
        string? mux4SboxProtocol,
        string? xudpProxyUDP443,
        string? fragmentPackets) => new(
            false, "warning", fingerprint, userAgent, null, null,
            null, null, xudpProxyUDP443, mux4SboxProtocol, null, false,
            0, 0, false, false, fragmentPackets, [], [], null);
}
