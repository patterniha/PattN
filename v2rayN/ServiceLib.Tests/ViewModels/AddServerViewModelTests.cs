using ReactiveUI.Primitives;
using ReactiveUI.Primitives.Extensions;
using ServiceLib.Tests.CoreConfig;
using ServiceLib.ViewModels;
using TUnit.Assertions.Enums;

namespace ServiceLib.Tests.ViewModels;

/// <summary>
/// PattN (design 3.3, stage 10): the server editor's finalMask, cipherSuites and dialMode as preset fields (PattNG
/// PresetField in BaseServerActivity), and the save checks of PattNG's TlsSettingsCheck. The editor is made where no UI
/// thread is. No test writes the database: a refused save stops before it, and a save that passes the checks is a new
/// VMess profile with a security the handler does not know, which ConfigHandler.AddVMessServer refuses before it stores
/// anything.
/// </summary>
[NotInParallel("AppManager config")]
public class AddServerViewModelTests
{
    private const string Suites = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";

    private static string FinalMask(int index) => Global.FinalMaskPresets[index].Value;

    private static string FinalMaskName(int index) => Global.FinalMaskPresets[index].Name;

    /// <summary>A new profile of <paramref name="type" />, filled in so that the checks before the TLS ones pass.</summary>
    private static ProfileItem NewProfile(EConfigType type = EConfigType.VLESS, string finalmask = "", string cipherSuites = "", string dialMode = "")
    {
        return new ProfileItem
        {
            ConfigType = type,
            Remarks = "tls",
            Address = "example.com",
            Port = 443,
            Password = "5783a3e7-e373-51cd-8642-c83782b807c5",
            Finalmask = finalmask,
            CipherSuites = cipherSuites,
            DialMode = dialMode,
        };
    }

    /// <summary>
    /// The editor of <paramref name="profile" />, with <paramref name="defaultFingerprint" /> as the settings' default
    /// fingerprint and <paramref name="vmessCore" /> as the core they give VMess, its fields matched.
    /// </summary>
    private static async Task<AddServerViewModel> Editor(ProfileItem profile, string? defaultFingerprint = "chrome", ECoreType vmessCore = ECoreType.Xray)
    {
        var config = CoreConfigTestFactory.CreateConfig(vmessCore);
        config.CoreBasicItem.DefFingerprint = defaultFingerprint;
        var vm = await Task.Run(() => ViewModelConfig.With(config, () => new AddServerViewModel(profile)));
        await vm.FinalmaskPreset.Matched;
        await vm.CipherSuitesPreset.Matched;
        await vm.DialModePreset.Matched;
        return vm;
    }

    /// <summary>
    /// The editor of a new profile of <paramref name="type" /> under TLS over <paramref name="network" />, as the window
    /// sets them once it is open (a new profile starts with no security).
    /// </summary>
    private static async Task<AddServerViewModel> TlsEditor(
        EConfigType type = EConfigType.VLESS,
        string network = "ws",
        string fingerprint = "",
        string alpn = "",
        string cipherSuites = "",
        string? defaultFingerprint = "chrome",
        ECoreType vmessCore = ECoreType.Xray)
    {
        var vm = await Editor(NewProfile(type), defaultFingerprint, vmessCore);
        vm.SelectedSource.StreamSecurity = Global.StreamSecurity;
        vm.SelectedSource.Network = network;
        vm.SelectedSource.Fingerprint = fingerprint;
        vm.SelectedSource.Alpn = alpn;
        vm.CipherSuitesPreset.Text = cipherSuites;
        await vm.CipherSuitesPreset.Matched;
        if (type == EConfigType.VMess)
        {
            // A security ConfigHandler.AddVMessServer does not know: the save that passes the checks stops there.
            vm.VmessSecurity = "not-a-security";
        }
        return vm;
    }

    /// <summary>Saves and gives the snackbar messages sent meanwhile; other tests may send some too.</summary>
    private static async Task<ConcurrentQueue<string>> Save(AddServerViewModel vm)
    {
        var shown = new ConcurrentQueue<string>();
        using (AppEvents.SendSnackMsgRequested.AsObservable().Subscribe(shown.Enqueue))
        {
            await vm.SaveCmd.Execute().ToTask();
        }
        return shown;
    }

    /// <summary>Answers the replace question with <paramref name="answer" /> and gives the questions asked.</summary>
    private static List<(string Setting, string Pick)> Answering(PresetFieldViewModel field, bool answer)
    {
        var asked = new List<(string Setting, string Pick)>();
        field.ReplaceInteraction.RegisterHandler(interaction =>
        {
            asked.Add(interaction.Input);
            interaction.SetOutput(answer);
        });
        return asked;
    }

    /// <summary><paramref name="node" /> with the keys of every object in the reverse order.</summary>
    private static JsonNode? Reversed(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject obj:
                var reversed = new JsonObject();
                foreach (var (key, value) in obj.ToList().AsEnumerable().Reverse())
                {
                    reversed[key] = Reversed(value);
                }
                return reversed;

            case JsonArray array:
                return new JsonArray(array.Select(Reversed).ToArray());

            default:
                return node?.DeepClone();
        }
    }

    #region the preset fields

    [Test]
    public async Task TheFieldsOpenOnTheProfilesValuesAndNameThePresetsTheyHold()
    {
        // JSON in another layout and key order, at every depth, and cipher names whatever the spaces around each, with
        // an empty name that counts for none.
        var finalmask = Reversed(JsonNode.Parse(FinalMask(1)))!.ToJsonString();
        var (suitesName, suites) = Global.CipherSuitesPresets[1];
        var spaced = string.Join(" : ", suites.Split(':')) + " :";
        var vm = await Editor(NewProfile(finalmask: finalmask, cipherSuites: spaced));

        await vm.FinalmaskPreset.Text.Should().BeEqualTo(finalmask);
        await vm.FinalmaskPreset.HeldName.Should().BeEqualTo(FinalMaskName(1));
        await vm.FinalmaskPreset.Setting.Should().BeEqualTo("finalMask");
        await vm.CipherSuitesPreset.Text.Should().BeEqualTo(spaced);
        await vm.CipherSuitesPreset.HeldName.Should().BeEqualTo(suitesName);
        await vm.CipherSuitesPreset.Setting.Should().BeEqualTo("cipherSuites");
        await vm.CipherSuitesPreset.PickNames.Should().BeEquivalentTo(
            [ResUI.TbPresetDefault, .. Global.CipherSuitesPresets.Select(preset => preset.Name)], CollectionOrdering.Matching);

        // Blank fields hold the default pick; values of the user's own hold none.
        var blank = await Editor(NewProfile());
        await blank.FinalmaskPreset.HeldName.Should().BeEqualTo(ResUI.TbPresetDefault);
        await blank.CipherSuitesPreset.HeldName.Should().BeEqualTo(ResUI.TbPresetDefault);
        var own = await Editor(NewProfile(finalmask: """{"tcp": []}""", cipherSuites: "TLS_AES_128_GCM_SHA256"));
        await own.FinalmaskPreset.HeldName.Should().BeNull();
        await own.CipherSuitesPreset.HeldName.Should().BeNull();
    }

    [Test]
    public async Task TheDialModeFieldNamesThePresetItHoldsOnlyWhenItIsExactlyOne()
    {
        var (oobName, oob) = Global.DialModePresets[0];
        var vm = await Editor(NewProfile(dialMode: oob));

        await vm.DialModePreset.Text.Should().BeEqualTo(oob);
        await vm.DialModePreset.HeldName.Should().BeEqualTo(oobName);
        await vm.DialModePreset.Setting.Should().BeEqualTo("dialMode");
        await vm.DialModePreset.PickNames.Should().BeEquivalentTo(
            [ResUI.TbPresetDefault, .. Global.DialModePresets.Select(preset => preset.Name)], CollectionOrdering.Matching);

        // Blank, it holds the default; Xray reads a dialMode as written, so with a space it is the user's own.
        await (await Editor(NewProfile())).DialModePreset.HeldName.Should().BeEqualTo(ResUI.TbPresetDefault);
        await (await Editor(NewProfile(dialMode: $" {oob}"))).DialModePreset.HeldName.Should().BeNull();
    }

    [Test]
    public async Task APickOverABlankOrAPresetValueReplacesItWithoutAsking()
    {
        var vm = await Editor(NewProfile());
        var askedFinalmask = Answering(vm.FinalmaskPreset, answer: false);
        var askedSuites = Answering(vm.CipherSuitesPreset, answer: false);

        await vm.FinalmaskPreset.ChooseAtAsync(1);
        await vm.FinalmaskPreset.Text.Should().BeEqualTo(FinalMask(0));
        await vm.FinalmaskPreset.Matched;
        await vm.FinalmaskPreset.HeldName.Should().BeEqualTo(FinalMaskName(0));
        await vm.FinalmaskPreset.ChooseAtAsync(2);
        await vm.FinalmaskPreset.Text.Should().BeEqualTo(FinalMask(1));

        await vm.CipherSuitesPreset.ChooseAtAsync(1);
        await vm.CipherSuitesPreset.Text.Should().BeEqualTo(Global.CipherSuitesPresets[0].Value);
        await vm.CipherSuitesPreset.Matched;
        await vm.CipherSuitesPreset.ChooseAtAsync(2);
        await vm.CipherSuitesPreset.Text.Should().BeEqualTo(Global.CipherSuitesPresets[1].Value);

        await askedFinalmask.Should().BeEmpty();
        await askedSuites.Should().BeEmpty();
    }

    [Test]
    public async Task APickOverAValueOfTheUsersOwnAsksFirst()
    {
        const string ownMask = """{"udp": [{"type": "noise"}]}""";
        const string ownSuites = "TLS_AES_128_GCM_SHA256";
        var vm = await Editor(NewProfile(finalmask: ownMask, cipherSuites: ownSuites));
        var keep = Answering(vm.FinalmaskPreset, answer: false);
        var replace = Answering(vm.CipherSuitesPreset, answer: true);

        await vm.FinalmaskPreset.ChooseAtAsync(1);
        await vm.FinalmaskPreset.Text.Should().BeEqualTo(ownMask);
        await keep.Should().BeEquivalentTo([("finalMask", FinalMaskName(0))], CollectionOrdering.Matching);

        await vm.CipherSuitesPreset.ChooseAtAsync(1);
        await vm.CipherSuitesPreset.Text.Should().BeEqualTo(Global.CipherSuitesPresets[0].Value);
        await replace.Should().BeEquivalentTo([("cipherSuites", Global.CipherSuitesPresets[0].Name)], CollectionOrdering.Matching);
    }

    [Test]
    public async Task DefaultBlanksTheField()
    {
        var vm = await Editor(NewProfile(finalmask: FinalMask(2), cipherSuites: "TLS_AES_128_GCM_SHA256"));
        var none = Answering(vm.FinalmaskPreset, answer: false);
        var asked = Answering(vm.CipherSuitesPreset, answer: true);

        // Over a preset at once; over a value of the user's own once asked.
        await vm.FinalmaskPreset.ChooseAtAsync(0);
        await vm.FinalmaskPreset.Text.Should().BeEqualTo(string.Empty);
        await vm.FinalmaskPreset.HeldName.Should().BeEqualTo(ResUI.TbPresetDefault);
        await none.Should().BeEmpty();

        await vm.CipherSuitesPreset.ChooseAtAsync(0);
        await vm.CipherSuitesPreset.Text.Should().BeEqualTo(string.Empty);
        await asked.Should().BeEquivalentTo([("cipherSuites", ResUI.TbPresetDefault)], CollectionOrdering.Matching);
    }

    [Test]
    public async Task TheSaveStoresWhatTheFieldsHoldABlankOneAsNone()
    {
        var vm = await TlsEditor(EConfigType.VMess, fingerprint: TlsSettingsCheck.UnsafeFingerprint);
        await vm.FinalmaskPreset.ChooseAtAsync(1);
        await vm.CipherSuitesPreset.ChooseAtAsync(2);
        await vm.DialModePreset.ChooseAtAsync(1);
        // An edit after the pick is what is saved.
        vm.CipherSuitesPreset.Text += ":TLS_AES_128_GCM_SHA256";

        var shown = await Save(vm);

        await shown.Should().Contain(ResUI.OperationFailed);
        await vm.SelectedSource.Finalmask.Should().BeEqualTo(FinalMask(0));
        await vm.SelectedSource.CipherSuites.Should().BeEqualTo(Global.CipherSuitesPresets[1].Value + ":TLS_AES_128_GCM_SHA256");
        await vm.SelectedSource.DialMode.Should().BeEqualTo(Global.DialModePresets[0].Value);

        vm.FinalmaskPreset.Text = " \n ";
        vm.CipherSuitesPreset.Text = "  ";
        vm.DialModePreset.Text = " ";
        await Save(vm);

        await vm.SelectedSource.Finalmask.Should().BeEqualTo(string.Empty);
        await vm.SelectedSource.CipherSuites.Should().BeEqualTo(string.Empty);
        await vm.SelectedSource.DialMode.Should().BeEqualTo(string.Empty);
    }

    #endregion the preset fields

    #region the TLS save checks (PattNG TlsSettingsCheck)

    [Test]
    public async Task CipherSuitesNeedTheUnsafeFingerprint()
    {
        // PattN: SOCKS and HTTP too, whose TLS shows these settings (R10-1); a refused save never reaches the database.
        foreach (var type in new[] { EConfigType.VMess, EConfigType.VLESS, EConfigType.Shadowsocks, EConfigType.Trojan, EConfigType.SOCKS, EConfigType.HTTP })
        {
            var vm = await TlsEditor(type, fingerprint: "chrome", cipherSuites: Suites);
            if (type == EConfigType.Shadowsocks)
            {
                vm.SsMethod = "aes-128-gcm";
            }
            var closed = 0;
            vm.RequestClose += (_, _) => closed++;

            var shown = await Save(vm);

            await shown.Should().Contain(ResUI.MsgCipherSuitesNeedUnsafe).Because(type.ToString());
            await shown.Should().NotContain(ResUI.OperationSuccess).Because(type.ToString());
            await shown.Should().NotContain(ResUI.OperationFailed).Because(type.ToString());
            await closed.Should().BeEqualTo(0).Because(type.ToString());
        }

        // A preset picked into the field is checked as typed text is.
        var picked = await TlsEditor(fingerprint: "firefox");
        await picked.CipherSuitesPreset.ChooseAtAsync(1);
        await (await Save(picked)).Should().Contain(ResUI.MsgCipherSuitesNeedUnsafe);
    }

    [Test]
    public async Task TheUnsafeFingerprintOrNoCipherSuitesPass()
    {
        // The fork lowercases the fingerprint.
        foreach (var fingerprint in new[] { "unsafe", "Unsafe" })
        {
            var vm = await TlsEditor(EConfigType.VMess, fingerprint: fingerprint, cipherSuites: Suites);
            var shown = await Save(vm);
            await shown.Should().NotContain(ResUI.MsgCipherSuitesNeedUnsafe).Because(fingerprint);
            await shown.Should().Contain(ResUI.OperationFailed).Because(fingerprint);
        }

        var blank = await TlsEditor(EConfigType.VMess, fingerprint: "chrome", cipherSuites: " ");
        await (await Save(blank)).Should().Contain(ResUI.OperationFailed);

        // Outside TLS the editor hides cipherSuites, so a value left there is not refused.
        var noTls = await TlsEditor(EConfigType.VMess, fingerprint: "chrome", cipherSuites: Suites);
        noTls.SelectedSource.StreamSecurity = string.Empty;
        await (await Save(noTls)).Should().Contain(ResUI.OperationFailed);
    }

    // PattN (X1): the cipherSuites rule is for a profile Xray runs: the core chosen in the editor, or the one the settings
    // give its type. sing-box applies the cipher suites with an empty fingerprint.
    [Test]
    public async Task TheCipherSuitesRuleIsForAProfileXrayRuns()
    {
        // The core chosen in the editor.
        foreach (var fingerprint in new[] { "", "chrome" })
        {
            var singBox = await TlsEditor(EConfigType.VMess, "raw", fingerprint: fingerprint, cipherSuites: Suites);
            singBox.CoreType = nameof(ECoreType.sing_box);
            var shown = await Save(singBox);
            await shown.Should().NotContain(ResUI.MsgCipherSuitesNeedUnsafe).Because(fingerprint);
            await shown.Should().Contain(ResUI.OperationFailed).Because(fingerprint);

            var xray = await TlsEditor(EConfigType.VMess, "raw", fingerprint: fingerprint, cipherSuites: Suites, vmessCore: ECoreType.sing_box);
            xray.CoreType = nameof(ECoreType.Xray);
            await (await Save(xray)).Should().Contain(ResUI.MsgCipherSuitesNeedUnsafe).Because(fingerprint);
        }

        // None chosen: the core the settings give the type.
        var settingsSingBox = await TlsEditor(EConfigType.VMess, "raw", cipherSuites: Suites, vmessCore: ECoreType.sing_box);
        await settingsSingBox.CoreType.Should().BeNull();
        var passed = await Save(settingsSingBox);
        await passed.Should().NotContain(ResUI.MsgCipherSuitesNeedUnsafe);
        await passed.Should().Contain(ResUI.OperationFailed);
        var settingsXray = await TlsEditor(EConfigType.VMess, "raw", cipherSuites: Suites);
        await (await Save(settingsXray)).Should().Contain(ResUI.MsgCipherSuitesNeedUnsafe);

        // The alpn rule holds under sing-box too.
        var alpn = await TlsEditor(EConfigType.VMess, "ws", alpn: "h2,http/1.1", cipherSuites: Suites, vmessCore: ECoreType.sing_box);
        var refused = await Save(alpn);
        await refused.Should().Contain(ResUI.MsgWebsocketAlpnHttp1Only);
        await refused.Should().NotContain(ResUI.MsgCipherSuitesNeedUnsafe);
    }

    [Test]
    public async Task AnEmptyFingerprintIsTheDefaultOneOfTheSettings()
    {
        var chrome = await TlsEditor(EConfigType.VMess, cipherSuites: Suites, defaultFingerprint: "chrome");
        await (await Save(chrome)).Should().Contain(ResUI.MsgCipherSuitesNeedUnsafe);

        var none = await TlsEditor(EConfigType.VMess, cipherSuites: Suites, defaultFingerprint: null);
        await (await Save(none)).Should().Contain(ResUI.MsgCipherSuitesNeedUnsafe);

        var unsafeDefault = await TlsEditor(EConfigType.VMess, cipherSuites: Suites, defaultFingerprint: "unsafe");
        var shown = await Save(unsafeDefault);
        await shown.Should().NotContain(ResUI.MsgCipherSuitesNeedUnsafe);
        await shown.Should().Contain(ResUI.OperationFailed);
    }

    // PattN: curvePreferences are refused as cipherSuites are, with a message of their own, told after the cipherSuites
    // one; sing-box, which takes them as curve_preferences, is not asked (X1). enableSessionResumption is never refused.
    [Test]
    public async Task CurvePreferencesNeedTheUnsafeFingerprint()
    {
        var chrome = await TlsEditor(EConfigType.VMess, "raw", fingerprint: "chrome");
        chrome.SelectedSource.CurvePreferences = "X25519MLKEM768";
        var refused = await Save(chrome);
        await refused.Should().Contain(ResUI.MsgCurvePreferencesNeedUnsafe);
        await refused.Should().NotContain(ResUI.OperationFailed);

        var both = await TlsEditor(EConfigType.VMess, "raw", fingerprint: "chrome", cipherSuites: Suites);
        both.SelectedSource.CurvePreferences = "X25519";
        var first = await Save(both);
        await first.Should().Contain(ResUI.MsgCipherSuitesNeedUnsafe);
        await first.Should().NotContain(ResUI.MsgCurvePreferencesNeedUnsafe);

        var unsafeOne = await TlsEditor(EConfigType.VMess, "raw", fingerprint: "unsafe");
        unsafeOne.SelectedSource.CurvePreferences = "X25519MLKEM768,X25519";
        unsafeOne.SelectedSource.EnableSessionResumption = true;
        var passed = await Save(unsafeOne);
        await passed.Should().NotContain(ResUI.MsgCurvePreferencesNeedUnsafe);
        await passed.Should().Contain(ResUI.OperationFailed);

        var resumption = await TlsEditor(EConfigType.VMess, "raw", fingerprint: "chrome");
        resumption.SelectedSource.EnableSessionResumption = true;
        await (await Save(resumption)).Should().Contain(ResUI.OperationFailed);

        var singBox = await TlsEditor(EConfigType.VMess, "raw", fingerprint: "chrome");
        singBox.CoreType = nameof(ECoreType.sing_box);
        singBox.SelectedSource.CurvePreferences = "X25519";
        var singBoxShown = await Save(singBox);
        await singBoxShown.Should().NotContain(ResUI.MsgCurvePreferencesNeedUnsafe);
        await singBoxShown.Should().Contain(ResUI.OperationFailed);
    }

    [Test]
    public async Task WebSocketAndHttpUpgradeTakeOnlyHttp1OrNoAlpn()
    {
        foreach (var network in new[] { "ws", "httpupgrade" })
        {
            foreach (var alpn in new[] { "h2,http/1.1", "h3", "http/1.1,h2" })
            {
                var vm = await TlsEditor(EConfigType.VMess, network, fingerprint: "chrome", alpn: alpn);
                var shown = await Save(vm);
                await shown.Should().Contain(ResUI.MsgWebsocketAlpnHttp1Only).Because($"{network} {alpn}");
                await shown.Should().NotContain(ResUI.OperationFailed).Because($"{network} {alpn}");
            }
            foreach (var alpn in new[] { "http/1.1", "" })
            {
                var vm = await TlsEditor(EConfigType.VMess, network, fingerprint: "chrome", alpn: alpn);
                var shown = await Save(vm);
                await shown.Should().NotContain(ResUI.MsgWebsocketAlpnHttp1Only).Because($"{network} {alpn}");
                await shown.Should().Contain(ResUI.OperationFailed).Because($"{network} {alpn}");
            }
        }

        // PattN: SOCKS and HTTP over WebSocket as well (R10-1); a refused save never reaches the database.
        foreach (var type in new[] { EConfigType.SOCKS, EConfigType.HTTP })
        {
            var vm = await TlsEditor(type, "ws", fingerprint: "chrome", alpn: "h2");
            await (await Save(vm)).Should().Contain(ResUI.MsgWebsocketAlpnHttp1Only).Because(type.ToString());
        }

        // Other transports keep their alpn.
        var grpc = await TlsEditor(EConfigType.VMess, "grpc", fingerprint: "chrome", alpn: "h2");
        await (await Save(grpc)).Should().Contain(ResUI.OperationFailed);

        // cipherSuites without the unsafe fingerprint are refused first.
        var both = await TlsEditor(fingerprint: "chrome", alpn: "h2", cipherSuites: Suites);
        var first = await Save(both);
        await first.Should().Contain(ResUI.MsgCipherSuitesNeedUnsafe);
        await first.Should().NotContain(ResUI.MsgWebsocketAlpnHttp1Only);
    }

    [Test]
    public async Task TheChecksComeAfterTheEditorsOwn()
    {
        var vm = await TlsEditor(fingerprint: "chrome", alpn: "h2", cipherSuites: Suites);
        vm.SelectedSource.Remarks = string.Empty;

        var shown = await Save(vm);

        await shown.Should().Contain(ResUI.PleaseFillRemarks);
        await shown.Should().NotContain(ResUI.MsgCipherSuitesNeedUnsafe);
    }

    #endregion the TLS save checks (PattNG TlsSettingsCheck)
}
