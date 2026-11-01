namespace ServiceLib.Tests.Common;

/// <summary>
/// From PattNG FieldPresetsTest: the ready-made values the finalMask and cipherSuites fields offer, which one a field
/// holds, whether a pick asks before it takes the field's place, and the lists themselves as Global gives them.
/// </summary>
public class FieldPresetsTests
{
    private const string Fragment = """{"tcp": [{"type": "fragment", "settings": {"packets": "tlshello"}}]}""";
    private const string Noise = """{"udp": [{"type": "noise", "settings": {"noise": [{"rand": "10-20", "delay": "10"}]}}]}""";
    private const string Ecdsa = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
    private const string Rsa = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
    private const string Chacha = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";

    private static readonly FieldPresets Masks = new([Fragment, Noise], EPresetMatch.Json);
    private static readonly FieldPresets Suites = new([$"{Ecdsa}:{Rsa}", Chacha], EPresetMatch.Names);

    private const string RealFirefox = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA";

    private const string SemiPython = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";

    // Laid out as PattNG writes them, with "\n" line breaks whatever line endings this file is checked out with.
    private static readonly string Tlshello0Len =
        """
        {
          "tcp": [
            {"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["0", "104", "1"], "delays": ["0"], "maxSplit": "0"}},
            {"type": "fragment", "settings": {"packets": "1-1", "lengths": ["114", "1"], "delays": ["1"], "maxSplit": "11"}}
          ]
        }
        """.ReplaceLineEndings("\n");

    private static readonly string Tlshello =
        """
        {
          "tcp": [
            {"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["6", "98", "1"], "delays": ["0"], "maxSplit": "0"}},
            {"type": "fragment", "settings": {"packets": "1-1", "lengths": ["114", "1"], "delays": ["1"], "maxSplit": "11"}}
          ]
        }
        """.ReplaceLineEndings("\n");

    private static readonly string UdpNoise =
        """
        {
          "udp": [
            {
              "type": "noise",
              "settings": {
                "reset": "28",
                "noise": [
                  {"rand": "1200-1230", "delay": "10"}, {"rand": "1200-1230", "delay": "10"}, {"rand": "1200-1230", "delay": "10"},
                  {"rand": "1200-1230", "delay": "10"}, {"rand": "1200-1230", "delay": "10"}, {"rand": "1200-1230", "delay": "10"},
                  {"rand": "1200-1230", "delay": "10"}, {"rand": "1200-1230", "delay": "10"}, {"rand": "1200-1230", "delay": "10"},
                  {"rand": "1200-1230", "delay": "10"}, {"rand": "1200-1230", "delay": "10"}, {"rand": "1200-1230", "delay": "10"},
                  {"rand": "1200-1230", "delay": "10"}, {"rand": "1200-1230", "delay": "10"}, {"rand": "1200-1230", "delay": "10"},
                  {"rand": "1200-1230", "delay": "10"}, {"rand": "1200-1230", "delay": "10"}, {"rand": "1200-1230", "delay": "10"},
                  {"rand": "1200-1230", "delay": "10"}, {"rand": "1200-1230", "delay": "10"}, {"rand": "1200-1230", "delay": "10"},
                  {"rand": "1200-1230", "delay": "10"}, {"rand": "1200-1230", "delay": "10"}, {"rand": "1200-1230", "delay": "10"}
                ]
              }
            }
          ]
        }
        """.ReplaceLineEndings("\n");

    private static readonly string Merge =
        """
        {
          "tcp": [
            {"type": "merge", "settings": {"times": 100, "delayMs": 30, "maxBytes": 16384}}
          ]
        }
        """.ReplaceLineEndings("\n");

    private static bool Asks(FieldPresets presets, string text)
    {
        return FieldPresets.AsksBeforeReplacing(text, presets.HeldOf(text));
    }

    [Test]
    public async Task AFinalMaskFieldHoldsOneOfTheListInWhateverSpacingOrKeyOrder()
    {
        await Masks.IndexOf(Fragment).Should().BeEqualTo(0);
        await Masks.IndexOf(Noise).Should().BeEqualTo(1);
        await Masks.IndexOf(Noise.Replace(" ", "")).Should().BeEqualTo(1);
        await Masks.IndexOf("{\n  \"tcp\": [\n    {\"settings\": {\"packets\": \"tlshello\"}, \"type\": \"fragment\"}\n  ]\n}").Should().BeEqualTo(0);
    }

    [Test]
    public async Task AFinalMaskFieldThatIsBlankEditedOrNotJsonHoldsNoneOfThem()
    {
        await Masks.IndexOf("").Should().BeEqualTo(-1);
        await Masks.IndexOf(" \n ").Should().BeEqualTo(-1);
        await Masks.IndexOf(Fragment.Replace("tlshello", "1-3")).Should().BeEqualTo(-1);
        await Masks.IndexOf("""{"tcp": [{"type": "fragment""").Should().BeEqualTo(-1);
        await Masks.IndexOf("[]").Should().BeEqualTo(-1);
        // The masks run in the order they are written, so the same two in the other order are another finalMask.
        var both = new FieldPresets(["""{"tcp": [{"type": "a"}, {"type": "b"}]}"""], EPresetMatch.Json);
        await both.IndexOf("""{"tcp": [{"type": "a"}, {"type": "b"}]}""").Should().BeEqualTo(0);
        await both.IndexOf("""{"tcp": [{"type": "b"}, {"type": "a"}]}""").Should().BeEqualTo(-1);
    }

    [Test]
    public async Task ACipherSuitesFieldHoldsOneOfTheListWhenItHasItsNamesInItsOrder()
    {
        await Suites.IndexOf($"{Ecdsa}:{Rsa}").Should().BeEqualTo(0);
        await Suites.IndexOf(Chacha).Should().BeEqualTo(1);
        // Xray splits the names on ':' and trims each, and skips an empty one.
        await Suites.IndexOf($" {Ecdsa} :\n{Rsa}\n").Should().BeEqualTo(0);
        await Suites.IndexOf($"{Ecdsa}::{Rsa}:").Should().BeEqualTo(0);
        await Suites.IndexOf($"{Chacha}\n").Should().BeEqualTo(1);
    }

    [Test]
    public async Task ACipherSuitesFieldWithOtherNamesOrInAnotherOrderHoldsNoneOfThem()
    {
        await Suites.IndexOf($"{Rsa}:{Ecdsa}").Should().BeEqualTo(-1);
        await Suites.IndexOf($"{Ecdsa}:{Rsa}:{Chacha}").Should().BeEqualTo(-1);
        await Suites.IndexOf(Ecdsa).Should().BeEqualTo(-1);
        await Suites.IndexOf($"{Ecdsa}X:{Rsa}").Should().BeEqualTo(-1);
        await Suites.IndexOf("").Should().BeEqualTo(-1);
        await Suites.IndexOf(" : \n").Should().BeEqualTo(-1);
    }

    [Test]
    public async Task ADialModeFieldHoldsOneOfTheListOnlyWithExactlyItsText()
    {
        var modes = new FieldPresets(["oob.0", "oob.1,2"], EPresetMatch.Exact);
        await modes.IndexOf("oob.0").Should().BeEqualTo(0);
        await modes.IndexOf("oob.1,2").Should().BeEqualTo(1);
        // Xray reads a dialMode as it is written, neither trimmed nor folded: anything else is one of the user's own.
        await modes.IndexOf(" oob.0").Should().BeEqualTo(FieldPresets.None);
        await modes.IndexOf("oob.0\n").Should().BeEqualTo(FieldPresets.None);
        await modes.IndexOf("OOB.0").Should().BeEqualTo(FieldPresets.None);
        await modes.IndexOf("oob.1, 2").Should().BeEqualTo(FieldPresets.None);
        await modes.HeldOf(" ").Should().BeEqualTo(FieldPresets.Default);
        await modes.HeldOf("oob.0 ").Should().BeEqualTo(FieldPresets.None);
    }

    [Test]
    public async Task APickAsksFirstOnlyWhenItWouldTakeThePlaceOfAValueOfTheUsersOwn()
    {
        await Asks(Masks, "").Should().BeFalse();
        await Asks(Masks, "  ").Should().BeFalse();
        await Asks(Masks, Noise).Should().BeFalse();
        await Asks(Masks, Noise.Replace(" ", "")).Should().BeFalse();
        await Asks(Masks, Noise.Replace("10-20", "30-40")).Should().BeTrue();
        await Asks(Masks, """{"tcp": [""").Should().BeTrue();
        await Asks(Suites, "").Should().BeFalse();
        await Asks(Suites, Chacha).Should().BeFalse();
        await Asks(Suites, $"{Ecdsa} : {Rsa}").Should().BeFalse();
        await Asks(Suites, $"{Rsa}:{Ecdsa}").Should().BeTrue();
        await Asks(Suites, " : ").Should().BeTrue();
    }

    [Test]
    public async Task APickAsksFirstWhileWhatTheFieldHoldsIsNotKnownYetUnlessItIsBlank()
    {
        // The fields match off the UI thread, so a pick can come before the text the field holds now is matched.
        await FieldPresets.AsksBeforeReplacing(Noise, null).Should().BeTrue();
        await FieldPresets.AsksBeforeReplacing($"{Rsa}:{Ecdsa}", null).Should().BeTrue();
        await FieldPresets.AsksBeforeReplacing("", null).Should().BeFalse();
        await FieldPresets.AsksBeforeReplacing(" \n ", null).Should().BeFalse();
    }

    [Test]
    public async Task TheDefaultPickBlanksTheFieldAndEveryOtherPickPutsItsValue()
    {
        // A blank field leaves the setting at its default: no finalMask, Xray's own cipher suites.
        await Masks.TextOf(FieldPresets.Default).Should().BeEqualTo("");
        await Suites.TextOf(FieldPresets.Default).Should().BeEqualTo("");
        await Masks.TextOf(0).Should().BeEqualTo(Fragment);
        await Suites.TextOf(1).Should().BeEqualTo(Chacha);
        await Masks.TextOf(2).Should().BeNull();
    }

    [Test]
    public async Task ABlankFieldHoldsTheDefaultPickAPresetItsIndexAndAnyOtherTextNone()
    {
        // The default is chosen until another pick is, so a new profile's field shows it. Neither it nor None can be an
        // index, and they differ, or a blank field and one of the user's own would show alike.
        await (FieldPresets.Default < 0 && FieldPresets.None < 0).Should().BeTrue();
        await (FieldPresets.None != FieldPresets.Default).Should().BeTrue();
        await Masks.HeldOf("").Should().BeEqualTo(FieldPresets.Default);
        await Masks.HeldOf(" \n ").Should().BeEqualTo(FieldPresets.Default);
        await Suites.HeldOf("").Should().BeEqualTo(FieldPresets.Default);
        await Masks.HeldOf(Noise.Replace(" ", "")).Should().BeEqualTo(1);
        await Suites.HeldOf($"{Ecdsa} : {Rsa}").Should().BeEqualTo(0);
        await Masks.HeldOf(Noise.Replace("10-20", "30-40")).Should().BeEqualTo(FieldPresets.None);
        await Suites.HeldOf(" : ").Should().BeEqualTo(FieldPresets.None);
        await Masks.HeldOf("""{"tcp": [""").Should().BeEqualTo(FieldPresets.None);
        // Nothing of the user's own is lost when the field holds the default or a preset.
        await FieldPresets.AsksBeforeReplacing("", Masks.HeldOf("")).Should().BeFalse();
        await FieldPresets.AsksBeforeReplacing(Noise, Masks.HeldOf(Noise)).Should().BeFalse();
        await FieldPresets.AsksBeforeReplacing($"{Rsa}:{Ecdsa}", Suites.HeldOf($"{Rsa}:{Ecdsa}")).Should().BeTrue();
    }

    [Test]
    public async Task TheFinalMaskFieldsOfferTheGivenFinalMasksEachLaidOutAsWrittenUnderItsName()
    {
        var names = Global.FinalMaskPresets.Select(preset => preset.Name).ToList();
        var values = Global.FinalMaskPresets.Select(preset => preset.Value).ToList();
        await names.SequenceEqual(["tlshello-0-len (0-104-1-0-0-114-1-1-11)", "tlshello (6-98-1-0-0-114-1-1-11)", "udp-noise (rnd-24-1200-1230)", "merge"]).Should().BeTrue();
        await values.SequenceEqual([Tlshello0Len, Tlshello, UdpNoise, Merge]).Should().BeTrue();
        // Each is one an exit-node takes, as an outbound does, and the list tells each apart from the others.
        var listed = new FieldPresets(values, EPresetMatch.Json);
        for (var index = 0; index < values.Count; index++)
        {
            await AetherExit.TakesFinalMask(values[index]).Should().BeTrue();
            await listed.IndexOf(values[index]).Should().BeEqualTo(index);
        }
        // The fields' own presets are these, under these names, matched as JSON.
        await FieldPresets.FinalMask.Names.SequenceEqual(names).Should().BeTrue();
        await FieldPresets.FinalMask.Values.SequenceEqual(values).Should().BeTrue();
        await FieldPresets.FinalMask.Match.Should().BeEqualTo(EPresetMatch.Json);
        await FieldPresets.FinalMask.Setting.Should().BeEqualTo("finalMask");
    }

    [Test]
    public async Task TheCipherSuitesFieldOffersTheGivenListsUnderTheirNames()
    {
        var names = Global.CipherSuitesPresets.Select(preset => preset.Name).ToList();
        var values = Global.CipherSuitesPresets.Select(preset => preset.Value).ToList();
        await names.SequenceEqual(["semi-python-cipherSuites", "real-firefox-cipherSuites"]).Should().BeTrue();
        await values.SequenceEqual([SemiPython, RealFirefox]).Should().BeTrue();
        var listed = new FieldPresets(values, EPresetMatch.Names);
        for (var index = 0; index < values.Count; index++)
        {
            await listed.IndexOf(values[index]).Should().BeEqualTo(index);
        }
        await FieldPresets.CipherSuites.Names.SequenceEqual(names).Should().BeTrue();
        await FieldPresets.CipherSuites.Values.SequenceEqual(values).Should().BeTrue();
        await FieldPresets.CipherSuites.Match.Should().BeEqualTo(EPresetMatch.Names);
        await FieldPresets.CipherSuites.Setting.Should().BeEqualTo("cipherSuites");
    }

    [Test]
    public async Task TheDialModeFieldsOfferTheGivenDialModesUnderTheirNames()
    {
        var names = Global.DialModePresets.Select(preset => preset.Name).ToList();
        var values = Global.DialModePresets.Select(preset => preset.Value).ToList();
        await names.SequenceEqual(["oob"]).Should().BeTrue();
        await values.SequenceEqual(["oob.0"]).Should().BeTrue();
        var listed = new FieldPresets(values, EPresetMatch.Exact);
        for (var index = 0; index < values.Count; index++)
        {
            await listed.IndexOf(values[index]).Should().BeEqualTo(index);
        }
        await FieldPresets.DialMode.Names.SequenceEqual(names).Should().BeTrue();
        await FieldPresets.DialMode.Values.SequenceEqual(values).Should().BeTrue();
        await FieldPresets.DialMode.Match.Should().BeEqualTo(EPresetMatch.Exact);
        await FieldPresets.DialMode.Setting.Should().BeEqualTo("dialMode");
    }

    // PattN: JsonNode.DeepEquals is what ignores the key order (a risk the port design names); pinned at every depth,
    // with a key written twice counting with its last value, as Gson and Xray read it, and comments skipped, as PattN
    // reads a finalMask.
    [Test]
    public async Task AFinalMaskMatchesWhateverTheKeyOrderAtEveryDepth()
    {
        var presets = new FieldPresets(["""{"a": {"b": 1, "c": [{"d": "x", "e": "y"}]}, "f": true}"""], EPresetMatch.Json);
        await presets.IndexOf("""{"f": true, "a": {"c": [{"e": "y", "d": "x"}], "b": 1}}""").Should().BeEqualTo(0);
        await presets.IndexOf("""{"f": true, "a": {"c": [{"e": "y", "d": "x"}], "b": 1.0}}""").Should().BeEqualTo(0);
        await presets.IndexOf("""{"f": true, "a": {"c": [{"e": "y", "d": "x"}], "b": "1"}}""").Should().BeEqualTo(-1);
        await presets.IndexOf("""{"f": false, "a": {"c": [{"e": "y", "d": "x"}], "b": 1}, "f": true}""").Should().BeEqualTo(0);
        await presets.IndexOf("""{"f": true, "a": {"c": [{"e": "y", "d": "x"}], "b": 1}, "f": false}""").Should().BeEqualTo(-1);
        await presets.IndexOf("{\"f\": true, /* the mask */ \"a\": {\"c\": [{\"e\": \"y\", \"d\": \"x\"}], \"b\": 1}}").Should().BeEqualTo(0);
        await presets.IndexOf("null").Should().BeEqualTo(-1);
    }

    // PattN: the name PattNG's PresetFields shows under the field and in the question before a pick replaces a value.
    [Test]
    public async Task TheNameUnderAFieldIsTheDefaultsForBlankTextThePresetsItHoldsOrNone()
    {
        var named = new FieldPresets("finalMask", [("fragment", Fragment), ("noise", Noise)], EPresetMatch.Json);
        await named.NameOf(FieldPresets.Default, "default").Should().BeEqualTo("default");
        await named.NameOf(1, "default").Should().BeEqualTo("noise");
        await named.NameOf(2, "default").Should().BeEqualTo("");
        // A blank field shows the default at once, before any match is in.
        await named.HeldNameOf(" ", null, "default").Should().BeEqualTo("default");
        await named.HeldNameOf(Noise, named.HeldOf(Noise), "default").Should().BeEqualTo("noise");
        await named.HeldNameOf(Noise, null, "default").Should().BeNull();
        await named.HeldNameOf("{}", named.HeldOf("{}"), "default").Should().BeNull();
    }

    // PattN: text the match cannot read is a value of the user's own, never an error, as PattNG catches whatever Gson
    // throws. A lone UTF-16 surrogate is such text: written as it is, which no UTF-8 holds, or escaped in plain ASCII
    // text, in a key or in a value, which a link's fm can carry and a save of a finalMask takes.
    [Test]
    public async Task TextWithALoneSurrogateHoldsNoneOfThem()
    {
        var texts = new[]
        {
            "\ud800",
            "{\"a\": \"\ud800\"}",
            "{\"\ud800\": 1}",
            "{\"\\ud800\": 1}",
            "{\"a\": \"\\ud800\"}",
            // The first preset with one of its values escaped so, which the match only reaches comparing the values.
            FieldPresets.FinalMask.Values[0].Replace("\"maxSplit\": \"11\"", "\"maxSplit\": \"\\ud800\""),
        };
        foreach (var text in texts)
        {
            await FieldPresets.FinalMask.IndexOf(text).Should().BeEqualTo(FieldPresets.None).Because(text);
            await FieldPresets.FinalMask.HeldOf(text).Should().BeEqualTo(FieldPresets.None).Because(text);
            await FieldPresets.AsksBeforeReplacing(text, FieldPresets.FinalMask.HeldOf(text)).Should().BeTrue().Because(text);
        }
        // Where the comparison reaches the value at once.
        var shaped = new FieldPresets(["""{"a": "b"}"""], EPresetMatch.Json);
        await shaped.IndexOf("{\"a\": \"\\ud800\"}").Should().BeEqualTo(FieldPresets.None);
        await shaped.IndexOf("{\"a\": \"\\u0062\"}").Should().BeEqualTo(0);
        await FieldPresets.CipherSuites.IndexOf("\ud800").Should().BeEqualTo(FieldPresets.None);
    }
}
