namespace ServiceLib.Common;

// PattN: fork-only file, the preset fields of PattNG's editors (finalMask, cipherSuites, dialMode).

/// <summary>How the text of a preset field is matched to its presets (PattNG FieldPresets.Match).</summary>
public enum EPresetMatch
{
    /// <summary>JSON, such as a finalMask: a field holds one in whatever spacing or key order it is written.</summary>
    Json,

    /// <summary>
    /// Names joined by ':', such as cipherSuites, which Xray splits on ':' and trims each of: a field holds one when it
    /// has the same names in the same order, whatever the white space around each, and an empty name counts for none,
    /// as Xray skips it.
    /// </summary>
    Names,

    /// <summary>
    /// Text the core reads as it is written, such as a dialMode, which Xray neither trims nor folds the case of: a
    /// field holds one only when it has exactly its text.
    /// </summary>
    Exact,
}

/// <summary>
/// PattN: the ready-made values a field offers to pick from (PattNG ui/server/FieldPresets.kt, and the names
/// PresetFields.kt shows), each given as the text a pick puts in the field, and how the field's text is matched to them.
/// A pick only fills the field in: what the field holds afterwards, edited or not, is what is saved. Matching parses
/// JSON, so the fields match off the UI thread.
/// </summary>
public sealed class FieldPresets
{
    /// <summary>What a field holds that is none of the presets: a value of the user's own.</summary>
    public const int None = -1;

    /// <summary>
    /// The pick, chosen until another is, that leaves the setting at its default: a blank field, which is no finalMask
    /// and no dialMode, and for cipherSuites Xray's own suites.
    /// </summary>
    public const int Default = -2;

    /// <summary>JSON is read as PattN reads a finalMask (JsonUtils.ParseJson): comments are skipped.</summary>
    private static readonly JsonDocumentOptions _jsonOptions = new()
    {
        CommentHandling = JsonCommentHandling.Skip
    };

    /// <summary>The finalMask fields of the server editors and of the exit-node on the Aether pages.</summary>
    public static FieldPresets FinalMask { get; } = new("finalMask", Global.FinalMaskPresets, EPresetMatch.Json);

    /// <summary>The cipherSuites field of a TLS profile.</summary>
    public static FieldPresets CipherSuites { get; } = new("cipherSuites", Global.CipherSuitesPresets, EPresetMatch.Names);

    /// <summary>The dialMode fields of the server editor and of the exit-node on the Aether pages.</summary>
    public static FieldPresets DialMode { get; } = new("dialMode", Global.DialModePresets, EPresetMatch.Exact);

    /// <summary>What each value is compared by, read on the first match, on the thread that matches.</summary>
    private readonly Lazy<object?[]> _keys;

    /// <summary>Presets known by their values alone, with no names and no setting.</summary>
    public FieldPresets(IReadOnlyList<string> values, EPresetMatch match)
        : this(string.Empty, values.Select(value => (string.Empty, value)).ToList(), match)
    {
    }

    /// <summary>
    /// The presets of <paramref name="setting" />, the name of what the field sets (on its arrow and in the question
    /// before a pick replaces a value of the user's own), each with the name the list shows it by.
    /// </summary>
    public FieldPresets(string setting, IReadOnlyList<(string Name, string Value)> presets, EPresetMatch match)
    {
        Setting = setting;
        Names = presets.Select(preset => preset.Name).ToList();
        Values = presets.Select(preset => preset.Value).ToList();
        Match = match;
        _keys = new Lazy<object?[]>(() => Values.Select(KeyOf).ToArray());
    }

    public string Setting { get; }

    public IReadOnlyList<string> Names { get; }

    public IReadOnlyList<string> Values { get; }

    public EPresetMatch Match { get; }

    /// <summary>The index of the value <paramref name="text" /> is, or <see cref="None" /> when it is none of them, blank, or for JSON not JSON at all.</summary>
    public int IndexOf(string? text)
    {
        var key = KeyOf(text ?? string.Empty);
        if (key == null)
        {
            return None;
        }
        var keys = _keys.Value;
        for (var index = 0; index < keys.Length; index++)
        {
            if (keys[index] is { } preset && SameKey(preset, key))
            {
                return index;
            }
        }
        return None;
    }

    /// <summary>The pick a field holding <paramref name="text" /> shows: <see cref="Default" /> when it is blank, else the index of its value, or <see cref="None" />.</summary>
    public int HeldOf(string? text)
    {
        return string.IsNullOrWhiteSpace(text) ? Default : IndexOf(text);
    }

    /// <summary>The text <paramref name="pick" /> puts in the field: the value at that index, or a blank one for <see cref="Default" />; null for no such pick.</summary>
    public string? TextOf(int pick)
    {
        if (pick == Default)
        {
            return string.Empty;
        }
        return pick >= 0 && pick < Values.Count ? Values[pick] : null;
    }

    /// <summary>The name of <paramref name="pick" />: <paramref name="defaultName" /> for <see cref="Default" />, the name of a preset, or empty for no such pick.</summary>
    public string NameOf(int pick, string defaultName)
    {
        if (pick == Default)
        {
            return defaultName;
        }
        return pick >= 0 && pick < Names.Count ? Names[pick] : string.Empty;
    }

    /// <summary>
    /// The name shown under a field holding <paramref name="text" />, whose last match gave <paramref name="held" /> (null
    /// before the first match is in): the default pick's for a blank field at once, with nothing to parse, else the name
    /// of the preset it holds; null for a value of the user's own.
    /// </summary>
    public string? HeldNameOf(string? text, int? held, string defaultName)
    {
        var pick = string.IsNullOrWhiteSpace(text) ? Default : held;
        return pick is null or None ? null : NameOf(pick.Value, defaultName);
    }

    /// <summary>
    /// Whether a pick asks before it takes the place of <paramref name="text" />, which holds <paramref name="held" />,
    /// as <see cref="HeldOf" /> gives it, or null while that is not known yet: only when the field holds a value of the
    /// user's own, or may hold one, which is anything but blank or one of the list, since that would be lost.
    /// </summary>
    public static bool AsksBeforeReplacing(string? text, int? held)
    {
        return !string.IsNullOrWhiteSpace(text) && (held is null or None);
    }

    /// <summary>What <paramref name="text" /> is compared by; null when it is not JSON where JSON is matched.</summary>
    private object? KeyOf(string text)
    {
        return Match switch
        {
            EPresetMatch.Json => JsonKeyOf(text),
            EPresetMatch.Exact => text,
            _ => text.Split(':').Select(name => name.Trim()).Where(name => name.Length > 0).ToList(),
        };
    }

    private static bool SameKey(object preset, object text)
    {
        return (preset, text) switch
        {
            (JsonKey a, JsonKey b) => JsonNode.DeepEquals(a.Node, b.Node),
            (List<string> a, List<string> b) => a.SequenceEqual(b, StringComparer.Ordinal),
            (string a, string b) => string.Equals(a, b, StringComparison.Ordinal),
            _ => false,
        };
    }

    /// <summary>
    /// <paramref name="text" /> read as JSON, or null when it is not JSON. What is being typed is often not JSON yet, so
    /// nothing is logged for it. Text that holds a lone UTF-16 surrogate is not read either, as it is or escaped: it is
    /// a value of the user's own, as PattNG's match takes whatever Gson cannot read, never an error.
    /// </summary>
    private static JsonKey? JsonKeyOf(string text)
    {
        try
        {
            using var document = JsonDocument.Parse(text, _jsonOptions);
            return new JsonKey(NodeOf(document.RootElement));
        }
        // PattN: JsonDocument throws ArgumentException for a lone surrogate written as it is (no UTF-8 holds it), and
        // reading an escaped one out of a name or a string throws InvalidOperationException.
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>
    /// <paramref name="element" /> as a node JsonNode.DeepEquals compares whatever the order of an object's keys. A key
    /// written twice keeps its last value, as PattNG's Gson and Xray read it; a JsonNode parsed from such text throws on
    /// the comparison instead. Names and strings are read out here, so that an escape that cannot be read throws inside
    /// <see cref="JsonKeyOf" /> and never in the comparison.
    /// </summary>
    private static JsonNode? NodeOf(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                var node = new JsonObject();
                foreach (var property in element.EnumerateObject())
                {
                    node[property.Name] = NodeOf(property.Value);
                }
                return node;

            case JsonValueKind.Array:
                var array = new JsonArray();
                foreach (var item in element.EnumerateArray())
                {
                    array.Add(NodeOf(item));
                }
                return array;

            case JsonValueKind.Null:
                return null;

            case JsonValueKind.String:
                return JsonValue.Create(element.GetString());

            default:
                return JsonValue.Create(element.Clone());
        }
    }

    /// <summary>A JSON text read: its node, null for the JSON null, which still differs from text that is not JSON.</summary>
    private sealed record JsonKey(JsonNode? Node);
}
