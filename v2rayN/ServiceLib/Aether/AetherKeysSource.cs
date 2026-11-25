namespace ServiceLib.Aether;

/// <summary>
/// PattN: what the WARP keys window reads and runs beyond its own fields (PattNG ui/server/AetherKeysRepository.kt,
/// AetherKeysSource): its settings, the keys in use, a run that gets new ones, the live session, the core folder and the
/// exit-nodes. <see cref="AetherKeysSource" /> is PattN's own; the tests give one of theirs, which reaches no network,
/// runs no core and writes no settings file.
/// </summary>
public interface IAetherKeysSource
{
    /// <summary>The protocol of the live session, scanning or connected; null without one. Its keys must not change under it.</summary>
    AetherProtocol? SessionProtocol { get; }

    /// <summary>Raised, on any thread, when a session starts or ends (see <see cref="AetherCoreManager.SessionChanged" />).</summary>
    event Action? SessionChanged;

    /// <summary>Whether the core folder holds the Aether core; read off the UI thread.</summary>
    Task<bool> IsCoreAvailableAsync();

    /// <summary>The settings of the window as they were left, or the defaults the first time.</summary>
    AetherKeysSettings LoadSettings();

    Task SaveSettingsAsync(AetherKeysSettings settings);

    /// <summary>Every key in use, each key file with the identity it holds, in the order of <see cref="AetherPaths.KeyFiles" />.</summary>
    Task<List<AetherKey>> KeysAsync();

    /// <summary>
    /// Registers new keys of <paramref name="kind" /> with the core on <paramref name="arguments" />, dialling out through
    /// <paramref name="exit" />; the new keys, or null when the old ones stay. See
    /// <see cref="AetherIdentityManager.RenewAsync(AetherKeyKind, IReadOnlyList{string}, AetherExit, Action{string}?, CancellationToken)" />.
    /// </summary>
    Task<List<AetherKey>?> RenewAsync(AetherKeyKind kind, IReadOnlyList<string> arguments, AetherExit exit, Action<string> onOutput, CancellationToken ct);

    /// <summary>The names of the profiles a run can dial out through in place of freedom, see <see cref="AetherExit.NodesOf" />.</summary>
    Task<List<AetherExitNode>> ExitNodesAsync();

    /// <summary>What the profile named <paramref name="name" /> gives as the exit-node now, as a key run looks it up.</summary>
    Task<ExitNodeLookup> FindExitNodeAsync(string name);
}

/// <summary>
/// The WARP keys window's source in PattN (PattNG AetherKeysRepository): its settings, kept in
/// <see cref="Config.AetherItem" /> apart from every profile, and the keys, which every Aether profile shares. Whether the
/// core is there, whether a session runs and the exit-nodes are told as the Aether editor tells them.
/// <paramref name="save" /> writes the settings file, ConfigTextHandler.SaveConfig unless a test gives one that writes none.
/// </summary>
public sealed class AetherKeysSource(Config config, Func<Config, Task<int>>? save = null) : IAetherKeysSource
{
    private readonly AetherEditorSource _editor = new(config);
    private readonly Func<Config, Task<int>> _save = save ?? (_ => ConfigTextHandler.SaveConfig());

    public AetherProtocol? SessionProtocol => _editor.SessionProtocol;

    public event Action? SessionChanged
    {
        add => _editor.SessionChanged += value;
        remove => _editor.SessionChanged -= value;
    }

    public async Task<bool> IsCoreAvailableAsync()
    {
        return (await _editor.AvailabilityAsync()).Core;
    }

    public AetherKeysSettings LoadSettings()
    {
        return SettingsOf(config.AetherItem);
    }

    public async Task SaveSettingsAsync(AetherKeysSettings settings)
    {
        Store(config.AetherItem ??= new(), settings);
        if (await _save(config) != 0)
        {
            Logging.SaveLog("AetherKeys: the settings of the WARP keys window were not saved; the next opening shows the earlier ones");
        }
    }

    public Task<List<AetherKey>> KeysAsync()
    {
        return AetherIdentityManager.KeysAsync();
    }

    public Task<List<AetherKey>?> RenewAsync(AetherKeyKind kind, IReadOnlyList<string> arguments, AetherExit exit, Action<string> onOutput, CancellationToken ct)
    {
        return AetherIdentityManager.RenewAsync(kind, arguments, exit, onOutput, ct);
    }

    public Task<List<AetherExitNode>> ExitNodesAsync()
    {
        return _editor.ExitNodesAsync();
    }

    public Task<ExitNodeLookup> FindExitNodeAsync(string name)
    {
        return _editor.FindExitNodeAsync(name);
    }

    /// <summary>
    /// The settings <paramref name="item" /> holds (PattNG loadSettings): each one as stored, or its default where none
    /// is; a kind or a fingerprint no build wrote reads as the default one.
    /// </summary>
    public static AetherKeysSettings SettingsOf(AetherItem? item)
    {
        var defaults = new AetherKeysSettings();
        if (item == null)
        {
            return defaults;
        }
        return new AetherKeysSettings
        {
            Kind = AetherKeyKind.FromString(item.KeysKind),
            EnrollAddress = item.KeysApiAddress ?? defaults.EnrollAddress,
            ApiSni = item.KeysApiSni ?? defaults.ApiSni,
            ApiHost = item.KeysApiHost ?? defaults.ApiHost,
            Fragment = item.KeysFragment,
            FragmentSize = item.KeysFragmentSize ?? defaults.FragmentSize,
            FragmentDelay = item.KeysFragmentDelay ?? defaults.FragmentDelay,
            Ech = item.KeysEch,
            EchDns = item.KeysEchDns ?? defaults.EchDns,
            EchDomain = item.KeysEchDomain ?? defaults.EchDomain,
            Fingerprint = AetherFingerprint.FromString(item.KeysFingerprint),
            ExitNode = item.KeysExitNode ?? defaults.ExitNode,
            FinalMask = item.KeysFinalMask ?? defaults.FinalMask,
            DialMode = item.KeysDialMode ?? defaults.DialMode,
            Command = item.KeysCommand ?? defaults.Command,
        };
    }

    /// <summary>
    /// Puts <paramref name="settings" /> in <paramref name="item" /> (PattNG saveSettings): text as written, but the ECH DNS
    /// and domain trimmed and not at all while blank or the default, so that they read as the default, whatever that
    /// comes to be, as a profile's ECH resolver and domain do.
    /// </summary>
    public static void Store(AetherItem item, AetherKeysSettings settings)
    {
        item.KeysKind = settings.Kind.Type;
        item.KeysApiAddress = settings.EnrollAddress;
        item.KeysApiSni = settings.ApiSni;
        item.KeysApiHost = settings.ApiHost;
        item.KeysFragment = settings.Fragment;
        item.KeysFragmentSize = settings.FragmentSize;
        item.KeysFragmentDelay = settings.FragmentDelay;
        item.KeysEch = settings.Ech;
        item.KeysEchDns = UnlessDefault(settings.EchDns, AetherArguments.DefaultEchDns);
        item.KeysEchDomain = UnlessDefault(settings.EchDomain, AetherArguments.DefaultEchDomain);
        item.KeysFingerprint = settings.Fingerprint.Type;
        item.KeysExitNode = settings.ExitNode;
        item.KeysFinalMask = settings.FinalMask;
        item.KeysDialMode = settings.DialMode;
        item.KeysCommand = settings.Command;
    }

    /// <summary><paramref name="value" /> trimmed as it is stored, or null, which stores nothing, when it is blank or <paramref name="defaultValue" />.</summary>
    private static string? UnlessDefault(string value, string defaultValue)
    {
        var trimmed = AetherKeys.Trim(value);
        return trimmed.Length == 0 || trimmed == defaultValue ? null : trimmed;
    }
}
