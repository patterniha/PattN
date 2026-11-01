using System.Globalization;

namespace ServiceLib.ViewModels;

// PattN: fork-only file, the Aether editor (design 3.2; PattNG ui/server/ServerAetherViewModel.kt, ServerUiState.kt and
// ServerAetherActivity.kt).

/// <summary>What the missing-keys question ends with (PattNG AetherKeysMissingDialog).</summary>
public enum EAetherKeysChoice
{
    /// <summary>Neither: the dialog was closed or cancelled.</summary>
    Cancel,

    /// <summary>Save anyway, or scan anyway: the core registers what it lacks on its own.</summary>
    Anyway,

    /// <summary>Get new WARP keys first, on the WARP keys window.</summary>
    GetKeys,
}

/// <summary>
/// The missing-keys question (PattNG AetherKeysMissingDialog): whether it is a scan's, so that going on scans rather than
/// saves, and whether "Get new WARP keys…" is offered. The WARP keys window opens only once a scan has ended (a scan holds
/// the exit a run of that window dials out through), so a save asked while a scan runs offers to go on or to cancel alone.
/// </summary>
public sealed record AetherKeysQuestion(bool Scan, bool CanGetKeys);

/// <summary>One of the CDN edge lists the Psiphon fronting scan can be told to try, with whether it is chosen.</summary>
public partial class AetherCdnSetOption : ReactiveObject
{
    public AetherCdnSetOption(AetherPsiphonCdnSet set, string label, bool isChecked)
    {
        Set = set;
        Label = label;
        IsChecked = isChecked;
    }

    public AetherPsiphonCdnSet Set { get; }

    public string Label { get; }

    [Reactive]
    public partial bool IsChecked { get; set; }
}

/// <summary>
/// PattN: the editor of an Aether profile (design 3.2). It edits a copy of the profile, field by field, in PattNG's
/// order; the lists are bound by index and always hold one of their own values, whatever was stored. What Save stores is
/// <see cref="ToProfileItem" /> normalized (3.2.3, 3.2.4); a scan, the Psiphon data and the key status go through
/// <see cref="IAetherEditorSource" /> (3.2.5).
/// </summary>
public partial class AddServerAetherViewModel : MyReactiveObject, ICloseable
{
    /// <summary>How long a WARP device id is shown in the key status lines (PattNG DEVICE_ID_LENGTH).</summary>
    private const int DeviceIdLength = 8;

    private readonly IAetherEditorSource _source;

    /// <summary>The profile as it was opened; never written before a save goes through.</summary>
    private readonly ProfileItem _initial;

    /// <summary>The profile the caller handed in: a new one gets the id of the profile stored, as AddServerViewModel's does.</summary>
    private readonly ProfileItem _item;

    private readonly SynchronizationContext? _ui = SynchronizationContext.Current;
    private List<string> _regionCodes = [];
    private List<string> _regions = [];
    private AetherIdentityStatus? _reportedIdentity;
    private CancellationTokenSource? _scanCancellation;
    private bool _refreshing;
    private bool _saved;
    private bool _closed;

    public event EventHandler? RequestClose;

    public AddServerAetherViewModel(ProfileItem profileItem) : this(profileItem, null)
    {
    }

    public AddServerAetherViewModel(ProfileItem profileItem, IAetherEditorSource? source)
    {
        _config = AppManager.Instance.Config;
        _source = source ?? new AetherEditorSource(_config);
        _item = profileItem;
        _initial = JsonUtils.DeepCopy(profileItem) ?? new ProfileItem();
        _initial.ConfigType = EConfigType.Aether;
        ListenPort = _source.ListenPort;

        var extra = _initial.GetProtocolExtra();
        Remarks = _initial.Remarks ?? string.Empty;
        Address = _initial.Address ?? string.Empty;
        Port = _initial.Port > 0 ? _initial.Port.ToString(CultureInfo.InvariantCulture) : string.Empty;
        // Normalized, so that the lists always hold one of their own values, whatever was stored.
        ProtocolIndex = IndexIn(AetherProtocol.All, AetherProtocol.FromString(extra.AetherProtocol));
        TransportIndex = IndexIn(AetherTransport.All, AetherTransport.FromString(extra.AetherTransport));
        // Shown filled in, as the ECH settings are, so that what the core is told is in sight.
        MasqueSni = KotlinText.NullIfBlank(extra.AetherMasqueSni) ?? AetherArguments.DefaultMasqueSni;
        ScanModeIndex = IndexIn(AetherScanMode.All, AetherScanMode.FromString(extra.AetherScanMode));
        ObfuscationIndex = IndexIn(AetherObfuscation.All, AetherObfuscation.FromString(extra.AetherObfuscation));
        FingerprintIndex = IndexIn(AetherFingerprint.All, AetherFingerprint.FromString(extra.AetherFingerprint));
        IpVersionIndex = IndexIn(AetherIpVersion.All, AetherIpVersion.FromString(extra.AetherIpVersion));
        WiwOuter = extra.AetherWiwOuter ?? string.Empty;
        WiwInner = extra.AetherWiwInner ?? string.Empty;
        Fragment = extra.AetherFragment ?? false;
        FragmentSize = extra.AetherFragmentSize ?? string.Empty;
        FragmentDelay = extra.AetherFragmentDelay ?? string.Empty;
        Ech = extra.AetherEch == true;
        EchDns = KotlinText.NullIfBlank(extra.AetherEchDns) ?? AetherArguments.DefaultEchDns;
        EchDomain = KotlinText.NullIfBlank(extra.AetherEchDomain) ?? AetherArguments.DefaultEchDomain;
        Dns = extra.AetherDns ?? string.Empty;
        ExitLoc = extra.AetherExitLoc ?? string.Empty;
        PsiphonIndex = IndexIn(AetherPsiphon.All, AetherPsiphon.FromString(extra.AetherPsiphon));
        PsiphonModeIndex = IndexIn(AetherPsiphonMode.All, AetherPsiphonMode.FromString(extra.AetherPsiphonMode));
        PsiphonCdnIps = extra.AetherPsiphonCdnIps ?? string.Empty;
        PsiphonCdnSni = extra.AetherPsiphonCdnSni ?? string.Empty;
        PsiphonCdnSets = extra.AetherPsiphonCdnSets ?? string.Empty;
        PsiphonRegion = extra.AetherPsiphonRegion ?? string.Empty;
        PsiphonBundledList = extra.AetherPsiphonBundledList != false;
        TorIndex = IndexIn(AetherTor.All, AetherTor.FromString(extra.AetherTor));
        TorBridgesIndex = IndexIn(AetherTorBridges.All, AetherTorBridges.FromString(extra.AetherTorBridges));
        TorBridgeLines = extra.AetherTorBridgeLines ?? string.Empty;
        TorRelaysIndex = IndexIn(AetherTorRelays.All, AetherTorRelays.FromString(extra.AetherTorRelays));
        // The targetStrategy chosen; blank while the profile follows its default, which the list shows.
        TargetStrategy = _initial.TargetStrategy ?? string.Empty;
        Command = extra.AetherCommand ?? string.Empty;

        ExitNode = new ExitNodeFieldViewModel(extra.AetherExitNode);
        FinalMask = new PresetFieldViewModel(FieldPresets.FinalMask, _initial.Finalmask);
        DialMode = new PresetFieldViewModel(FieldPresets.DialMode, _initial.DialMode);
        Log = new AetherLogViewModel(ResUI.TbAetherLogEmpty);
        var chosenSets = AetherPsiphonCdnSet.Parse(PsiphonCdnSets).ToHashSet();
        var setLabels = AetherLabels.PsiphonCdnSets;
        PsiphonCdnSetOptions = new ObservableCollection<AetherCdnSetOption>(AetherPsiphonCdnSet.All.Select((set, index) =>
            new AetherCdnSetOption(set, setLabels[index], chosenSets.Contains(set))));
        foreach (var option in PsiphonCdnSetOptions)
        {
            option.PropertyChanged += (_, e) =>
            {
                if (e.PropertyName == nameof(AetherCdnSetOption.IsChecked))
                {
                    SetPsiphonCdnSet(option.Set, option.IsChecked);
                }
            };
        }
        // Folded away unless one of its settings holds a value, so a profile that set one shows it at once.
        PsiphonCdnSetsExpanded = chosenSets.Count > 0;
        RebuildRegions();
        // Until the core folder is read, as PattNG: the note that the core is missing shows only once it is known to be,
        // and Scan is not held back meanwhile.
        CoreAvailable = true;
        // A session that runs as the editor opens; one that starts or ends later is followed through SessionChanged.
        SessionProtocol = _source.SessionProtocol;
        Refresh();
        OtherSettingsExpanded = HasOtherSettings;

        PropertyChanged += (_, e) => OnFieldChanged(e.PropertyName);
        ExitNode.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ExitNodeFieldViewModel.Name))
            {
                Refresh();
            }
        };
        _source.SessionChanged += OnSessionChanged;

        SaveCmd = ReactiveCommand.CreateFromTask(SaveAsync);
        ScanCmd = ReactiveCommand.CreateFromTask(() => ScanAsync(), this.WhenAnyValue(x => x.CanScan));
        CancelScanCmd = ReactiveCommand.Create(CancelScan, this.WhenAnyValue(x => x.IsScanning));
        ClearPsiphonCmd = ReactiveCommand.CreateFromTask(ClearPsiphonDataAsync, this.WhenAnyValue(x => x.CanClearPsiphon));
        OpenKeysCmd = ReactiveCommand.CreateFromTask(OpenKeysAsync, this.WhenAnyValue(x => x.NotScanning));
        UseSettingsCmd = ReactiveCommand.Create(() => { Command = string.Empty; });

        Initialized = InitAsync();
    }

    #region fields, in PattNG's order

    [Reactive] public partial string Remarks { get; set; }
    [Reactive] public partial int ProtocolIndex { get; set; }
    [Reactive] public partial int TransportIndex { get; set; }
    [Reactive] public partial string MasqueSni { get; set; }
    [Reactive] public partial bool Fragment { get; set; }
    [Reactive] public partial string FragmentSize { get; set; }
    [Reactive] public partial string FragmentDelay { get; set; }
    [Reactive] public partial bool Ech { get; set; }
    [Reactive] public partial string EchDns { get; set; }
    [Reactive] public partial string EchDomain { get; set; }
    [Reactive] public partial int ScanModeIndex { get; set; }
    [Reactive] public partial int ObfuscationIndex { get; set; }
    [Reactive] public partial int FingerprintIndex { get; set; }

    /// <summary>The exit-node, a name (design 3.2.2 row 15).</summary>
    public ExitNodeFieldViewModel ExitNode { get; }

    /// <summary>The finalMask of the freedom exit-node, a preset field (design 3.3).</summary>
    public PresetFieldViewModel FinalMask { get; }

    /// <summary>The dialMode of the freedom exit-node, a preset field (design 3.3).</summary>
    public PresetFieldViewModel DialMode { get; }

    [Reactive] public partial int PsiphonIndex { get; set; }
    [Reactive] public partial int PsiphonModeIndex { get; set; }
    [Reactive] public partial string PsiphonCdnIps { get; set; }
    [Reactive] public partial string PsiphonCdnSni { get; set; }

    /// <summary>The CDN edge lists chosen, comma separated in the order the core tries them; none chosen means all.</summary>
    [Reactive] public partial string PsiphonCdnSets { get; set; }

    public ObservableCollection<AetherCdnSetOption> PsiphonCdnSetOptions { get; }
    [Reactive] public partial bool PsiphonCdnSetsExpanded { get; set; }

    /// <summary>What the CDN edge lists header says: all of them, or the chosen ones in the order the core tries them.</summary>
    [Reactive] public partial string PsiphonCdnSetsSummary { get; set; }

    /// <summary>The exit country chosen, an ISO code; blank for any.</summary>
    [Reactive] public partial string PsiphonRegion { get; set; }

    [Reactive] public partial IReadOnlyList<string> PsiphonRegionLabels { get; set; }
    [Reactive] public partial bool PsiphonBundledList { get; set; }
    [Reactive] public partial int TorIndex { get; set; }
    [Reactive] public partial int TorBridgesIndex { get; set; }
    [Reactive] public partial int TorRelaysIndex { get; set; }
    [Reactive] public partial string TorBridgeLines { get; set; }
    [Reactive] public partial string WiwOuter { get; set; }
    [Reactive] public partial string WiwInner { get; set; }
    [Reactive] public partial string Address { get; set; }

    /// <summary>The port of the pinned endpoint, as typed; blank for none.</summary>
    [Reactive] public partial string Port { get; set; }

    [Reactive] public partial int IpVersionIndex { get; set; }
    [Reactive] public partial bool OtherSettingsExpanded { get; set; }
    [Reactive] public partial string Dns { get; set; }
    [Reactive] public partial string ExitLoc { get; set; }

    /// <summary>The targetStrategy chosen; blank while the profile follows its default, see <see cref="DefaultTargetStrategy" />.</summary>
    [Reactive] public partial string TargetStrategy { get; set; }

    /// <summary>The command written by hand; blank while the profile follows its settings.</summary>
    [Reactive] public partial string Command { get; set; }

    #endregion fields, in PattNG's order

    #region lists

    public IReadOnlyList<string> ProtocolLabels { get; } = AetherLabels.Protocols;
    public IReadOnlyList<string> TransportLabels { get; } = AetherLabels.Transports;
    public IReadOnlyList<string> ScanModeLabels { get; } = AetherLabels.ScanModes;
    public IReadOnlyList<string> ObfuscationLabels { get; } = AetherLabels.Obfuscations;
    public IReadOnlyList<string> FingerprintLabels { get; } = AetherLabels.Fingerprints;
    public IReadOnlyList<string> IpVersionLabels { get; } = AetherLabels.IpVersions;
    public IReadOnlyList<string> PsiphonLabels { get; } = AetherLabels.Psiphons;
    public IReadOnlyList<string> PsiphonModeLabels { get; } = AetherLabels.PsiphonModes;
    public IReadOnlyList<string> TorLabels { get; } = AetherLabels.Tors;
    public IReadOnlyList<string> TorBridgesLabels { get; } = AetherLabels.TorBridges;
    public IReadOnlyList<string> TorRelaysLabels { get; } = AetherLabels.TorRelays;
    public IReadOnlyList<string> TargetStrategyLabels { get; } = Global.TargetStrategies;
    public IReadOnlyList<string> EchDnsOptions { get; } = Global.AetherEchDnsOptions;
    public IReadOnlyList<string> EchDomainOptions { get; } = Global.AetherEchDomainOptions;

    #endregion lists

    #region derived

    public AetherProtocol Protocol => Pick(AetherProtocol.All, ProtocolIndex, AetherProtocol.WireGuard);
    public AetherTransport Transport => Pick(AetherTransport.All, TransportIndex, AetherTransport.Http3);
    public AetherPsiphon Psiphon => Pick(AetherPsiphon.All, PsiphonIndex, AetherPsiphon.Off);
    public AetherPsiphonMode PsiphonMode => Pick(AetherPsiphonMode.All, PsiphonModeIndex, AetherPsiphonMode.Auto);
    public AetherTor Tor => Pick(AetherTor.All, TorIndex, AetherTor.Off);
    public AetherTorBridges TorBridges => Pick(AetherTorBridges.All, TorBridgesIndex, AetherTorBridges.Auto);

    /// <summary>The Aether listen port of the settings, which the command is built on and a save checked against.</summary>
    public int ListenPort { get; }

    /// <summary>With Psiphon or Tor alone there is no WARP tunnel, and nothing about one to set.</summary>
    [Reactive] public partial bool WarpUsed { get; set; }

    [Reactive] public partial bool ShowTransport { get; set; }
    [Reactive] public partial bool ShowFragment { get; set; }
    [Reactive] public partial bool ShowFragmentSizes { get; set; }
    [Reactive] public partial bool ShowEch { get; set; }
    [Reactive] public partial bool ShowEchFields { get; set; }

    /// <summary>Obfuscation shapes the UDP of WireGuard and HTTP/3 alone; MASQUE over HTTP/2, chosen or forced by a carrier around the tunnel, takes none.</summary>
    [Reactive] public partial bool ShowObfuscation { get; set; }

    [Reactive] public partial bool PsiphonOn { get; set; }
    [Reactive] public partial bool ShowPsiphonUnavailable { get; set; }
    [Reactive] public partial bool PsiphonCdnShown { get; set; }
    [Reactive] public partial bool PsiphonCdnSniShown { get; set; }
    [Reactive] public partial bool TorOn { get; set; }
    [Reactive] public partial bool ShowTorTransportsUnavailable { get; set; }
    [Reactive] public partial bool TorRelaysShown { get; set; }
    [Reactive] public partial bool TorBridgeLinesShown { get; set; }
    [Reactive] public partial bool ShowHops { get; set; }
    [Reactive] public partial bool ShowEndpoint { get; set; }

    /// <summary>No scan looks for the WireGuard endpoint inside the MASQUE tunnel; blank, it is the one WARP assigns.</summary>
    [Reactive] public partial string InnerHopHint { get; set; }

    [Reactive] public partial bool IsScanning { get; set; }
    [Reactive] public partial bool NotScanning { get; set; }
    [Reactive] public partial string ScanText { get; set; }

    /// <summary>A scan opens a second tunnel on this protocol's key; a live session on that key must not be disturbed.</summary>
    [Reactive] public partial bool ScanBlocked { get; set; }

    [Reactive] public partial bool ShowScanBlocked { get; set; }
    [Reactive] public partial bool CanScan { get; set; }
    [Reactive] public partial bool CoreAvailable { get; set; }
    [Reactive] public partial bool PsiphonAvailable { get; set; }
    [Reactive] public partial bool TorTransportsAvailable { get; set; }

    /// <summary>What Psiphon has learned is shared by every Aether profile, so a live session on any of them keeps it.</summary>
    [Reactive] public partial bool CanClearPsiphon { get; set; }

    /// <summary>The protocol of the live session; null without one.</summary>
    [Reactive] public partial AetherProtocol? SessionProtocol { get; set; }

    /// <summary>The command the settings build, which the command box shows while none is written by hand.</summary>
    [Reactive] public partial string BuiltCommand { get; set; }

    [Reactive] public partial bool CommandIsCustom { get; set; }

    /// <summary>The targetStrategy the profile follows while it stores none: where Tor and Psiphon stand, or the command says.</summary>
    [Reactive] public partial string DefaultTargetStrategy { get; set; }

    /// <summary>
    /// Whether a setting the editor keeps folded away holds a value of its own, so that the fold opens by itself and
    /// nothing set stays out of sight (PattNG hasOtherAetherSettings).
    /// </summary>
    [Reactive] public partial bool HasOtherSettings { get; set; }

    /// <summary>The command box: the command written by hand, or the one the settings build while there is none.</summary>
    public string CommandText
    {
        get => KotlinText.IsBlank(Command) ? BuiltCommand : Command;
        set
        {
            // The box hands back what it was given: that is no edit.
            if ((value ?? string.Empty) == CommandText)
            {
                return;
            }
            // Cleared while it shows the command the settings build: the profile follows them already, and the box shows
            // that command again (PattNG aetherCommand.ifBlank { builtCommand }), once the view's own update is over.
            if (KotlinText.IsBlank(value ?? string.Empty) && KotlinText.IsBlank(Command))
            {
                if (_ui == null)
                {
                    this.RaisePropertyChanged(nameof(CommandText));
                }
                else
                {
                    _ui.Post(_ => this.RaisePropertyChanged(nameof(CommandText)), null);
                }
                return;
            }
            Command = value ?? string.Empty;
        }
    }

    /// <summary>The targetStrategy the list shows: the one chosen, or the default while none is.</summary>
    public int TargetStrategyIndex
    {
        get
        {
            var shown = KotlinText.IsBlank(TargetStrategy) ? DefaultTargetStrategy : TargetStrategy.Trim();
            return Global.TargetStrategies.FindIndex(it => it.Equals(shown, StringComparison.OrdinalIgnoreCase));
        }
        set
        {
            if (value < 0 || value >= Global.TargetStrategies.Count || value == TargetStrategyIndex)
            {
                return;
            }
            TargetStrategy = Global.TargetStrategies[value];
        }
    }

    /// <summary>The exit country the list shows: any first, then the countries on offer, named in the language of the app.</summary>
    public int PsiphonRegionIndex
    {
        get
        {
            var current = CurrentRegion();
            return current.Length == 0 ? 0 : _regionCodes.IndexOf(current) + 1;
        }
        set
        {
            if (value < 0 || value > _regionCodes.Count || value == PsiphonRegionIndex)
            {
                return;
            }
            PsiphonRegion = value == 0 ? string.Empty : _regionCodes[value - 1];
        }
    }

    #endregion derived

    /// <summary>The newest lines of what the editor did and the core said, and the key status.</summary>
    public AetherLogViewModel Log { get; }

    /// <summary>The look at the core folder, the lists and the keys as the editor opens; the tests wait for it.</summary>
    public Task Initialized { get; }

    /// <summary>
    /// Asked when a key the profile, or its scan (<see cref="AetherKeysQuestion.Scan" />), needs is missing (design 3.2.4
    /// step 6): get it first, where <see cref="AetherKeysQuestion.CanGetKeys" />, go on anyway, or neither. Unanswered,
    /// nothing goes on.
    /// </summary>
    public Interaction<AetherKeysQuestion, EAetherKeysChoice> KeysMissingInteraction { get; } = new();

    /// <summary>
    /// Opens the WARP keys window, modal, and comes back once it is closed (design 3.4): from "Get new WARP keys…" and
    /// from the missing-keys question. Both editor windows handle it with a new <see cref="AetherKeysViewModel" />, so
    /// that nothing is preselected there.
    /// </summary>
    public Interaction<RxVoid, RxVoid> OpenKeysInteraction { get; } = new();

    public ReactiveCommand<RxVoid, RxVoid> SaveCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> ScanCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> CancelScanCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> ClearPsiphonCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> OpenKeysCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> UseSettingsCmd { get; }

    #region the profile

    /// <summary>
    /// The profile the editor holds, built on the profile it opened (PattNG ServerUiState.toProfileItem). Psiphon's and
    /// Tor's settings are kept only while they are on, the defaults of the ECH resolver and domain and the MASQUE SNI as
    /// blanks; a command counts as one of its own only when it says something else than the settings on
    /// <see cref="ListenPort" />, unless <paramref name="keepCommand" /> keeps it as typed, trimmed; the targetStrategy is
    /// stored only when it is not the profile's default.
    /// </summary>
    public ProfileItem ToProfileItem(bool keepCommand = false)
    {
        var profile = JsonUtils.DeepCopy(_initial) ?? new ProfileItem();
        var psiphon = Psiphon;
        var tor = Tor;
        var psiphonOn = psiphon != AetherPsiphon.Off;
        var torOn = tor != AetherTor.Off;
        profile.ConfigType = EConfigType.Aether;
        profile.Remarks = Remarks;
        profile.Address = Address;
        profile.Port = PortOf(Port);
        profile.Finalmask = KotlinText.IsBlank(FinalMask.Text) ? string.Empty : FinalMask.Text;
        profile.DialMode = KotlinText.IsBlank(DialMode.Text) ? string.Empty : DialMode.Text;
        // Set below, against the default of the profile as built here.
        profile.TargetStrategy = string.Empty;
        profile.SetProtocolExtra(profile.GetProtocolExtra() with
        {
            AetherProtocol = Protocol.Type,
            AetherTransport = Transport.Type,
            // Kept whatever the protocol, as the transport is.
            AetherMasqueSni = KotlinText.NullIfBlank(MasqueSni),
            AetherScanMode = Pick(AetherScanMode.All, ScanModeIndex, AetherScanMode.Balanced).Type,
            AetherObfuscation = Pick(AetherObfuscation.All, ObfuscationIndex, AetherObfuscation.Auto).Type,
            AetherFingerprint = Pick(AetherFingerprint.All, FingerprintIndex, AetherFingerprint.Chrome).Type,
            AetherIpVersion = Pick(AetherIpVersion.All, IpVersionIndex, AetherIpVersion.V4).Type,
            AetherWiwOuter = KotlinText.NullIfBlank(WiwOuter),
            AetherWiwInner = KotlinText.NullIfBlank(WiwInner),
            AetherFragment = Fragment,
            AetherFragmentSize = KotlinText.NullIfBlank(FragmentSize),
            AetherFragmentDelay = KotlinText.NullIfBlank(FragmentDelay),
            AetherEch = Ech,
            // Kept while ECH is off as well, as the WARP keys window keeps its own.
            AetherEchDns = KotlinText.NullIfBlank(EchDns),
            AetherEchDomain = KotlinText.NullIfBlank(EchDomain),
            AetherDns = KotlinText.NullIfBlank(Dns),
            AetherExitLoc = KotlinText.NullIfBlank(ExitLoc),
            AetherExitNode = KotlinText.NullIfBlank(ExitNode.Name),
            AetherPsiphon = psiphonOn ? psiphon.Type : null,
            AetherPsiphonMode = psiphonOn ? PsiphonMode.Type : null,
            AetherPsiphonCdnIps = psiphonOn ? KotlinText.NullIfBlank(PsiphonCdnIps) : null,
            AetherPsiphonCdnSni = psiphonOn ? KotlinText.NullIfBlank(PsiphonCdnSni) : null,
            AetherPsiphonCdnSets = psiphonOn ? KotlinText.NullIfBlank(PsiphonCdnSets) : null,
            AetherPsiphonRegion = psiphonOn ? KotlinText.NullIfBlank(PsiphonRegion) : null,
            AetherPsiphonBundledList = psiphonOn && !PsiphonBundledList ? false : null,
            AetherTor = torOn ? tor.Type : null,
            AetherTorBridges = torOn ? TorBridges.Type : null,
            AetherTorBridgeLines = torOn ? KotlinText.NullIfBlank(TorBridgeLines) : null,
            AetherTorRelays = torOn ? Pick(AetherTorRelays.All, TorRelaysIndex, AetherTorRelays.Auto).Type : null,
            AetherCommand = null,
        });
        // A command that says what the settings say is no command of its own: the profile follows the settings.
        var command = KotlinText.Trim(Command ?? string.Empty);
        if (command.Length > 0 && (keepCommand || command != AetherCore.Of(profile, ListenPort).Command))
        {
            profile.SetProtocolExtra(profile.GetProtocolExtra() with { AetherCommand = command });
        }
        // The profile's default is stored as none, so that the profile follows it, as Tor and Psiphon move it; anything
        // else as it is, AsIs included (critique 5).
        var strategy = TargetStrategy ?? string.Empty;
        if (!KotlinText.IsBlank(strategy) && strategy != AetherOutbound.DefaultTargetStrategy(profile))
        {
            profile.TargetStrategy = strategy;
        }
        return profile;
    }

    /// <summary>
    /// Whether <paramref name="current" />, the profile the editor holds, is still <paramref name="checkedProfile" />,
    /// the one a check was made on, as a save stores them on <paramref name="listenPort" />, normalized (PattNG
    /// holdsChecked): a field the editor shows filled in with its default, as a cleared ECH resolver, is no edit.
    /// </summary>
    public static bool HoldsChecked(ProfileItem current, ProfileItem checkedProfile, int listenPort)
    {
        return SavedAs(current, listenPort) == SavedAs(checkedProfile, listenPort);
    }

    private static string SavedAs(ProfileItem profile, int listenPort)
    {
        var copy = JsonUtils.DeepCopy(profile) ?? new ProfileItem();
        AetherFmt.Normalize(copy, null, listenPort);
        return JsonUtils.Serialize(copy, false) ?? string.Empty;
    }

    #endregion the profile

    #region save

    /// <summary>
    /// Saves the profile once it passes the editor's checks and the WARP keys it needs are there, or the user goes on
    /// without them (design 3.2.4): remarks, the finalMask, the settings normalized as the core takes them, the exit-node
    /// looked up afresh, then the keys. The checks normalize a copy; one edited while they ran is checked in its turn,
    /// remarks included. Once a save has closed the editor, nothing more is saved.
    /// </summary>
    public async Task SaveAsync()
    {
        if (_saved)
        {
            return;
        }
        while (true)
        {
            // On every pass: a profile edited while the checks ran may have lost its remarks (PattNG requestSave).
            if (KotlinText.IsBlank(Remarks))
            {
                NoticeManager.Instance.Enqueue(ResUI.PleaseFillRemarks);
                return;
            }
            var held = ToProfileItem();
            var profile = JsonUtils.DeepCopy(held) ?? held;
            // The finalMask of an Aether profile is that of its exit-node: a bad one is named by its own label. With a
            // profile as the exit-node it is out of use, but a broken one is refused all the same: it would be kept for
            // freedom, and a link of the profile, which carries no exit-node, would hand it on.
            if (!AetherExit.TakesFinalMask(profile.Finalmask))
            {
                NoticeManager.Instance.Enqueue(string.Format(ResUI.MsgInvalidProperty, ResUI.TbAetherExitFinalMask));
                return;
            }
            // The core cannot listen where the local proxy of the app does, nor where the inbound it dials out through does.
            if (AetherFmt.Normalize(profile, _source.TakenPorts, ListenPort) is { } problem)
            {
                NoticeManager.Instance.Enqueue(MessageOf(problem, profile, _source.TakenPorts, ListenPort));
                return;
            }
            // The profile named as the exit-node may be renamed or gone since the editor opened, or share its name with
            // another by now, or give no outbound: looked up as the session will.
            var node = KotlinText.TrimOrNull(profile.GetProtocolExtra().AetherExitNode) ?? string.Empty;
            if (node.Length > 0 && await _source.FindExitNodeAsync(node) is ExitNodeLookup.Problem nodeProblem)
            {
                NoticeManager.Instance.Enqueue(AetherExitNodes.MessageOf(nodeProblem, node));
                return;
            }
            var missing = await MissingKeysAsync(AetherIdentityManager.FilesNeededBy(AetherCore.Of(profile, ListenPort).Arguments));
            if (_saved || _closed)
            {
                return;
            }
            // One edited while the checks ran is checked in its turn, rather than saved without its own check.
            if (!HoldsChecked(ToProfileItem(), held, ListenPort))
            {
                continue;
            }
            if (missing.Count > 0)
            {
                // A key is missing: get it first, or go on, and the core registers what it lacks on its own. The keys
                // window waits for a running scan to end, so it is not offered meanwhile.
                switch (await KeysMissingInteraction.HandleSafe(new AetherKeysQuestion(Scan: false, CanGetKeys: !IsScanning), EAetherKeysChoice.Cancel))
                {
                    case EAetherKeysChoice.GetKeys:
                        await OpenKeysAsync();
                        return;

                    case EAetherKeysChoice.Anyway:
                        if (!HoldsChecked(ToProfileItem(), held, ListenPort))
                        {
                            continue;
                        }
                        break;

                    default:
                        return;
                }
            }
            await StoreAsync(profile);
            return;
        }
    }

    private async Task StoreAsync(ProfileItem profile)
    {
        if (await _source.SaveAsync(profile))
        {
            _saved = true;
            if (_item.IndexId.IsNullOrEmpty())
            {
                // The caller reloads when the profile it added is the active one, as for every other editor.
                _item.IndexId = profile.IndexId;
            }
            NoticeManager.Instance.Enqueue(ResUI.OperationSuccess);
            RequestClose?.Invoke(this, EventArgs.Empty);
        }
        else
        {
            NoticeManager.Instance.Enqueue(ResUI.OperationFailed);
        }
    }

    /// <summary>
    /// The message a save shows for <paramref name="problem" />, a problem of the Aether settings of
    /// <paramref name="profile" /> with <paramref name="takenPorts" /> held, on the Aether listen port
    /// <paramref name="listenPort" />, as <see cref="AetherFmt.Normalize" /> left them: those about the listeners of a
    /// command name the port or the option, and the listen port where nothing else is to be named.
    /// </summary>
    public static string MessageOf(AetherProblem problem, ProfileItem profile, IEnumerable<int>? takenPorts, int listenPort)
    {
        return problem switch
        {
            AetherProblem.InvalidMasqueSni => ResUI.MsgAetherInvalidMasqueSni,
            AetherProblem.InvalidPeer => ResUI.MsgAetherInvalidEndpoint,
            AetherProblem.InvalidHop => ResUI.MsgAetherInvalidHop,
            AetherProblem.SharedHop => ResUI.MsgAetherSameHop,
            AetherProblem.InvalidFragment => ResUI.MsgAetherInvalidFragment,
            AetherProblem.InvalidDns => ResUI.MsgAetherInvalidDns,
            AetherProblem.InvalidExitLoc => ResUI.MsgAetherInvalidExitLoc,
            AetherProblem.InvalidEchDns => ResUI.MsgAetherInvalidEchDns,
            AetherProblem.InvalidEchDomain => ResUI.MsgAetherInvalidEchDomain,
            AetherProblem.ListenPortTaken =>
                string.Format(ResUI.MsgAetherListenPortTaken, AetherFmt.TakenListenPort(profile, takenPorts, listenPort) ?? listenPort),
            AetherProblem.ListenPortShared =>
                string.Format(ResUI.MsgAetherListenPortShared, AetherFmt.SharedListenPort(profile, listenPort) ?? listenPort),
            AetherProblem.ListenPortInvalid =>
                string.Format(ResUI.MsgAetherListenPortInvalid, AetherFmt.InvalidListenPort(profile, listenPort) ?? listenPort),
            AetherProblem.ListenAddressInvalid =>
                string.Format(ResUI.MsgAetherListenAddressInvalid, AetherFmt.InvalidListener(profile, listenPort) ?? string.Empty),
            AetherProblem.ListenAddressUnreachable =>
                string.Format(ResUI.MsgAetherListenAddressUnreachable, AetherFmt.UnreachableListener(profile, listenPort) ?? string.Empty),
            AetherProblem.PsiphonNeedsMasque => ResUI.MsgAetherPsiphonNeedsMasque,
            AetherProblem.NextPortTaken => ResUI.MsgAetherNextPortTaken,
            AetherProblem.TorNeedsMasque => ResUI.MsgAetherTorNeedsMasque,
            AetherProblem.TorPsiphonConflict => ResUI.MsgAetherTorPsiphonConflict,
            AetherProblem.TorBridgesMissing => ResUI.MsgAetherTorBridgesMissing,
            _ => ResUI.MsgAetherInvalidCommand,
        };
    }

    #endregion save

    #region scan, keys, Psiphon data

    /// <summary>
    /// Scans for an endpoint of the profile the editor holds (design 3.2.5, PattNG scan): not on the key of a live
    /// session, nor through an exit-node name that finds no profile or several; unless <paramref name="anyway" />, a scan
    /// whose protocol lacks a WARP key asks first. Ignored while a scan runs. A found endpoint is put in the fields.
    /// </summary>
    public async Task ScanAsync(bool anyway = false)
    {
        if (IsScanning)
        {
            return;
        }
        var profile = ToProfileItem();
        var askKeys = await ScanOnceAsync(profile, anyway);
        if (askKeys && !_closed)
        {
            // A key the scan needs is missing: get it first, or scan anyway, and the core registers it on its own.
            switch (await KeysMissingInteraction.HandleSafe(new AetherKeysQuestion(Scan: true, CanGetKeys: true), EAetherKeysChoice.Cancel))
            {
                case EAetherKeysChoice.GetKeys:
                    await OpenKeysAsync();
                    break;

                case EAetherKeysChoice.Anyway:
                    // A profile edited meanwhile is checked in its turn.
                    await ScanAsync(anyway: HoldsChecked(ToProfileItem(), profile, ListenPort));
                    break;
            }
        }
    }

    /// <summary>
    /// The scan of <paramref name="profile" />, which shows as running until it is over; true when it did not start for
    /// want of a key, which the caller asks about once the scan no longer shows as running.
    /// </summary>
    private async Task<bool> ScanOnceAsync(ProfileItem profile, bool anyway)
    {
        var protocol = AetherProtocol.FromString(profile.GetProtocolExtra().AetherProtocol);
        using var cancellation = new CancellationTokenSource();
        _scanCancellation = cancellation;
        SetScanning(true);
        try
        {
            // Checked at the tap: a second tunnel on the key of a live session would disturb it.
            RefreshSession();
            if (SessionProtocol is { } session && AetherIdentityManager.SharesIdentity(protocol, session))
            {
                Log.Append(AetherLogPriority.Warn, ResUI.MsgAetherScanBlocked);
                return false;
            }
            // The profile chosen as the exit-node may be renamed or gone since the editor opened, or share its name with
            // another by now; the scan would reach WARP without it.
            var node = KotlinText.TrimOrNull(profile.GetProtocolExtra().AetherExitNode) ?? string.Empty;
            if (node.Length > 0)
            {
                var lookup = await _source.FindExitNodeAsync(node);
                // Cancelled meanwhile, or the window closed: the scan ends here, and says nothing more (PattNG cancelScan).
                cancellation.Token.ThrowIfCancellationRequested();
                if (lookup is ExitNodeLookup.Problem problem)
                {
                    Log.Append(AetherLogPriority.Error, AetherExitNodes.MessageOf(problem, node));
                    return false;
                }
            }
            if (!anyway)
            {
                var missing = await MissingKeysAsync(AetherIdentityManager.FilesNeededBy(AetherArguments.Build(profile, 0, scan: true)));
                // Cancelled meanwhile, or the window closed: no question about the keys of a scan that is not to run.
                cancellation.Token.ThrowIfCancellationRequested();
                if (missing.Count > 0)
                {
                    return true;
                }
            }
            // A window closed meanwhile cancelled the scan before it started.
            cancellation.Token.ThrowIfCancellationRequested();
            Log.Append(AetherLogPriority.Info, ResUI.MsgAetherScanStarted);
            var result = await _source.ScanAsync(profile, Log.AppendOutput, cancellation.Token);
            if (result.Outcome == AetherRunOutcome.NotStarted)
            {
                Log.Append(AetherLogPriority.Error, ResUI.MsgAetherCoreCannotStart);
            }
            if (result.Value is { } found)
            {
                Log.Append(AetherLogPriority.Info, ScanOutcome(found));
                ApplyScanResult(protocol, found);
                NoticeManager.Instance.Enqueue(ResUI.MsgAetherScanSuccess);
            }
            else
            {
                Log.Append(AetherLogPriority.Warn, ResUI.MsgAetherScanFailed);
                NoticeManager.Instance.Enqueue(ResUI.MsgAetherScanFailed);
            }
            // A scan may have registered a key.
            await ShowIdentityAsync(protocol);
            return false;
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            // Cancelled, and over: the core and what it started have ended.
            return false;
        }
        finally
        {
            _scanCancellation = null;
            SetScanning(false);
        }
    }

    /// <summary>Stops the scan, which shows as running until its core, with whatever that started, has ended.</summary>
    public void CancelScan()
    {
        var cancellation = _scanCancellation;
        if (!IsScanning || cancellation == null || cancellation.IsCancellationRequested)
        {
            return;
        }
        Log.Append(AetherLogPriority.Warn, ResUI.MsgAetherScanCancelled);
        cancellation.Cancel();
    }

    /// <summary>Forgets what Psiphon has learned, unless a session runs on it; the outcome goes to the log.</summary>
    public async Task ClearPsiphonDataAsync()
    {
        if (IsScanning)
        {
            return;
        }
        // Checked again at the tap: the session may have come up after the editor opened.
        RefreshSession();
        if (SessionProtocol != null)
        {
            Log.Append(AetherLogPriority.Warn, ResUI.MsgAetherPsiphonClearBlocked);
            return;
        }
        switch (await _source.ClearPsiphonDataAsync())
        {
            case AetherPsiphonClear.Cleared:
                Log.Append(AetherLogPriority.Info, ResUI.MsgAetherPsiphonCleared);
                break;

            case AetherPsiphonClear.Blocked:
                Log.Append(AetherLogPriority.Warn, ResUI.MsgAetherPsiphonClearBlocked);
                break;

            default:
                Log.Append(AetherLogPriority.Error, ResUI.MsgAetherPsiphonClearFailed);
                break;
        }
    }

    /// <summary>
    /// Opens the WARP keys window, which preselects nothing (PattNG), and shows the key status once it is closed, if it
    /// changed. A scan holds the exit a run of that window dials out through, so it opens only once the scan has ended.
    /// </summary>
    public async Task OpenKeysAsync()
    {
        if (IsScanning)
        {
            return;
        }
        // Both views open the WARP keys window; unhandled, as in the tests, HandleSafe logs that and goes on.
        await OpenKeysInteraction.HandleSafe(RxVoid.Default, RxVoid.Default);
        if (!_closed)
        {
            await ShowIdentityAsync(Protocol);
        }
    }

    /// <summary>
    /// Logs the key status of <paramref name="protocol" /> when it differs from the one logged last: at the start, on a
    /// change of protocol, after a scan and after the WARP keys window.
    /// </summary>
    public async Task ShowIdentityAsync(AetherProtocol protocol)
    {
        AetherIdentityStatus status;
        try
        {
            status = await _source.IdentityStatusAsync(protocol);
        }
        catch (Exception ex)
        {
            Logging.SaveLog("AetherEditor: the WARP keys could not be read", ex);
            return;
        }
        if (status == _reportedIdentity)
        {
            return;
        }
        _reportedIdentity = status;
        foreach (var line in KeyLines(status))
        {
            Log.Append(AetherLogPriority.Info, line);
        }
    }

    /// <summary>Ends what the editor runs once its window is closed: a scan is cancelled, and the session no longer followed.</summary>
    public void OnClosed()
    {
        _closed = true;
        _source.SessionChanged -= OnSessionChanged;
        _scanCancellation?.Cancel();
    }

    /// <summary>The log line of what a scan found (PattNG scanOutcome).</summary>
    public static string ScanOutcome(AetherScanResult result)
    {
        return result.InnerHop is { } inner
            ? string.Format(ResUI.MsgAetherScanFoundHops, result.Endpoint, inner)
            : string.Format(ResUI.MsgAetherScanFound, result.Endpoint);
    }

    /// <summary>The key status lines of <paramref name="status" /> (PattNG identityLines): one for a one-hop protocol, the outer and the inner hop's for a two-hop one.</summary>
    public static List<string> KeyLines(AetherIdentityStatus status)
    {
        if (status.Protocol == AetherProtocol.Masque)
        {
            return [KeyLine(status.Primary, ResUI.MsgAetherKeyMasqueReady, ResUI.MsgAetherKeyMasqueMissing)];
        }
        if (status.Protocol == AetherProtocol.WireGuard)
        {
            return [KeyLine(status.Primary, ResUI.MsgAetherKeyWireguardReady, ResUI.MsgAetherKeyWireguardMissing)];
        }
        return
        [
            KeyLine(status.Primary, ResUI.MsgAetherKeyOuterReady, ResUI.MsgAetherKeyOuterMissing),
            KeyLine(status.Secondary, ResUI.MsgAetherKeyInnerReady, ResUI.MsgAetherKeyInnerMissing),
        ];
    }

    /// <summary>The log line of a key: <paramref name="ready" /> with its device and addresses, or <paramref name="missing" /> when there is none.</summary>
    public static string KeyLine(AetherIdentity? identity, string ready, string missing)
    {
        if (identity == null)
        {
            return missing;
        }
        var device = identity.DeviceId.Length > DeviceIdLength ? identity.DeviceId[..DeviceIdLength] + "…" : identity.DeviceId;
        return string.Format(ready, device, identity.Ipv4, identity.Ipv6);
    }

    private void ApplyScanResult(AetherProtocol protocol, AetherScanResult result)
    {
        if (protocol.TwoHops)
        {
            WiwOuter = result.Endpoint.ToString();
            // WireGuard over MASQUE finds its gateway alone, and keeps the WireGuard endpoint it scanned with.
            if (result.InnerHop is { } inner)
            {
                WiwInner = inner.ToString();
            }
        }
        else
        {
            Address = result.Endpoint.Host;
            Port = result.Endpoint.Port.ToString(CultureInfo.InvariantCulture);
        }
    }

    private async Task<List<string>> MissingKeysAsync(IReadOnlyList<string> needed)
    {
        if (needed.Count == 0)
        {
            return [];
        }
        try
        {
            return await _source.MissingKeysAsync(needed);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Logging.SaveLog("AetherEditor: the WARP keys could not be read", ex);
            return [.. needed];
        }
    }

    #endregion scan, keys, Psiphon data

    #region state

    private async Task InitAsync()
    {
        try
        {
            var availability = await _source.AvailabilityAsync();
            CoreAvailable = availability.Core;
            PsiphonAvailable = availability.Psiphon;
            TorTransportsAvailable = availability.TorTransports;
            Refresh();
            ExitNode.SetNodes(await _source.ExitNodesAsync());
            _regions = await _source.PsiphonRegionsAsync();
            RebuildRegions();
            await ShowIdentityAsync(Protocol);
        }
        catch (Exception ex)
        {
            Logging.SaveLog("AetherEditor: the editor could not read what it shows", ex);
        }
    }

    private void OnSessionChanged()
    {
        OnUi(RefreshSession);
    }

    private void RefreshSession()
    {
        SessionProtocol = _source.SessionProtocol;
        Refresh();
    }

    private void SetScanning(bool scanning)
    {
        IsScanning = scanning;
        Refresh();
    }

    private void OnFieldChanged(string? name)
    {
        if (_refreshing || name == null || !IsField(name))
        {
            return;
        }
        if (name == nameof(ProtocolIndex))
        {
            _ = ShowIdentityAsync(Protocol);
        }
        if (name == nameof(PsiphonRegion))
        {
            RebuildRegions();
        }
        if (name == nameof(PsiphonCdnSets))
        {
            // The boxes show the choice however it was made.
            var chosen = AetherPsiphonCdnSet.Parse(PsiphonCdnSets).ToHashSet();
            foreach (var option in PsiphonCdnSetOptions)
            {
                option.IsChecked = chosen.Contains(option.Set);
            }
            PsiphonCdnSetsSummary = CdnSetsSummary();
        }
        Refresh();
    }

    private static bool IsField(string name)
    {
        return name is nameof(Remarks) or nameof(ProtocolIndex) or nameof(TransportIndex) or nameof(MasqueSni)
            or nameof(Fragment) or nameof(FragmentSize) or nameof(FragmentDelay) or nameof(Ech) or nameof(EchDns)
            or nameof(EchDomain) or nameof(ScanModeIndex) or nameof(ObfuscationIndex) or nameof(FingerprintIndex)
            or nameof(PsiphonIndex) or nameof(PsiphonModeIndex) or nameof(PsiphonCdnIps)
            or nameof(PsiphonCdnSni) or nameof(PsiphonCdnSets) or nameof(PsiphonRegion) or nameof(PsiphonBundledList)
            or nameof(TorIndex) or nameof(TorBridgesIndex) or nameof(TorRelaysIndex) or nameof(TorBridgeLines)
            or nameof(WiwOuter) or nameof(WiwInner) or nameof(Address) or nameof(Port) or nameof(IpVersionIndex)
            or nameof(Dns) or nameof(ExitLoc) or nameof(TargetStrategy) or nameof(Command);
    }

    /// <summary>Recomputes what the fields decide: which are shown, which enabled, the command the settings build.</summary>
    private void Refresh()
    {
        if (_refreshing)
        {
            return;
        }
        _refreshing = true;
        try
        {
            var protocol = Protocol;
            var psiphon = Psiphon;
            var tor = Tor;
            var bridges = TorBridges;
            WarpUsed = psiphon != AetherPsiphon.Only && tor != AetherTor.Only;
            var overMasque = protocol.OverMasque;
            var usesHttp2 = overMasque && Transport == AetherTransport.Http2;
            ShowTransport = WarpUsed && overMasque;
            // A forced HTTP/2 does not show the fragment: it is the transport chosen that takes it.
            ShowFragment = WarpUsed && usesHttp2;
            ShowFragmentSizes = ShowFragment && Fragment;
            ShowEch = WarpUsed && overMasque;
            ShowEchFields = ShowEch && Ech;
            ShowObfuscation = WarpUsed && !AetherArguments.MasqueOverHttp2(protocol, Transport, tor, psiphon);
            PsiphonOn = psiphon != AetherPsiphon.Off;
            ShowPsiphonUnavailable = PsiphonOn && !PsiphonAvailable;
            // The CDN lists feed the fronted transports alone, which the direct shape never uses; the server names count
            // only beside an IP list of one's own, since the built-in list comes whole.
            PsiphonCdnShown = PsiphonOn && PsiphonMode != AetherPsiphonMode.Direct;
            PsiphonCdnSniShown = PsiphonCdnShown && !KotlinText.IsBlank(PsiphonCdnIps);
            TorOn = tor != AetherTor.Off;
            // Inside the tunnel Tor is never blocked and asks for no bridges unless told to; around it or alone it has to
            // reach Tor first, and where Tor is blocked that takes the transport program.
            var bridgesUsed = bridges != AetherTorBridges.Never && !(tor == AetherTor.Chain && bridges == AetherTorBridges.Auto);
            ShowTorTransportsUnavailable = TorOn && bridgesUsed && !TorTransportsAvailable;
            TorRelaysShown = TorOn && (bridges == AetherTorBridges.Auto || bridges == AetherTorBridges.First);
            TorBridgeLinesShown = TorOn && bridges == AetherTorBridges.Own;
            ShowHops = WarpUsed && protocol.TwoHops;
            ShowEndpoint = WarpUsed && !protocol.TwoHops;
            InnerHopHint = protocol == AetherProtocol.WgOverMasque ? ResUI.TbAetherGoolPeerHint : ResUI.TbAetherEndpointHint;
            NotScanning = !IsScanning;
            ScanText = IsScanning ? ResUI.TbAetherScanning : ResUI.TbAetherScan;
            ScanBlocked = SessionProtocol is { } session && AetherIdentityManager.SharesIdentity(protocol, session);
            ShowScanBlocked = WarpUsed && ScanBlocked;
            CanScan = CoreAvailable && !IsScanning && !ScanBlocked;
            CanClearPsiphon = CoreAvailable && !IsScanning && SessionProtocol == null;

            var settings = ToProfileItem();
            settings.SetProtocolExtra(settings.GetProtocolExtra() with { AetherCommand = null });
            BuiltCommand = AetherCore.Of(settings, ListenPort).Command;
            CommandIsCustom = !KotlinText.IsBlank(Command) && KotlinText.Trim(Command) != BuiltCommand;
            DefaultTargetStrategy = AetherOutbound.DefaultTargetStrategy(DefaultsProfile());
            HasOtherSettings = !KotlinText.IsBlank(Dns) || !KotlinText.IsBlank(ExitLoc)
                || (!KotlinText.IsBlank(TargetStrategy) && TargetStrategy != DefaultTargetStrategy);
            PsiphonCdnSetsSummary = CdnSetsSummary();
        }
        finally
        {
            _refreshing = false;
        }
        this.RaisePropertyChanged(nameof(CommandText));
        this.RaisePropertyChanged(nameof(TargetStrategyIndex));
        this.RaisePropertyChanged(nameof(PsiphonRegionIndex));
    }

    /// <summary>
    /// The profile the default targetStrategy is weighed on (PattNG defaultTargetStrategy): where Tor and Psiphon stand,
    /// or the command written by hand says, which runs in their place.
    /// </summary>
    private ProfileItem DefaultsProfile()
    {
        var profile = new ProfileItem { ConfigType = EConfigType.Aether };
        profile.SetProtocolExtra(new ProtocolExtraItem
        {
            AetherTor = Tor.Type,
            AetherPsiphon = Psiphon.Type,
            AetherCommand = KotlinText.NullIfBlank(Command),
        });
        return profile;
    }

    /// <summary>Chooses or drops one CDN edge list; the choice is kept in the order the core tries them.</summary>
    public void SetPsiphonCdnSet(AetherPsiphonCdnSet set, bool chosen)
    {
        var choice = AetherPsiphonCdnSet.Parse(PsiphonCdnSets).ToHashSet();
        if (chosen)
        {
            choice.Add(set);
        }
        else
        {
            choice.Remove(set);
        }
        PsiphonCdnSets = AetherPsiphonCdnSet.Join(choice) ?? string.Empty;
    }

    private string CdnSetsSummary()
    {
        var chosen = AetherPsiphonCdnSet.Parse(PsiphonCdnSets);
        if (chosen.Count == 0)
        {
            return ResUI.TbAetherPsiphonCdnSetsAll;
        }
        var labels = AetherLabels.PsiphonCdnSets;
        return string.Join(", ", chosen.Select(set => labels[AetherPsiphonCdnSet.All.ToList().IndexOf(set)]));
    }

    /// <summary>
    /// The exit countries on offer: those read, and the one the profile holds, which stays on offer so that a shared
    /// profile keeps its choice; sorted by their names in the language of the app.
    /// </summary>
    private void RebuildRegions()
    {
        var current = CurrentRegion();
        var codes = _regions.Concat(current.Length > 0 ? [current] : []).Distinct(StringComparer.Ordinal).ToList();
        var comparer = StringComparer.Create(CultureInfo.CurrentUICulture, ignoreCase: true);
        codes = codes.OrderBy(RegionName, comparer).ToList();
        var labels = new List<string> { ResUI.TbAetherPsiphonRegionAny };
        labels.AddRange(codes.Select(code => $"{RegionName(code)} ({code})"));
        if (!codes.SequenceEqual(_regionCodes) || PsiphonRegionLabels == null || !labels.SequenceEqual(PsiphonRegionLabels))
        {
            _regionCodes = codes;
            PsiphonRegionLabels = labels;
        }
        this.RaisePropertyChanged(nameof(PsiphonRegionIndex));
    }

    private string CurrentRegion()
    {
        return KotlinText.Uppercase(KotlinText.Trim(PsiphonRegion ?? string.Empty));
    }

    /// <summary>
    /// The name of the country <paramref name="code" /> in the language of the app (PattNG getDisplayCountry(locale)): as
    /// ICU names it within the display name of a culture of no language there, "Unknown language (Germany)", since
    /// RegionInfo.DisplayName gives the country's own name under ICU whatever the language of the app. Its English name
    /// where ICU names none, and the code where there is none at all.
    /// </summary>
    private static string RegionName(string code)
    {
        try
        {
            if (InParentheses(CultureInfo.GetCultureInfo("und-" + code).DisplayName) is { } named)
            {
                return named;
            }
        }
        catch (ArgumentException)
        {
            // CultureNotFoundException: no culture of that region, or no ICU to name it.
        }
        try
        {
            var name = new RegionInfo(code).EnglishName;
            return string.IsNullOrWhiteSpace(name) ? code : name;
        }
        catch (ArgumentException)
        {
            return code;
        }
    }

    /// <summary>
    /// The text inside the parentheses that end <paramref name="text" />, which may hold parentheses of their own, as
    /// "Myanmar (Burma)" does; full-width ones as well, as Chinese writes them. Null where it does not end in any.
    /// </summary>
    public static string? InParentheses(string? text)
    {
        var end = (text ?? string.Empty).TrimEnd().Length - 1;
        if (end < 0 || text![end] is not (')' or '\uFF09'))
        {
            return null;
        }
        var depth = 0;
        for (var i = end; i >= 0; i--)
        {
            if (text[i] is ')' or '\uFF09')
            {
                depth++;
            }
            else if (text[i] is '(' or '\uFF08' && --depth == 0)
            {
                var inner = text[(i + 1)..end].Trim();
                return inner.Length > 0 ? inner : null;
            }
        }
        return null;
    }

    private void OnUi(Action action)
    {
        if (_ui == null || SynchronizationContext.Current == _ui)
        {
            action();
        }
        else
        {
            _ui.Post(_ => action(), null);
        }
    }

    private static int IndexIn<T>(IReadOnlyList<T> all, T value)
    {
        for (var index = 0; index < all.Count; index++)
        {
            if (Equals(all[index], value))
            {
                return index;
            }
        }
        return 0;
    }

    private static T Pick<T>(IReadOnlyList<T> all, int index, T fallback)
    {
        return index >= 0 && index < all.Count ? all[index] : fallback;
    }

    /// <summary>
    /// The port typed, as the check of the endpoint reads it (<see cref="AetherEndpoint.Of" />): up to five digits of any
    /// script; 0, no port, for blank or anything else, which that check refuses beside an address, as one out of range.
    /// </summary>
    private static int PortOf(string? text)
    {
        var trimmed = KotlinText.Trim(text ?? string.Empty);
        if (trimmed.Length is 0 or > 5)
        {
            return 0;
        }
        var port = 0;
        foreach (var ch in trimmed)
        {
            var digit = AetherDigits.DigitOf(ch);
            if (digit < 0)
            {
                return 0;
            }
            port = (port * 10) + digit;
        }
        return port;
    }

    #endregion state
}
