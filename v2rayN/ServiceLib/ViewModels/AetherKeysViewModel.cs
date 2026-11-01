namespace ServiceLib.ViewModels;

// PattN: fork-only file, the WARP keys window (design 3.4; PattNG ui/server/AetherKeysViewModel.kt and
// ServerAetherKeysActivity.kt).

/// <summary>One of the kinds of keys the WARP keys window can get, with whether it is the one chosen.</summary>
public partial class AetherKeyKindOption : ReactiveObject
{
    public AetherKeyKindOption(AetherKeyKind kind, string label, bool isChecked)
    {
        Kind = kind;
        Label = label;
        IsChecked = isChecked;
    }

    public AetherKeyKind Kind { get; }

    public string Label { get; }

    [Reactive]
    public partial bool IsChecked { get; set; }
}

/// <summary>
/// PattN: the window that gets new WARP keys (design 3.4, PattNG AetherKeysViewModel): its settings, which are its own and
/// no profile's (<see cref="AetherKeysSettings" />, kept in <see cref="Config.AetherItem" />), the run of the core that
/// registers the keys, and the log of that run and of the keys in use. Each change of a setting is saved as it is made;
/// one that changes nothing saves nothing. What a run was started with stays on show while it runs.
/// </summary>
public partial class AetherKeysViewModel : MyReactiveObject
{
    private readonly IAetherKeysSource _source;
    private readonly SynchronizationContext? _ui = SynchronizationContext.Current;

    /// <summary>One save at a time, each of the settings as they are by then, so that the last one written is the latest.</summary>
    private readonly SemaphoreSlim _saving = new(1, 1);

    /// <summary>The identity of each key file as the log last showed it.</summary>
    private readonly Dictionary<string, AetherIdentity?> _shownKeys = new(StringComparer.Ordinal);

    private CancellationTokenSource? _renewal;

    /// <summary>Set while the fields are put in line with the settings, so that this is not taken for an edit.</summary>
    private bool _showing;

    private bool _closed;

    public AetherKeysViewModel() : this(null)
    {
    }

    public AetherKeysViewModel(IAetherKeysSource? source)
    {
        _config = AppManager.Instance.Config;
        _source = source ?? new AetherKeysSource(_config);
        Settings = _source.LoadSettings();
        KindOptions = AetherKeyKind.All.Select(kind => new AetherKeyKindOption(kind, KindLabel(kind), kind == Settings.Kind)).ToList();
        ExitNode = new ExitNodeFieldViewModel(Settings.ExitNode);
        FinalMask = new PresetFieldViewModel(FieldPresets.FinalMask, Settings.FinalMask);
        DialMode = new PresetFieldViewModel(FieldPresets.DialMode, Settings.DialMode);
        Log = new AetherLogViewModel(ResUI.TbAetherKeysLogEmpty);
        // Until the core folder is read, as PattNG: the note that it is missing shows only once it is known to be.
        CoreAvailable = true;
        // A session that runs as the window opens; one that starts or ends later is followed through SessionChanged.
        SessionProtocol = _source.SessionProtocol;
        Show();

        foreach (var option in KindOptions)
        {
            option.PropertyChanged += (_, e) =>
            {
                // A radio that is unchecked is the other side of one that is checked.
                if (!_showing && e.PropertyName == nameof(AetherKeyKindOption.IsChecked) && option.IsChecked)
                {
                    Kind = option.Kind;
                }
            };
        }
        ExitNode.PropertyChanged += (_, e) =>
        {
            if (!_showing && e.PropertyName == nameof(ExitNodeFieldViewModel.Name))
            {
                Update(settings => settings with { ExitNode = ExitNode.Name ?? string.Empty });
            }
        };
        FinalMask.PropertyChanged += (_, e) =>
        {
            if (!_showing && e.PropertyName == nameof(PresetFieldViewModel.Text))
            {
                Update(settings => settings with { FinalMask = FinalMask.Text ?? string.Empty });
            }
        };
        DialMode.PropertyChanged += (_, e) =>
        {
            if (!_showing && e.PropertyName == nameof(PresetFieldViewModel.Text))
            {
                Update(settings => settings with { DialMode = DialMode.Text ?? string.Empty });
            }
        };
        _source.SessionChanged += OnSessionChanged;

        GetKeysCmd = ReactiveCommand.CreateFromTask(GetKeysAsync, this.WhenAnyValue(x => x.CanGetKeys));
        CancelCmd = ReactiveCommand.Create(Cancel, this.WhenAnyValue(x => x.IsRenewing));
        UseSettingsCmd = ReactiveCommand.Create(UseSettings, this.WhenAnyValue(x => x.NotRenewing));

        Initialized = InitAsync();
    }

    /// <summary>The settings of the window as they are now; each field below shows one of them.</summary>
    public AetherKeysSettings Settings { get; private set; }

    #region fields, in PattNG's order

    /// <summary>The kinds of keys, one radio each: every key, then each protocol's.</summary>
    public IReadOnlyList<AetherKeyKindOption> KindOptions { get; }

    public AetherKeyKind Kind
    {
        get => Settings.Kind;
        set => Update(settings => settings with { Kind = value ?? AetherKeyKind.AllKeys });
    }

    /// <summary>The API address (PattNG enrollAddress); blank, the core's own.</summary>
    public string ApiAddress
    {
        get => Settings.EnrollAddress;
        set => Update(settings => settings with { EnrollAddress = value ?? string.Empty });
    }

    /// <summary>The server name of the calls to the WARP API (PattNG apiSni); blank, the core's own.</summary>
    public string ApiSni
    {
        get => Settings.ApiSni;
        set => Update(settings => settings with { ApiSni = value ?? string.Empty });
    }

    /// <summary>The HTTP host of the calls to the WARP API (PattNG apiHost); blank, the core's own.</summary>
    public string ApiHost
    {
        get => Settings.ApiHost;
        set => Update(settings => settings with { ApiHost = value ?? string.Empty });
    }

    /// <summary>
    /// What the API address, server name and host show under them, as a preset field shows the name of what it holds:
    /// default while one is blank, which leaves it to the core, else nothing, as a name the field holds is its text.
    /// </summary>
    public string? ApiAddressHeldName => HeldNameOf(Settings.EnrollAddress);

    public string? ApiSniHeldName => HeldNameOf(Settings.ApiSni);

    public string? ApiHostHeldName => HeldNameOf(Settings.ApiHost);

    private string? HeldNameOf(string value) => string.IsNullOrWhiteSpace(value) ? ApiNameOptions[0].Display : null;

    public bool Fragment
    {
        get => Settings.Fragment;
        set => Update(settings => settings with { Fragment = value });
    }

    public string FragmentSize
    {
        get => Settings.FragmentSize;
        set => Update(settings => settings with { FragmentSize = value ?? string.Empty });
    }

    public string FragmentDelay
    {
        get => Settings.FragmentDelay;
        set => Update(settings => settings with { FragmentDelay = value ?? string.Empty });
    }

    public bool Ech
    {
        get => Settings.Ech;
        set => Update(settings => settings with { Ech = value });
    }

    public string EchDns
    {
        get => Settings.EchDns;
        set => Update(settings => settings with { EchDns = value ?? string.Empty });
    }

    public string EchDomain
    {
        get => Settings.EchDomain;
        set => Update(settings => settings with { EchDomain = value ?? string.Empty });
    }

    /// <summary>The fingerprint, an index of <see cref="FingerprintLabels" />; a list that picks nothing for a moment changes nothing.</summary>
    public int FingerprintIndex
    {
        get => IndexIn(AetherFingerprint.All, Settings.Fingerprint);
        set
        {
            if (value < 0 || value >= AetherFingerprint.All.Count)
            {
                return;
            }
            Update(settings => settings with { Fingerprint = AetherFingerprint.All[value] });
        }
    }

    /// <summary>The exit-node of a run, a name (design 3.4 row 6, as the editor's row 15).</summary>
    public ExitNodeFieldViewModel ExitNode { get; }

    /// <summary>The finalMask of the freedom exit-node, a preset field (design 3.3).</summary>
    public PresetFieldViewModel FinalMask { get; }

    /// <summary>The dialMode of the freedom exit-node, a preset field (design 3.3).</summary>
    public PresetFieldViewModel DialMode { get; }

    /// <summary>
    /// The command box: the command written by hand, or the one the settings build while there is none. The built one
    /// typed back is no command of its own: the settings make the command again (PattNG setCommand).
    /// </summary>
    public string CommandText
    {
        get => KotlinText.IsBlank(Settings.Command) ? BuiltCommand : Settings.Command;
        set
        {
            var text = value ?? string.Empty;
            // The box hands back what it shows: that is no edit.
            if (text == CommandText)
            {
                return;
            }
            Update(settings => settings with { Command = AetherKeys.Trim(text) == AetherKeys.BuiltCommand(settings) ? string.Empty : text });
        }
    }

    #endregion fields, in PattNG's order

    #region lists

    public IReadOnlyList<string> FingerprintLabels { get; } = AetherLabels.Fingerprints;

    /// <summary>
    /// What the API address, server name and host offer to pick (PattNG aether_api_name_options): first default, as the
    /// list of a preset field has it, whose value blanks the field and so leaves it to the core, then the two names of the
    /// API, each its own value.
    /// </summary>
    public IReadOnlyList<ApiNameOption> ApiNameOptions { get; } =
        [new(string.Empty, ResUI.TbPresetDefault), .. AetherKeys.ApiNameOptions.Select(name => new ApiNameOption(name, name))];

    public IReadOnlyList<string> EchDnsOptions { get; } = Global.AetherEchDnsOptions;
    public IReadOnlyList<string> EchDomainOptions { get; } = Global.AetherEchDomainOptions;

    #endregion lists

    #region derived

    [Reactive] public partial bool IsRenewing { get; set; }
    [Reactive] public partial bool NotRenewing { get; set; }
    [Reactive] public partial bool CoreAvailable { get; set; }

    /// <summary>The protocol of the live session; null without one.</summary>
    [Reactive] public partial AetherProtocol? SessionProtocol { get; set; }

    /// <summary>
    /// Whether the live session uses a key the keys of the command that would run replace: a session keeps the keys it
    /// uses; the keys of the other protocols can change under it.
    /// </summary>
    [Reactive] public partial bool Blocked { get; set; }

    [Reactive] public partial bool CanGetKeys { get; set; }

    /// <summary>"Get new WARP keys", or while a run goes on, that it does.</summary>
    [Reactive] public partial string GetKeysText { get; set; }

    /// <summary>The command the settings build, which the command box shows while none is written by hand.</summary>
    [Reactive] public partial string BuiltCommand { get; set; }

    [Reactive] public partial bool CommandIsCustom { get; set; }

    #endregion derived

    /// <summary>The newest lines of what the window did and the core said, and the keys in use.</summary>
    public AetherLogViewModel Log { get; }

    /// <summary>The look at the core folder, the keys and the exit-nodes as the window opens; the tests wait for it.</summary>
    public Task Initialized { get; }

    public ReactiveCommand<RxVoid, RxVoid> GetKeysCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> CancelCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> UseSettingsCmd { get; }

    #region run

    /// <summary>
    /// Gets new keys as the settings say (PattNG getKeys): registers them with a run of the core, which dials out through
    /// the exit-node of the settings, and puts them in place of the keys in use once all of them are ready. Settings
    /// that cannot run are told, and nothing runs; a session that uses one of those keys keeps them, the other keys can
    /// change under it. Ignored while a run goes on. Over once the run is: the core, and the exit it dialled out through,
    /// have ended by then.
    /// </summary>
    public async Task GetKeysAsync()
    {
        if (IsRenewing || _closed)
        {
            return;
        }
        var current = Settings;
        if (AetherKeys.Problem(current) is { } problem)
        {
            NoticeManager.Instance.Enqueue(MessageOf(problem));
            return;
        }
        var arguments = AetherKeys.RunArguments(current);
        if (AetherKeys.KindOf(arguments) is not { } kind)
        {
            return;
        }
        using var cancellation = new CancellationTokenSource();
        _renewal = cancellation;
        SetRenewing(true);
        try
        {
            // Checked at the click: the session may have come up after the window opened.
            RefreshSession();
            if (SessionProtocol is { } session && AetherIdentityManager.UsesKeysOf(session, kind))
            {
                Log.Append(AetherLogPriority.Warn, ResUI.MsgAetherRenewBlocked);
                return;
            }
            // The profile chosen as the exit-node may be renamed or gone since the window opened, or share its name with
            // another by now; the run would reach WARP without it.
            var node = AetherKeys.Trim(current.ExitNode);
            if (node.Length > 0 && await _source.FindExitNodeAsync(node) is ExitNodeLookup.Problem nodeProblem)
            {
                NoticeManager.Instance.Enqueue(AetherExitNodes.MessageOf(nodeProblem, node));
                return;
            }
            // A window closed meanwhile cancelled the run before it started.
            cancellation.Token.ThrowIfCancellationRequested();
            Log.Append(AetherLogPriority.Info, ResUI.MsgAetherKeyRenewing);
            var keys = await _source.RenewAsync(kind, arguments, current.Exit, Log.AppendOutput, cancellation.Token);
            if (keys == null)
            {
                Log.Append(AetherLogPriority.Error, ResUI.MsgAetherKeyRenewFailed);
            }
            else
            {
                // By now the core and the exit it dialled out through have ended, and the new keys are in place.
                Log.Append(AetherLogPriority.Info, ResUI.MsgAetherKeyRenewed);
                ShowKeys(keys, onlyChanges: false);
                NoticeManager.Instance.Enqueue(ResUI.MsgAetherKeyRenewed);
            }
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            // By now the core and what it started have ended. A run cancelled once every new key was ready has put them
            // in place all the same, so the keys in use are shown where they changed.
            await ShowKeysInUseAsync(onlyChanges: true);
        }
        catch (Exception ex)
        {
            Logging.SaveLog("AetherKeys: getting new WARP keys failed", ex);
            Log.Append(AetherLogPriority.Error, ResUI.MsgAetherKeyRenewFailed);
        }
        finally
        {
            _renewal = null;
            SetRenewing(false);
        }
    }

    /// <summary>
    /// Stops getting new keys (PattNG cancel): the core that registers them ends, with whatever it started, and until then
    /// the run shows as going on. The keys in use stay, unless every new key was ready already.
    /// </summary>
    public void Cancel()
    {
        var cancellation = _renewal;
        if (!IsRenewing || cancellation == null || cancellation.IsCancellationRequested)
        {
            return;
        }
        Log.Append(AetherLogPriority.Warn, ResUI.MsgAetherKeyRenewCancelled);
        TryCancel(cancellation);
    }

    /// <summary>Drops the command written by hand, so that the settings make the command again.</summary>
    public void UseSettings()
    {
        Update(settings => settings with { Command = string.Empty });
    }

    /// <summary>
    /// Ends what the window runs once it is closed (PattNG: the view model's scope ends with the page): a run is
    /// cancelled, and the session no longer followed.
    /// </summary>
    public void OnClosed()
    {
        _closed = true;
        _source.SessionChanged -= OnSessionChanged;
        if (_renewal is { } cancellation)
        {
            TryCancel(cancellation);
        }
    }

    /// <summary>What tells the user why settings cannot run (PattNG messageOf); the finalMask is named by its label, as the editor names it.</summary>
    public static string MessageOf(AetherKeysProblem problem)
    {
        return problem switch
        {
            AetherKeysProblem.InvalidEnrollAddress => ResUI.MsgAetherKeysInvalidApiAddress,
            AetherKeysProblem.InvalidApiSni => ResUI.MsgAetherKeysInvalidApiSni,
            AetherKeysProblem.InvalidApiHost => ResUI.MsgAetherKeysInvalidApiHost,
            AetherKeysProblem.InvalidFragment => ResUI.MsgAetherInvalidFragment,
            AetherKeysProblem.InvalidEchDns => ResUI.MsgAetherInvalidEchDns,
            AetherKeysProblem.InvalidEchDomain => ResUI.MsgAetherInvalidEchDomain,
            AetherKeysProblem.InvalidFinalMask => string.Format(ResUI.MsgInvalidProperty, ResUI.TbAetherExitFinalMask),
            _ => ResUI.MsgAetherKeysInvalidCommand,
        };
    }

    /// <summary>The log line of <paramref name="key" />, named after its file: its device and addresses, or that there is none yet (PattNG keyLine).</summary>
    public static string KeyLine(AetherKey key)
    {
        return key.File switch
        {
            AetherPaths.WireGuardFile =>
                AddServerAetherViewModel.KeyLine(key.Identity, ResUI.MsgAetherKeyWireguardReady, ResUI.MsgAetherKeyWireguardMissing),
            AetherPaths.WireGuardInnerFile =>
                AddServerAetherViewModel.KeyLine(key.Identity, ResUI.MsgAetherKeyWireguardInnerReady, ResUI.MsgAetherKeyWireguardInnerMissing),
            AetherPaths.MasqueFile =>
                AddServerAetherViewModel.KeyLine(key.Identity, ResUI.MsgAetherKeyMasqueReady, ResUI.MsgAetherKeyMasqueMissing),
            AetherPaths.MasqueGoolFile =>
                AddServerAetherViewModel.KeyLine(key.Identity, ResUI.MsgAetherKeyGoolReady, ResUI.MsgAetherKeyGoolMissing),
            _ =>
                AddServerAetherViewModel.KeyLine(key.Identity, ResUI.MsgAetherKeyMasqueInnerReady, ResUI.MsgAetherKeyMasqueInnerMissing),
        };
    }

    /// <summary>The name a kind of keys goes by: every key, or the protocol whose keys they are, by the name the editor gives it.</summary>
    public static string KindLabel(AetherKeyKind kind)
    {
        return kind == AetherKeyKind.AllKeys ? ResUI.TbAetherKeysKindAll : AetherLabels.ProtocolLabel(AetherProtocol.FromString(kind.Type));
    }

    #endregion run

    #region state

    private async Task InitAsync()
    {
        try
        {
            CoreAvailable = await _source.IsCoreAvailableAsync();
            Refresh();
            await ShowKeysInUseAsync(onlyChanges: false);
            ExitNode.SetNodes(await _source.ExitNodesAsync());
        }
        catch (Exception ex)
        {
            Logging.SaveLog("AetherKeys: the WARP keys window could not read what it shows", ex);
        }
    }

    /// <summary>
    /// Takes the change <paramref name="change" /> makes to the settings and saves it, unless it makes none; while a run
    /// goes on, none is taken. Either way the fields show the settings afterwards.
    /// </summary>
    private void Update(Func<AetherKeysSettings, AetherKeysSettings> change)
    {
        var current = Settings;
        // What a run was started with stays on show while it runs.
        var next = IsRenewing ? current : change(current);
        if (next != current)
        {
            Settings = next;
            this.RaisePropertyChanged(nameof(Settings));
            _ = SaveAsync();
        }
        Show();
    }

    private async Task SaveAsync()
    {
        await _saving.WaitAsync();
        try
        {
            await _source.SaveSettingsAsync(Settings);
        }
        catch (Exception ex)
        {
            Logging.SaveLog("AetherKeys: the settings of the WARP keys window could not be saved", ex);
        }
        finally
        {
            _saving.Release();
        }
    }

    /// <summary>Puts every field in line with <see cref="Settings" />, and recomputes what they decide.</summary>
    private void Show()
    {
        var settings = Settings;
        _showing = true;
        try
        {
            foreach (var option in KindOptions)
            {
                option.IsChecked = option.Kind == settings.Kind;
            }
            if (ExitNode.Name != settings.ExitNode)
            {
                ExitNode.Name = settings.ExitNode;
            }
            if (FinalMask.Text != settings.FinalMask)
            {
                FinalMask.Text = settings.FinalMask;
            }
            if (DialMode.Text != settings.DialMode)
            {
                DialMode.Text = settings.DialMode;
            }
            BuiltCommand = AetherKeys.BuiltCommand(settings);
            CommandIsCustom = AetherKeys.IsCustom(settings);
            Refresh();
        }
        finally
        {
            _showing = false;
        }
        this.RaisePropertyChanged(nameof(Kind));
        this.RaisePropertyChanged(nameof(ApiAddress));
        this.RaisePropertyChanged(nameof(ApiSni));
        this.RaisePropertyChanged(nameof(ApiHost));
        this.RaisePropertyChanged(nameof(ApiAddressHeldName));
        this.RaisePropertyChanged(nameof(ApiSniHeldName));
        this.RaisePropertyChanged(nameof(ApiHostHeldName));
        this.RaisePropertyChanged(nameof(Fragment));
        this.RaisePropertyChanged(nameof(FragmentSize));
        this.RaisePropertyChanged(nameof(FragmentDelay));
        this.RaisePropertyChanged(nameof(Ech));
        this.RaisePropertyChanged(nameof(EchDns));
        this.RaisePropertyChanged(nameof(EchDomain));
        this.RaisePropertyChanged(nameof(FingerprintIndex));
        this.RaisePropertyChanged(nameof(CommandText));
    }

    /// <summary>Recomputes what the settings, the session and a run decide: whether a run can start, and the button's text.</summary>
    private void Refresh()
    {
        NotRenewing = !IsRenewing;
        GetKeysText = IsRenewing ? ResUI.TbAetherRenewing : ResUI.TbAetherGetKeys;
        // A session keeps the keys it uses; the keys of the other protocols can change under it.
        Blocked = SessionProtocol is { } session
                  && AetherKeys.KindOf(AetherKeys.RunArguments(Settings)) is { } kind
                  && AetherIdentityManager.UsesKeysOf(session, kind);
        CanGetKeys = CoreAvailable && !IsRenewing && !Blocked;
    }

    private void SetRenewing(bool renewing)
    {
        IsRenewing = renewing;
        Refresh();
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

    /// <summary>Shows each key in use, or with <paramref name="onlyChanges" /> only those whose identity is not the one the log showed last.</summary>
    private async Task ShowKeysInUseAsync(bool onlyChanges)
    {
        try
        {
            ShowKeys(await _source.KeysAsync(), onlyChanges);
        }
        catch (Exception ex)
        {
            Logging.SaveLog("AetherKeys: the WARP keys could not be read", ex);
        }
    }

    private void ShowKeys(IReadOnlyList<AetherKey> keys, bool onlyChanges)
    {
        foreach (var key in keys)
        {
            if (onlyChanges && _shownKeys.TryGetValue(key.File, out var shown) && shown == key.Identity)
            {
                continue;
            }
            _shownKeys[key.File] = key.Identity;
            Log.Append(AetherLogPriority.Info, KeyLine(key));
        }
    }

    /// <summary>Cancels <paramref name="cancellation" />, which the run it belongs to may have let go of meanwhile.</summary>
    private static void TryCancel(CancellationTokenSource cancellation)
    {
        try
        {
            cancellation.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // The run is over.
        }
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

    #endregion state
}
