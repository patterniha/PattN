namespace ServiceLib.ViewModels;

public partial class StatusBarViewModel : MyReactiveObject
{
    public Interaction<string, RxVoid> SetClipboardDataInteraction { get; } = new();
    public Interaction<RxVoid, string?> PasswordInputInteraction { get; } = new();
    public Interaction<RxVoid, RxVoid> DispatcherRefreshIconInteraction { get; } = new();
    public EventChannel<bool> SubscriptionsUpdateRequested { get; } = new();
    public EventChannel<bool?> ShowHideWindowRequested { get; } = new();

    private static readonly Lazy<StatusBarViewModel> _instance = new(() => new());
    public static StatusBarViewModel Instance => _instance.Value;

    public EventChannel<string> SetDefaultServerRequested { get; } = new();
    public EventChannel<RxVoid> ReloadRequested { get; } = new();
    public EventChannel<RxVoid> AddServerViaScanRequested { get; } = new();
    public EventChannel<RxVoid> AddServerViaClipboardRequested { get; } = new();

    #region ObservableCollection

    public BulkObservableCollection<RoutingItem> RoutingItems { get; } = [];

    public BulkObservableCollection<ComboItem> Servers { get; } = [];

    [Reactive]
    public partial RoutingItem SelectedRouting { get; set; }

    [Reactive]
    public partial ComboItem SelectedServer { get; set; }

    [Reactive]
    public partial bool BlServers { get; set; }

    #endregion ObservableCollection

    public ReactiveCommand<RxVoid, RxVoid> AddServerViaClipboardCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> AddServerViaScanCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> SubUpdateCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> SubUpdateViaProxyCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> CopyProxyCmdToClipboardCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> NotifyLeftClickCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> ShowWindowCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> HideWindowCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> EnableWinDivertCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> ToggleConnectCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> ConnectCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> DisconnectCmd { get; }

    #region System Proxy

    [Reactive]
    public partial bool BlSystemProxyClear { get; set; }

    [Reactive]
    public partial bool BlSystemProxySet { get; set; }

    [Reactive]
    public partial bool BlSystemProxyNothing { get; set; }

    [Reactive]
    public partial bool BlSystemProxyPac { get; set; }

    public ReactiveCommand<RxVoid, RxVoid> SystemProxyClearCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> SystemProxySetCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> SystemProxyNothingCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> SystemProxyPacCmd { get; }

    [Reactive]
    public partial bool BlRouting { get; set; }

    [Reactive]
    public partial int SystemProxySelected { get; set; }

    [Reactive]
    public partial bool BlSystemProxyPacVisible { get; set; }

    #endregion System Proxy

    #region UI

    [Reactive]
    public partial string InboundDisplay { get; set; }

    [Reactive]
    public partial string InboundLanDisplay { get; set; }

    [Reactive]
    public partial string RunningServerDisplay { get; set; }

    [Reactive]
    public partial string RunningServerToolTipText { get; set; }

    [Reactive]
    public partial string RunningInfoDisplay { get; set; }

    [Reactive]
    public partial string SpeedProxyDisplay { get; set; }

    [Reactive]
    public partial string SpeedDirectDisplay { get; set; }

    [Reactive]
    public partial bool EnableTun { get; set; }

    [Reactive]
    public partial bool EnableWinDivert { get; set; }

    [Reactive]
    public partial bool BlWinDivert { get; set; }

    [Reactive]
    public partial bool IsConnected { get; set; } = true;

    [Reactive]
    public partial bool BlIsNonWindows { get; set; }

    #endregion UI

    public StatusBarViewModel()
    {
        _config = AppManager.Instance.Config;
        SelectedRouting = new();
        SelectedServer = new();
        RunningServerToolTipText = GetRunningServerToolTipText("-");
        BlSystemProxyPacVisible = Utils.IsWindows();
        BlIsNonWindows = Utils.IsNonWindows();

        if (_config.TunModeItem.EnableTun && AllowEnableTun())
        {
            EnableTun = true;
        }
        else
        {
            _config.TunModeItem.EnableTun = EnableTun = false;
        }

        if (_config.WinDivertItem.Enable && AllowEnableWinDivert())
        {
            EnableWinDivert = true;
            BlWinDivert = true;
        }
        else
        {
            _config.WinDivertItem.Enable = EnableWinDivert = false;
            BlWinDivert = false;
        }

        #region WhenAnyValue && ReactiveCommand

        this.WhenAnyValue(x => x.SelectedRouting)
            .Where(y => y != null && !y.Remarks.IsNullOrEmpty())
            .SubscribeAsync(async _ => await RoutingSelectedChangedAsync());

        this.WhenAnyValue(x => x.SelectedServer)
            .Where(y => y != null && !y.Text.IsNullOrEmpty())
            .Subscribe(_ => ServerSelectedChanged());

        SystemProxySelected = (int)_config.SystemProxyItem.SysProxyType;
        this.WhenAnyValue(x => x.SystemProxySelected)
            .Where(y => y >= 0)
            .SubscribeAsync(async _ => await DoSystemProxySelected());

        this.WhenAnyValue(x => x.EnableTun)
            .SubscribeAsync(async _ => await DoEnableTun());

        this.WhenAnyValue(x => x.EnableWinDivert)
            .SubscribeAsync(async _ => await DoEnableWinDivert());

        CopyProxyCmdToClipboardCmd = ReactiveCommand.CreateFromTask(async () =>
        {
            await CopyProxyCmdToClipboard();
        });

        NotifyLeftClickCmd = ReactiveCommand.CreateFromTask(async () =>
        {
            ShowHideWindowRequested.Publish(null);
            await Task.CompletedTask;
        });
        ShowWindowCmd = ReactiveCommand.CreateFromTask(async () =>
        {
            ShowHideWindowRequested.Publish(true);
            await Task.CompletedTask;
        });
        HideWindowCmd = ReactiveCommand.CreateFromTask(async () =>
        {
            ShowHideWindowRequested.Publish(false);
            await Task.CompletedTask;
        });

        EnableWinDivertCmd = ReactiveCommand.CreateFromTask(async () =>
        {
            EnableWinDivert = !EnableWinDivert;
            await Task.CompletedTask;
        });

        ToggleConnectCmd = ReactiveCommand.CreateFromTask(async () =>
        {
            await DoToggleConnect();
        });
        ConnectCmd = ReactiveCommand.CreateFromTask(async () =>
        {
            await DoConnect();
        });
        DisconnectCmd = ReactiveCommand.CreateFromTask(async () =>
        {
            await DoDisconnect();
        });

        AddServerViaClipboardCmd = ReactiveCommand.CreateFromTask(async () =>
            {
                await AddServerViaClipboard();
            });
        AddServerViaScanCmd = ReactiveCommand.CreateFromTask(async () =>
        {
            await AddServerViaScan();
        });
        SubUpdateCmd = ReactiveCommand.CreateFromTask(async () =>
        {
            await UpdateSubscriptionProcess(false);
        });
        SubUpdateViaProxyCmd = ReactiveCommand.CreateFromTask(async () =>
        {
            await UpdateSubscriptionProcess(true);
        });

        //System proxy
        SystemProxyClearCmd = ReactiveCommand.CreateFromTask(async () =>
        {
            await SetListenerType(ESysProxyType.ForcedClear);
        });
        SystemProxySetCmd = ReactiveCommand.CreateFromTask(async () =>
        {
            await SetListenerType(ESysProxyType.ForcedChange);
        });
        SystemProxyNothingCmd = ReactiveCommand.CreateFromTask(async () =>
        {
            await SetListenerType(ESysProxyType.Unchanged);
        });
        SystemProxyPacCmd = ReactiveCommand.CreateFromTask(async () =>
        {
            await SetListenerType(ESysProxyType.Pac);
        });

        #endregion WhenAnyValue && ReactiveCommand

        #region AppEvents

        AppEvents.DispatcherStatisticsRequested
            .AsObservable()
            .ObserveOn(RxSchedulers.MainThreadScheduler)
            .SubscribeAsync(async result => await UpdateStatistics(result));

        AppEvents.SysProxyChangeRequested
            .AsObservable()
            .ObserveOn(RxSchedulers.MainThreadScheduler)
            .SubscribeAsync(async result => await SetListenerType(result));

        #endregion AppEvents

        _ = Init();
    }

    private async Task Init()
    {
        await ConfigHandler.InitBuiltinRouting(_config);
        await RefreshRoutingsMenu();
        await InboundDisplayStatus();
        // The view refreshes its icon on initialization; interaction handlers are not registered yet.
        await ChangeSystemProxyAsync(_config.SystemProxyItem.SysProxyType, false);

        BlRouting = true;
    }

    private async Task CopyProxyCmdToClipboard()
    {
        var cmd = Utils.IsWindows() ? "set" : "export";
        var address = $"{Global.Loopback}:{AppManager.Instance.GetLocalPort(EInboundProtocol.socks)}";

        var sb = new StringBuilder();
        sb.AppendLine($"{cmd} http_proxy={Global.HttpProtocol}{address}");
        sb.AppendLine($"{cmd} https_proxy={Global.HttpProtocol}{address}");
        sb.AppendLine($"{cmd} all_proxy={Global.Socks5Protocol}{address}");
        sb.AppendLine("");
        sb.AppendLine($"{cmd} HTTP_PROXY={Global.HttpProtocol}{address}");
        sb.AppendLine($"{cmd} HTTPS_PROXY={Global.HttpProtocol}{address}");
        sb.AppendLine($"{cmd} ALL_PROXY={Global.Socks5Protocol}{address}");

        await SetClipboardDataInteraction.HandleSafe(sb.ToString());
    }

    private async Task AddServerViaClipboard()
    {
        AddServerViaClipboardRequested.Publish();
        await Task.Delay(1000);
    }

    private async Task AddServerViaScan()
    {
        AddServerViaScanRequested.Publish();
        await Task.Delay(1000);
    }

    private async Task UpdateSubscriptionProcess(bool blProxy)
    {
        SubscriptionsUpdateRequested.Publish(blProxy);
        await Task.Delay(1000);
    }

    public async Task RefreshServersBiz()
    {
        await RefreshServersMenu();

        //display running server
        var running = await ConfigHandler.GetDefaultServer(_config);
        if (running != null)
        {
            RunningServerDisplay = running.GetSummary();
            RunningServerToolTipText = GetRunningServerToolTipText(RunningServerDisplay);
        }
        else
        {
            RunningServerDisplay = ResUI.CheckServerSettings;
            RunningServerToolTipText = GetRunningServerToolTipText(RunningServerDisplay);
        }
    }

    private string GetRunningServerToolTipText(string serverInfo)
    {
        return Utils.IsLinux() ? Global.AppName : serverInfo;
    }

    private async Task RefreshServersMenu()
    {
        var lstModel = await AppManager.Instance.ProfileModels(_config.SubIndexId, "");

        if (lstModel?.Count > _config.GuiItem.TrayMenuServersLimit)
        {
            BlServers = false;
            return;
        }

        var models = lstModel.Select(it => new ComboItem { ID = it.IndexId, Text = it.GetSummary() }).ToList();

        BlServers = true;
        Servers.ReplaceRange(models);

        // Update the ItemsSource before SelectedItem so a collection reset does not clear the tray selection.
        SelectedServer = models.FirstOrDefault(it => it.ID == _config.IndexId) ?? new();
    }

    private void ServerSelectedChanged()
    {
        if (SelectedServer == null)
        {
            return;
        }
        if (SelectedServer.ID.IsNullOrEmpty())
        {
            return;
        }
        SetDefaultServerRequested.Publish(SelectedServer.ID);
    }

    public async Task<AvailabilityCheckResult?> TestServerAvailability()
    {
        var item = await ConfigHandler.GetDefaultServer(_config);
        if (item == null)
        {
            return null;
        }

        await TestServerAvailabilitySub(ResUI.Speedtesting);

        // PattN: an Aether core still connecting is waited for within a test's budget, and reported rather than failed
        // when it still connects or is gone by then (critique 20, PattNG measureV2rayDelay)
        if (await AetherCoreManager.Instance.AwaitTestableAsync() is { } aetherNotReady)
        {
            NoticeManager.Instance.SendMessageEx(aetherNotReady);
            await TestServerAvailabilitySub(aetherNotReady);
            return new AvailabilityCheckResult(-1, Global.None);
        }

        var result = await Task.Run(ConnectionHandler.RunAvailabilityCheck);
        var msg = string.Format(ResUI.TestMeOutput, result.Time, result.Ip);

        var ip = result.GetValidIp();
        if (ip.IsNotEmpty())
        {
            ProfileExManager.Instance.SetTestIpInfo(item.IndexId, ip);
        }
        if (result.Time > 0)
        {
            ProfileExManager.Instance.SetTestDelay(item.IndexId, result.Time);
        }

        NoticeManager.Instance.SendMessageEx(msg);
        await TestServerAvailabilitySub(msg);
        return result;
    }

    private async Task TestServerAvailabilitySub(string msg)
    {
        RxSchedulers.MainThreadScheduler.Schedule(() =>
        {
            _ = TestServerAvailabilityResult(msg);
        });
        await Task.CompletedTask;
    }

    public async Task TestServerAvailabilityResult(string msg)
    {
        RunningInfoDisplay = msg;
        await Task.CompletedTask;
    }

    #region System proxy and Routings

    private async Task SetListenerType(ESysProxyType type)
    {
        if (_config.SystemProxyItem.SysProxyType == type)
        {
            return;
        }
        _config.SystemProxyItem.SysProxyType = type;
        await ChangeSystemProxyAsync(type, true);
        NoticeManager.Instance.SendMessageEx($"{ResUI.TipChangeSystemProxy} - {_config.SystemProxyItem.SysProxyType}");

        SystemProxySelected = (int)_config.SystemProxyItem.SysProxyType;
        await ConfigHandler.SaveConfig(_config);
    }

    public async Task ChangeSystemProxyAsync(ESysProxyType type, bool blChange)
    {
        await SysProxyHandler.UpdateSysProxy(_config, false);

        BlSystemProxyClear = type == ESysProxyType.ForcedClear;
        BlSystemProxySet = type == ESysProxyType.ForcedChange;
        BlSystemProxyNothing = type == ESysProxyType.Unchanged;
        BlSystemProxyPac = type == ESysProxyType.Pac;

        if (blChange)
        {
            await DispatcherRefreshIconInteraction.HandleSafe(RxVoid.Default);
        }
    }

    public async Task RefreshRoutingsMenu()
    {
        var routings = await AppManager.Instance.RoutingItems();

        RoutingItems.ReplaceRange(routings);

        SelectedRouting = routings.FirstOrDefault(t => t.IsActive == true);
    }

    private async Task RoutingSelectedChangedAsync()
    {
        if (SelectedRouting == null)
        {
            return;
        }

        var item = await AppManager.Instance.GetRoutingItem(SelectedRouting?.Id);
        if (item is null)
        {
            return;
        }

        if (await ConfigHandler.SetDefaultRouting(_config, item) == 0)
        {
            NoticeManager.Instance.SendMessageEx(ResUI.TipChangeRouting);
            ReloadRequested.Publish();
            await DispatcherRefreshIconInteraction.HandleSafe(RxVoid.Default);
        }
    }

    private async Task DoSystemProxySelected()
    {
        if (_config.SystemProxyItem.SysProxyType == (ESysProxyType)SystemProxySelected)
        {
            return;
        }
        await SetListenerType((ESysProxyType)SystemProxySelected);
    }

    private async Task DoEnableTun()
    {
        if (_config.TunModeItem.EnableTun == EnableTun)
        {
            return;
        }

        _config.TunModeItem.EnableTun = EnableTun;

        if (EnableTun && AllowEnableTun() == false)
        {
            // When running as a non-administrator, reboot to administrator mode
            if (Utils.IsWindows())
            {
                _config.TunModeItem.EnableTun = false;
                await AppManager.Instance.RebootAsAdmin();
                return;
            }
            else
            {
                var password = await PasswordInputInteraction.HandleSafe(RxVoid.Default);
                if (password.IsNullOrEmpty())
                {
                    _config.TunModeItem.EnableTun = false;
                    return;
                }
            }
        }

        await ConfigHandler.SaveConfig(_config);
        if (EnableTun && !IsConnected)
        {
            await DoConnect();
        }
        else
        {
            ReloadRequested.Publish();
        }
    }

    private bool AllowEnableTun()
    {
        if (Utils.IsWindows())
        {
            return Utils.IsAdministrator();
        }
        else if (Utils.IsLinux())
        {
            return AppManager.Instance.LinuxSudoPwd.IsNotEmpty();
        }
        else if (Utils.IsMacOS())
        {
            return AppManager.Instance.LinuxSudoPwd.IsNotEmpty();
        }
        return false;
    }

    private bool AllowEnableWinDivert()
    {
        // WinDivert is a windows only feature and needs administrator rights
        return Utils.IsWindows() && Utils.IsAdministrator();
    }

    private bool StartWinDivert()
    {
        var result = WinDivertService.Instance.Start(_config);
        BlWinDivert = result;
        if (!result)
        {
            Logging.SaveLog($"StatusBarViewModel, WinDivert: {WinDivertService.Instance.LastError}");
        }
        return result;
    }

    private async Task DoEnableWinDivert()
    {
        if (_config.WinDivertItem.Enable == EnableWinDivert)
        {
            return;
        }

        if (EnableWinDivert)
        {
            if (!Utils.IsWindows())
            {
                _config.WinDivertItem.Enable = false;
                EnableWinDivert = false;
                BlWinDivert = false;
                return;
            }

            if (!AllowEnableWinDivert())
            {
                // When running as a non-administrator, reboot to administrator mode
                _config.WinDivertItem.Enable = false;
                EnableWinDivert = false;
                BlWinDivert = false;
                await AppManager.Instance.RebootAsAdmin();
                return;
            }

            // The tun mode and the WinDivert mode can not be used at the same time
            if (_config.TunModeItem.EnableTun)
            {
                _config.TunModeItem.EnableTun = false;
                EnableTun = false;
            }

            if (!IsConnected)
            {
                _config.WinDivertItem.Enable = true;
                await ConfigHandler.SaveConfig(_config);
                await DoConnect();
                return;
            }

            if (!StartWinDivert())
            {
                _config.WinDivertItem.Enable = false;
                EnableWinDivert = false;
                BlWinDivert = false;
                await ConfigHandler.SaveConfig(_config);
                return;
            }
        }
        else
        {
            WinDivertService.Instance.Stop();
            BlWinDivert = false;
        }

        _config.WinDivertItem.Enable = EnableWinDivert;
        await ConfigHandler.SaveConfig(_config);
    }

    public async Task DoToggleConnect()
    {
        if (IsConnected)
        {
            await DoDisconnect();
        }
        else
        {
            await DoConnect();
        }
    }

    public async Task DoDisconnect()
    {
        if (!IsConnected)
        {
            return;
        }

        try
        {
            WinDivertService.Instance.Stop();
            await CoreManager.Instance.CoreStop();
            await SysProxyHandler.UpdateSysProxy(_config, true);

            IsConnected = false;
            SpeedProxyDisplay = string.Empty;
            SpeedDirectDisplay = string.Empty;
            RunningInfoDisplay = ResUI.TipDisconnected;
            RunningServerToolTipText = $"{Global.AppName} - {ResUI.TipDisconnected}";

            NoticeManager.Instance.SendMessageEx(ResUI.TipDisconnected);
            NoticeManager.Instance.Enqueue(ResUI.TipDisconnected);

            await DispatcherRefreshIconInteraction.HandleSafe(RxVoid.Default);
        }
        catch (Exception ex)
        {
            Logging.SaveLog("StatusBarViewModel.DoDisconnect", ex);
        }
    }

    public async Task DoConnect()
    {
        try
        {
            var server = await ConfigHandler.GetDefaultServer(_config);
            if (server == null)
            {
                NoticeManager.Instance.Enqueue(ResUI.CheckServerSettings);
                return;
            }

            IsConnected = true;

            ReloadRequested.Publish();

            if (_config.WinDivertItem.Enable && AllowEnableWinDivert())
            {
                StartWinDivert();
            }

            NoticeManager.Instance.SendMessageEx(ResUI.TipConnected);
            NoticeManager.Instance.Enqueue(ResUI.TipConnected);

            await DispatcherRefreshIconInteraction.HandleSafe(RxVoid.Default);
        }
        catch (Exception ex)
        {
            Logging.SaveLog("StatusBarViewModel.DoConnect", ex);
        }
    }

    #endregion System proxy and Routings

    #region UI

    public async Task InboundDisplayStatus()
    {
        StringBuilder sb = new();
        sb.Append($"[{EInboundProtocol.mixed}:{AppManager.Instance.GetLocalPort(EInboundProtocol.socks)}");
        if (_config.Inbound.First().SecondLocalPortEnabled)
        {
            sb.Append($",{AppManager.Instance.GetLocalPort(EInboundProtocol.socks2)}");
        }
        sb.Append(']');
        InboundDisplay = $"{ResUI.LabLocal}:{sb}";

        if (_config.Inbound.First().AllowLANConn)
        {
            var lan = _config.Inbound.First().NewPort4LAN
                ? $"[{EInboundProtocol.mixed}:{AppManager.Instance.GetLocalPort(EInboundProtocol.socks3)}]"
                : $"[{EInboundProtocol.mixed}:{AppManager.Instance.GetLocalPort(EInboundProtocol.socks)}]";
            InboundLanDisplay = $"{ResUI.LabLAN}:{lan}";
        }
        else
        {
            InboundLanDisplay = $"{ResUI.LabLAN}:{Global.None}";
        }
        await Task.CompletedTask;
    }

    public async Task UpdateStatistics(ServerSpeedItem update)
    {
        if (!_config.GuiItem.DisplayRealTimeSpeed || !IsConnected)
        {
            return;
        }

        try
        {
            if (AppManager.Instance.IsRunningCore(ECoreType.sing_box))
            {
                SpeedProxyDisplay = string.Format(ResUI.SpeedDisplayText, EInboundProtocol.mixed, Utils.HumanFy(update.ProxyUp), Utils.HumanFy(update.ProxyDown));
                SpeedDirectDisplay = string.Empty;
            }
            else
            {
                SpeedProxyDisplay = string.Format(ResUI.SpeedDisplayText, Global.ProxyTag, Utils.HumanFy(update.ProxyUp), Utils.HumanFy(update.ProxyDown));
                SpeedDirectDisplay = string.Format(ResUI.SpeedDisplayText, Global.DirectTag, Utils.HumanFy(update.DirectUp), Utils.HumanFy(update.DirectDown));
            }
        }
        catch
        {
        }
        await Task.CompletedTask;
    }

    #endregion UI
}
