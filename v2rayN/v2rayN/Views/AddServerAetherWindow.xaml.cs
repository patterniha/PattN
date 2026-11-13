namespace v2rayN.Views;

/// <summary>
/// PattN: the Aether editor (design 3.2), for an <see cref="AddServerAetherViewModel" />: every row is shown and enabled
/// as the view model decides, the lists are bound by index, and the questions of the view model are answered here.
/// </summary>
public partial class AddServerAetherWindow
{
    public AddServerAetherWindow()
    {
        InitializeComponent();

        Loaded += Window_Loaded;
        Closed += (_, _) => ViewModel?.OnClosed();
        Title = nameof(EConfigType.Aether);

        this.WhenActivated(disposables =>
        {
            // The fields that have view models of their own.
            this.OneWayBind(ViewModel, vm => vm.ExitNode, v => v.exitNodeField.ViewModel).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.FinalMask, v => v.presetFinalMask.ViewModel).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.Log, v => v.logPanel.ViewModel).DisposeWith(disposables);

            // The lists, before the entries they show. The lists of names are handed over as they are, not through
            // OneWayBind: that gives a list without an ItemTemplate or DisplayMemberPath ReactiveUI's view-model template
            // (AutoDataTemplateBindingHook), which shows a name, and the one chosen, as nothing.
            this.WhenAnyValue(v => v.ViewModel)
                .KeepNotNull()
                .Subscribe(vm =>
                {
                    cmbProtocol.ItemsSource = vm.ProtocolLabels;
                    cmbTransport.ItemsSource = vm.TransportLabels;
                    cmbEchDns.ItemsSource = vm.EchDnsOptions;
                    cmbEchDomain.ItemsSource = vm.EchDomainOptions;
                    cmbScanMode.ItemsSource = vm.ScanModeLabels;
                    cmbObfuscation.ItemsSource = vm.ObfuscationLabels;
                    cmbFingerprint.ItemsSource = vm.FingerprintLabels;
                    cmbPsiphon.ItemsSource = vm.PsiphonLabels;
                    cmbPsiphonMode.ItemsSource = vm.PsiphonModeLabels;
                    cmbTor.ItemsSource = vm.TorLabels;
                    cmbTorBridges.ItemsSource = vm.TorBridgesLabels;
                    cmbTorRelays.ItemsSource = vm.TorRelaysLabels;
                    cmbIpVersion.ItemsSource = vm.IpVersionLabels;
                    cmbTargetStrategy.ItemsSource = vm.TargetStrategyLabels;
                })
                .DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.PsiphonCdnSetOptions, v => v.lstPsiphonCdnSets.ItemsSource).DisposeWith(disposables);
            // The exit countries change as the editor reads them.
            this.WhenAnyValue(v => v.ViewModel!.PsiphonRegionLabels)
                .Subscribe(labels => cmbPsiphonRegion.ItemsSource = labels)
                .DisposeWith(disposables);

            // The fields, in PattNG's order.
            this.Bind(ViewModel, vm => vm.Remarks, v => v.txtRemarks.Text).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.ProtocolIndex, v => v.cmbProtocol.SelectedIndex).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.TransportIndex, v => v.cmbTransport.SelectedIndex).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.MasqueSni, v => v.txtMasqueSni.Text).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.Fragment, v => v.togFragment.IsChecked).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.FragmentSize, v => v.txtFragmentSize.Text).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.FragmentDelay, v => v.txtFragmentDelay.Text).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.Ech, v => v.togEch.IsChecked).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.EchDns, v => v.cmbEchDns.Text).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.EchDomain, v => v.cmbEchDomain.Text).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.ScanModeIndex, v => v.cmbScanMode.SelectedIndex).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.ObfuscationIndex, v => v.cmbObfuscation.SelectedIndex).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.FingerprintIndex, v => v.cmbFingerprint.SelectedIndex).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.DialMode, v => v.presetDialMode.ViewModel).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.PsiphonIndex, v => v.cmbPsiphon.SelectedIndex).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.PsiphonModeIndex, v => v.cmbPsiphonMode.SelectedIndex).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.PsiphonCdnIps, v => v.txtPsiphonCdnIps.Text).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.PsiphonCdnSni, v => v.txtPsiphonCdnSni.Text).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.PsiphonCdnSetsExpanded, v => v.expPsiphonCdnSets.IsExpanded).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.PsiphonCdnSetsSummary, v => v.txtPsiphonCdnSetsSummary.Text).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.PsiphonRegionIndex, v => v.cmbPsiphonRegion.SelectedIndex).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.PsiphonBundledList, v => v.togPsiphonBundledList.IsChecked).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.TorIndex, v => v.cmbTor.SelectedIndex).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.TorBridgesIndex, v => v.cmbTorBridges.SelectedIndex).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.TorRelaysIndex, v => v.cmbTorRelays.SelectedIndex).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.TorBridgeLines, v => v.txtTorBridgeLines.Text).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.WiwOuter, v => v.txtWiwOuter.Text).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.WiwInner, v => v.txtWiwInner.Text).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.Address, v => v.txtAddress.Text).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.Port, v => v.txtPort.Text).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.IpVersionIndex, v => v.cmbIpVersion.SelectedIndex).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.OtherSettingsExpanded, v => v.expOtherSettings.IsExpanded).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.Dns, v => v.txtDns.Text).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.ExitLoc, v => v.txtExitLoc.Text).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.TcpUserTimeout, v => v.txtTcpUserTimeout.Text).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.TargetStrategyIndex, v => v.cmbTargetStrategy.SelectedIndex).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.CommandText, v => v.txtCommand.Text).DisposeWith(disposables);

            // What the settings call for: the rows shown, the fields enabled.
            this.OneWayBind(ViewModel, vm => vm.WarpUsed, v => v.rowProtocol.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ShowTransport, v => v.rowTransport.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ShowTransport, v => v.rowMasqueSni.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ShowFragment, v => v.rowFragment.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ShowFragmentSizes, v => v.rowFragmentSize.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ShowFragmentSizes, v => v.rowFragmentDelay.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ShowEch, v => v.rowEch.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ShowEchFields, v => v.rowEchDns.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ShowEchFields, v => v.rowEchDomain.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.WarpUsed, v => v.rowScanMode.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ShowObfuscation, v => v.rowObfuscation.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ShowTransport, v => v.rowFingerprint.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ExitNode.IsFreedom, v => v.presetFinalMask.IsEnabled).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ExitNode.IsFreedom, v => v.presetDialMode.IsEnabled).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ShowPsiphonUnavailable, v => v.rowPsiphonUnavailable.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.PsiphonOn, v => v.rowPsiphonMode.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.PsiphonCdnShown, v => v.rowPsiphonCdnIps.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.PsiphonCdnSniShown, v => v.rowPsiphonCdnSni.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.PsiphonCdnShown, v => v.rowPsiphonCdnSets.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.PsiphonOn, v => v.rowPsiphonRegion.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.PsiphonOn, v => v.rowPsiphonBundledList.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.PsiphonOn, v => v.rowClearPsiphon.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ShowTorTransportsUnavailable, v => v.rowTorTransportsUnavailable.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.TorOn, v => v.rowTorBridges.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.TorRelaysShown, v => v.rowTorRelays.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.TorBridgeLinesShown, v => v.rowTorBridgeLines.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ShowHops, v => v.rowOuterHop.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ShowHops, v => v.rowInnerHop.Visibility, Shown).DisposeWith(disposables);
            this.WhenAnyValue(v => v.ViewModel!.InnerHopHint)
                .Subscribe(hint => MaterialDesignThemes.Wpf.HintAssist.SetHint(txtWiwInner, hint))
                .DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ShowEndpoint, v => v.rowAddress.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ShowEndpoint, v => v.rowPort.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.WarpUsed, v => v.rowIpVersion.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.WarpUsed, v => v.rowDns.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.WarpUsed, v => v.rowExitLoc.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ShowTcpUserTimeout, v => v.rowTcpUserTimeout.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ExitNode.IsFreedom, v => v.txtTcpUserTimeout.IsEnabled).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.WarpUsed, v => v.rowScan.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ShowScanBlocked, v => v.rowScanBlocked.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.CoreAvailable, v => v.rowCoreUnavailable.Visibility, available => Shown(!available)).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ScanText, v => v.btnScan.Content).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.IsScanning, v => v.barScanning.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.IsScanning, v => v.btnCancelScan.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.CommandIsCustom, v => v.panelCommandCustom.Visibility, Shown).DisposeWith(disposables);
            // A scan holds what these settings change: they wait for it to end.
            this.OneWayBind(ViewModel, vm => vm.NotScanning, v => v.cmbProtocol.IsEnabled).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.NotScanning, v => v.cmbPsiphon.IsEnabled).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.NotScanning, v => v.cmbTor.IsEnabled).DisposeWith(disposables);

            this.BindCommand(ViewModel, vm => vm.OpenKeysCmd, v => v.btnRenewKey).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.ClearPsiphonCmd, v => v.btnClearPsiphon).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.ScanCmd, v => v.btnScan).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.CancelScanCmd, v => v.btnCancelScan).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.UseSettingsCmd, v => v.btnUseSettings).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.SaveCmd, v => v.btnSave).DisposeWith(disposables);

            // A key the profile, or its scan, needs is missing: get it first, go on anyway, or neither. The WARP keys window
            // is not offered while a scan runs, which it waits for.
            ViewModel.KeysMissingInteraction.RegisterHandler(interaction =>
            {
                var question = interaction.Input;
                List<string> buttons = [question.Scan ? ResUI.TbAetherScanAnyway : ResUI.TbAetherSaveAnyway];
                if (question.CanGetKeys)
                {
                    buttons.Add(ResUI.TbAetherRenewKey);
                }
                buttons.Add(ResUI.TbCancel);
                var choice = UI.ShowChoice(Title, ResUI.MsgAetherKeysMissing, buttons, cancelIndex: buttons.Count - 1);
                interaction.SetOutput(choice == 0 ? EAetherKeysChoice.Anyway
                    : question.CanGetKeys && choice == 1 ? EAetherKeysChoice.GetKeys
                    : EAetherKeysChoice.Cancel);
            }).DisposeWith(disposables);

            // The WARP keys window, from "Get new WARP keys…" and from the missing-keys question: a new one each time,
            // which preselects nothing (PattNG). The editor shows the key status again once it is closed.
            ViewModel.OpenKeysInteraction.RegisterHandler(async interaction =>
            {
                await AppManager.Instance.WindowDialog.ShowDialogAsync(new AetherKeysViewModel());
                interaction.SetOutput(RxVoid.Default);
            }).DisposeWith(disposables);
        });

        WindowsUtils.SetDarkBorder(this, AppManager.Instance.Config.UiItem.CurrentTheme);
    }

    private static Visibility Shown(bool shown)
    {
        return shown ? Visibility.Visible : Visibility.Collapsed;
    }

    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        txtRemarks.Focus();
    }
}
