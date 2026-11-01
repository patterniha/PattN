namespace v2rayN.Views;

/// <summary>
/// PattN: the WARP keys window (design 3.4), for an <see cref="AetherKeysViewModel" />: its settings save as they change,
/// so it has a Close button only, and closing it while a run goes on cancels the run.
/// </summary>
public partial class AetherKeysWindow
{
    public AetherKeysWindow()
    {
        InitializeComponent();

        Closed += (_, _) => ViewModel?.OnClosed();

        this.WhenActivated(disposables =>
        {
            // The fields that have view models of their own.
            this.OneWayBind(ViewModel, vm => vm.ExitNode, v => v.exitNodeField.ViewModel).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.FinalMask, v => v.presetFinalMask.ViewModel).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.Log, v => v.logPanel.ViewModel).DisposeWith(disposables);

            // The lists, before the entries they show. The lists of names are handed over as they are, not through
            // OneWayBind: that gives a list without an ItemTemplate or DisplayMemberPath ReactiveUI's view-model template
            // (AutoDataTemplateBindingHook), which shows a name, and the one chosen, as nothing.
            this.OneWayBind(ViewModel, vm => vm.KindOptions, v => v.lstKinds.ItemsSource).DisposeWith(disposables);
            this.WhenAnyValue(v => v.ViewModel)
                .KeepNotNull()
                .Subscribe(vm =>
                {
                    cmbApiAddress.ItemsSource = vm.ApiNameOptions;
                    cmbApiSni.ItemsSource = vm.ApiNameOptions;
                    cmbApiHost.ItemsSource = vm.ApiNameOptions;
                    cmbEchDns.ItemsSource = vm.EchDnsOptions;
                    cmbEchDomain.ItemsSource = vm.EchDomainOptions;
                    cmbFingerprint.ItemsSource = vm.FingerprintLabels;
                })
                .DisposeWith(disposables);

            // The fields, in PattNG's order.
            this.Bind(ViewModel, vm => vm.ApiAddress, v => v.cmbApiAddress.Text).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.ApiSni, v => v.cmbApiSni.Text).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.ApiHost, v => v.cmbApiHost.Text).DisposeWith(disposables);
            // Under each API field the name of what it holds, as under a preset field: default while it is blank.
            this.OneWayBind(ViewModel, vm => vm.ApiAddressHeldName, v => v.txtApiAddressHeld.Text).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ApiAddressHeldName, v => v.txtApiAddressHeld.Visibility, name => Shown(!string.IsNullOrEmpty(name))).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ApiSniHeldName, v => v.txtApiSniHeld.Text).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ApiSniHeldName, v => v.txtApiSniHeld.Visibility, name => Shown(!string.IsNullOrEmpty(name))).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ApiHostHeldName, v => v.txtApiHostHeld.Text).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ApiHostHeldName, v => v.txtApiHostHeld.Visibility, name => Shown(!string.IsNullOrEmpty(name))).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.Fragment, v => v.togFragment.IsChecked).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.FragmentSize, v => v.txtFragmentSize.Text).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.FragmentDelay, v => v.txtFragmentDelay.Text).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.Ech, v => v.togEch.IsChecked).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.EchDns, v => v.cmbEchDns.Text).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.EchDomain, v => v.cmbEchDomain.Text).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.FingerprintIndex, v => v.cmbFingerprint.SelectedIndex).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.DialMode, v => v.presetDialMode.ViewModel).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.CommandText, v => v.txtCommand.Text).DisposeWith(disposables);

            // What the settings call for: the rows shown, the fields enabled; a run locks them all.
            this.OneWayBind(ViewModel, vm => vm.Fragment, v => v.rowFragmentSize.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.Fragment, v => v.rowFragmentDelay.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.Ech, v => v.rowEchDns.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.Ech, v => v.rowEchDomain.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ExitNode.IsFreedom, v => v.presetFinalMask.IsEnabled).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.ExitNode.IsFreedom, v => v.presetDialMode.IsEnabled).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.NotRenewing, v => v.panelSettings.IsEnabled).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.NotRenewing, v => v.txtCommand.IsEnabled).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.GetKeysText, v => v.btnGetKeys.Content).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.IsRenewing, v => v.barRenewing.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.IsRenewing, v => v.btnCancelRenew.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.Blocked, v => v.rowBlocked.Visibility, Shown).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.CoreAvailable, v => v.rowCoreUnavailable.Visibility, available => Shown(!available)).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.CommandIsCustom, v => v.panelCommandCustom.Visibility, Shown).DisposeWith(disposables);

            this.BindCommand(ViewModel, vm => vm.GetKeysCmd, v => v.btnGetKeys).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.CancelCmd, v => v.btnCancelRenew).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.UseSettingsCmd, v => v.btnUseSettings).DisposeWith(disposables);
        });

        WindowsUtils.SetDarkBorder(this, AppManager.Instance.Config.UiItem.CurrentTheme);
    }

    private static Visibility Shown(bool shown)
    {
        return shown ? Visibility.Visible : Visibility.Collapsed;
    }
}
