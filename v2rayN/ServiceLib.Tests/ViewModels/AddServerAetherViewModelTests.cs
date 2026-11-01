using System.Globalization;
using ReactiveUI.Primitives;
using ReactiveUI.Primitives.Extensions;
using ServiceLib.Tests.CoreConfig;
using ServiceLib.ViewModels;
using TUnit.Assertions.Enums;

namespace ServiceLib.Tests.ViewModels;

/// <summary>
/// PattN (design 3.2, stage 8): the Aether editor, from PattNG ServerUiStateTest (what the editor shows and what Save
/// stores), ServerAetherViewModelTest (the scan, the keys, the session, the log, the save) and AetherEditorRepositoryTest
/// (which session a scan disturbs). The editor reads and runs through a fake source: no test reaches the network, starts a
/// core or writes the database.
/// </summary>
[NotInParallel("AppManager config")]
public class AddServerAetherViewModelTests
{
    private static readonly AetherScanResult Found = new(new AetherEndpoint("162.159.197.3", 443));
    private static readonly AetherIdentity OldKey = new("a1b2c3d4e5f6", "172.16.0.2", "2606:4700:110:8a36::1");

    private sealed class FakeSource : IAetherEditorSource
    {
        public bool Available = true;
        public AetherProtocol? Session;
        public Func<ProfileItem, Action<string>, CancellationToken, Task<AetherRunResult<AetherScanResult>>> Scanner =
            (_, _, _) => Task.FromResult(new AetherRunResult<AetherScanResult>(AetherRunOutcome.Done));
        public Func<AetherPsiphonClear> Clearer = () => AetherPsiphonClear.Cleared;
        public List<string> Regions = [];
        public int Port = 10819;
        public HashSet<int> Taken = [.. AetherPorts.LocalPortsOf(10808), 10822];
        public readonly Dictionary<AetherProtocol, AetherIdentityStatus> Identities = [];
        public readonly HashSet<string> MissingFiles = [];

        /// <summary>When set, a look at the key files waits for it, as one off the UI thread takes its time.</summary>
        public TaskCompletionSource? KeysGate;

        /// <summary>When set, the look at the core folder waits for it.</summary>
        public TaskCompletionSource? AvailabilityGate;

        /// <summary>When set, a lookup of the exit-node waits for it, as one that builds a whole context takes its time.</summary>
        public TaskCompletionSource? LookupGate;

        public List<AetherExitNode> Nodes = [];
        public readonly Dictionary<string, ExitNodeLookup> Lookups = [];
        public readonly List<ProfileItem> Saved = [];
        public readonly List<ProfileItem> Scanned = [];
        public int Clears;
        public int KeyChecks;
        public int Lookups_;

        public int ListenPort => Port;
        public IReadOnlyCollection<int> TakenPorts => Taken;
        public AetherProtocol? SessionProtocol => Session;

        public event Action? SessionChanged;

        public void RaiseSessionChanged()
        {
            SessionChanged?.Invoke();
        }

        public bool Followed => SessionChanged != null;

        public async Task<AetherEditorAvailability> AvailabilityAsync()
        {
            if (AvailabilityGate is { } gate)
            {
                await gate.Task;
            }
            return new AetherEditorAvailability(Available, false, false);
        }

        public Task<List<string>> PsiphonRegionsAsync()
        {
            return Task.FromResult(Regions.ToList());
        }

        public Task<List<AetherExitNode>> ExitNodesAsync()
        {
            return Task.FromResult(Nodes.ToList());
        }

        public async Task<ExitNodeLookup> FindExitNodeAsync(string name)
        {
            Lookups_++;
            if (LookupGate is { } gate)
            {
                await gate.Task;
            }
            return Lookups.GetValueOrDefault(name) ?? ExitNodeLookup.NotFound.Instance;
        }

        public async Task<List<string>> MissingKeysAsync(IReadOnlyList<string> files)
        {
            KeyChecks++;
            if (KeysGate is { } gate)
            {
                await gate.Task;
            }
            return files.Where(MissingFiles.Contains).ToList();
        }

        public Task<AetherIdentityStatus> IdentityStatusAsync(AetherProtocol protocol)
        {
            return Task.FromResult(Identities.GetValueOrDefault(protocol) ?? new AetherIdentityStatus(protocol, null));
        }

        public Task<AetherRunResult<AetherScanResult>> ScanAsync(ProfileItem profile, Action<string> onOutput, CancellationToken ct)
        {
            Scanned.Add(profile);
            return Scanner(profile, onOutput, ct);
        }

        public Task<AetherPsiphonClear> ClearPsiphonDataAsync()
        {
            Clears++;
            return Task.FromResult(Clearer());
        }

        public Task<bool> SaveAsync(ProfileItem profile)
        {
            if (string.IsNullOrEmpty(profile.IndexId))
            {
                profile.IndexId = "saved-" + Saved.Count;
            }
            Saved.Add(profile);
            return Task.FromResult(true);
        }
    }

    /// <summary>A profile with the protocol extra <paramref name="extra" />.</summary>
    private static ProfileItem With(ProtocolExtraItem extra, string remarks = "warp")
    {
        var profile = new ProfileItem { ConfigType = EConfigType.Aether, Remarks = remarks, IsSub = false };
        profile.SetProtocolExtra(extra);
        return profile;
    }

    /// <summary>The editor of <paramref name="profile" /> on <paramref name="source" />, made where no UI thread is, and opened.</summary>
    private static async Task<AddServerAetherViewModel> Editor(FakeSource source, ProfileItem? profile = null)
    {
        var item = profile ?? With(new ProtocolExtraItem { AetherProtocol = AetherProtocol.Masque.Type });
        var vm = await Task.Run(() => ViewModelConfig.With(CoreConfigTestFactory.CreateConfig(), () => new AddServerAetherViewModel(item, source)));
        await vm.Initialized;
        return vm;
    }

    /// <summary>
    /// <paramref name="run" />, which a cancel or a close is to end, given ten seconds: one that never ends fails the test
    /// that waits for it rather than hang the run.
    /// </summary>
    private static Task Over(Task run)
    {
        return run.WaitAsync(TimeSpan.FromSeconds(10));
    }

    private static List<string> Texts(AddServerAetherViewModel vm)
    {
        return vm.Log.Entries.Select(entry => entry.Text).ToList();
    }

    /// <summary>Runs <paramref name="action" /> and gives the snackbar messages sent meanwhile; other tests may send some too.</summary>
    private static async Task<ConcurrentQueue<string>> Notices(Func<Task> action)
    {
        var shown = new ConcurrentQueue<string>();
        using (AppEvents.SendSnackMsgRequested.AsObservable().Subscribe(shown.Enqueue))
        {
            await action();
        }
        return shown;
    }

    #region what the editor shows (ServerUiStateTest)

    [Test]
    public async Task OptionsAreNormalizedToValuesTheListsKnow()
    {
        var vm = await Editor(new FakeSource(), With(new ProtocolExtraItem
        {
            AetherProtocol = "gool",
            AetherTransport = "h2",
            AetherScanMode = "from-a-newer-version",
            AetherObfuscation = null,
            AetherIpVersion = "both",
            AetherFingerprint = "lynx",
            AetherPsiphon = "sideways",
            AetherTor = "bogus",
        }));

        await vm.Protocol.Should().BeEqualTo(AetherProtocol.Gool);
        await vm.Transport.Should().BeEqualTo(AetherTransport.Http2);
        await vm.ScanModeLabels[vm.ScanModeIndex].Should().BeEqualTo(ResUI.TbAetherScanBalanced);
        await vm.ObfuscationLabels[vm.ObfuscationIndex].Should().BeEqualTo(ResUI.TbAetherNoizeAuto);
        await vm.IpVersionLabels[vm.IpVersionIndex].Should().BeEqualTo("IPv4 + IPv6");
        // A value no build wrote reads as Chrome's.
        await vm.FingerprintLabels[vm.FingerprintIndex].Should().BeEqualTo("Chrome");
        await vm.Psiphon.Should().BeEqualTo(AetherPsiphon.Off);
        await vm.Tor.Should().BeEqualTo(AetherTor.Off);
        // The verified mode of aether 2.1 read under its old name.
        var stealth = await Editor(new FakeSource(), With(new ProtocolExtraItem { AetherScanMode = AetherScanMode.Stealth }));
        await stealth.ScanModeLabels[stealth.ScanModeIndex].Should().BeEqualTo(ResUI.TbAetherScanVerified);
    }

    [Test]
    public async Task ANewProfileStartsWithTheDefaultsAndNoPort()
    {
        var vm = await Editor(new FakeSource(), new ProfileItem { ConfigType = EConfigType.Aether, IsSub = false });

        await vm.Protocol.Should().BeEqualTo(AetherProtocol.WireGuard);
        await vm.Transport.Should().BeEqualTo(AetherTransport.Http3);
        await vm.Port.Should().BeEqualTo(string.Empty);
        await vm.Address.Should().BeEqualTo(string.Empty);
        await vm.Remarks.Should().BeEqualTo(string.Empty);
        // Shown filled in, so that what the core is told is in sight.
        await vm.MasqueSni.Should().BeEqualTo("www.cloudflare.com");
        await vm.EchDns.Should().BeEqualTo("udp://1.1.1.1");
        await vm.EchDomain.Should().BeEqualTo("cloudflare-ech.com");
        await vm.Ech.Should().BeFalse();
        await vm.Fragment.Should().BeFalse();
        await vm.PsiphonBundledList.Should().BeTrue();
        await vm.ExitNode.Name.Should().BeEqualTo(string.Empty);
        await vm.ExitNode.IsFreedom.Should().BeTrue();
        await vm.FinalMask.Text.Should().BeEqualTo(string.Empty);
        await vm.DialMode.Text.Should().BeEqualTo(string.Empty);
        await vm.Command.Should().BeEqualTo(string.Empty);
        // The command box shows the command the settings build.
        await vm.CommandText.Should().BeEqualTo(vm.BuiltCommand);
        await vm.CommandIsCustom.Should().BeFalse();
        await vm.BuiltCommand.Should().StartWith("aether --bind 127.0.0.1:10819 --protocol wg");
    }

    [Test]
    public async Task AStoredPortShowsAsItIsAndNoneAsBlank()
    {
        var pinned = With(new ProtocolExtraItem { AetherProtocol = "wg" });
        pinned.Address = "162.159.192.1";
        pinned.Port = 2408;
        var vm = await Editor(new FakeSource(), pinned);
        await vm.Address.Should().BeEqualTo("162.159.192.1");
        await vm.Port.Should().BeEqualTo("2408");

        // Digits of another script count as the core reads them.
        vm.Port = "۲۴۰۸";
        await vm.ToProfileItem().Port.Should().BeEqualTo(2408);
        vm.Port = " ";
        await vm.ToProfileItem().Port.Should().BeEqualTo(0);
    }

    [Test]
    public async Task TheTargetStrategyFollowsTheDefaultAndIsStoredOnlyWhenOtherThanIt()
    {
        var vm = await Editor(new FakeSource());
        // None is chosen while the profile follows its default, which the list shows; through WARP it is ForceIPv4v6.
        await vm.TargetStrategy.Should().BeEqualTo(string.Empty);
        await vm.DefaultTargetStrategy.Should().BeEqualTo(AetherOutbound.ForceIPv4v6);
        await Global.TargetStrategies[vm.TargetStrategyIndex].Should().BeEqualTo(AetherOutbound.ForceIPv4v6);
        await vm.ToProfileItem().TargetStrategy.Should().BeEqualTo(string.Empty);

        // The list handing back the entry it shows is no choice.
        vm.TargetStrategyIndex = vm.TargetStrategyIndex;
        await vm.TargetStrategy.Should().BeEqualTo(string.Empty);

        // The default, chosen, is stored as none, so that the profile follows it.
        vm.TargetStrategy = AetherOutbound.ForceIPv4v6;
        await vm.ToProfileItem().TargetStrategy.Should().BeEqualTo(string.Empty);
        // AsIs is not its default, so it is stored as it is, and read back so (critique 5).
        vm.TargetStrategyIndex = Global.TargetStrategies.IndexOf(Global.AsIs);
        await vm.TargetStrategy.Should().BeEqualTo(Global.AsIs);
        var asIs = vm.ToProfileItem();
        await asIs.TargetStrategy.Should().BeEqualTo(Global.AsIs);
        var reopened = await Editor(new FakeSource(), asIs);
        await Global.TargetStrategies[reopened.TargetStrategyIndex].Should().BeEqualTo(Global.AsIs);
        await reopened.TargetStrategy.Should().BeEqualTo(Global.AsIs);

        vm.TargetStrategy = "UseIPv4v6";
        await vm.ToProfileItem().TargetStrategy.Should().BeEqualTo("UseIPv4v6");
    }

    [Test]
    public async Task TheDefaultTargetStrategyFollowsWhereTorAndPsiphonStand()
    {
        var vm = await Editor(new FakeSource());

        // Inside the tunnel, or alone, Tor and Psiphon carry the traffic last and look names up at their exit.
        foreach (var tor in new[] { AetherTor.Chain, AetherTor.Only })
        {
            vm.TorIndex = AetherTor.All.ToList().IndexOf(tor);
            await vm.DefaultTargetStrategy.Should().BeEqualTo(Global.AsIs).Because(tor.Type);
            await vm.ToProfileItem().TargetStrategy.Should().BeEqualTo(string.Empty).Because(tor.Type);
        }
        // Around the tunnel, they leave the traffic to WARP.
        vm.TorIndex = AetherTor.All.ToList().IndexOf(AetherTor.Reverse);
        await vm.DefaultTargetStrategy.Should().BeEqualTo(AetherOutbound.ForceIPv4v6);
        vm.TorIndex = 0;
        foreach (var psiphon in new[] { AetherPsiphon.Chain, AetherPsiphon.Only })
        {
            vm.PsiphonIndex = AetherPsiphon.All.ToList().IndexOf(psiphon);
            await vm.DefaultTargetStrategy.Should().BeEqualTo(Global.AsIs).Because(psiphon.Type);
        }
        vm.PsiphonIndex = AetherPsiphon.All.ToList().IndexOf(AetherPsiphon.Reverse);
        await vm.DefaultTargetStrategy.Should().BeEqualTo(AetherOutbound.ForceIPv4v6);

        // A choice is weighed against the default of the profile as it is saved: on one whose traffic leaves through Tor,
        // ForceIPv4v6 is stored, and AsIs is not.
        vm.PsiphonIndex = 0;
        vm.TorIndex = AetherTor.All.ToList().IndexOf(AetherTor.Chain);
        vm.TargetStrategy = AetherOutbound.ForceIPv4v6;
        await vm.ToProfileItem().TargetStrategy.Should().BeEqualTo(AetherOutbound.ForceIPv4v6);
        vm.TargetStrategy = Global.AsIs;
        await vm.ToProfileItem().TargetStrategy.Should().BeEqualTo(string.Empty);
    }

    [Test]
    public async Task ACommandOfItsOwnSaysWhereTheTrafficLeaves()
    {
        var vm = await Editor(new FakeSource { Port = 20808 });
        var built = vm.BuiltCommand;

        // The settings leave through WARP, the command through Tor; the command runs, so the traffic leaves through Tor.
        vm.CommandText = $"{built} --tor";
        await vm.DefaultTargetStrategy.Should().BeEqualTo(Global.AsIs);
        var stored = vm.ToProfileItem();
        await stored.GetProtocolExtra().AetherCommand.Should().BeEqualTo($"{built} --tor");
        await stored.TargetStrategy.Should().BeEqualTo(string.Empty);
        vm.TargetStrategy = AetherOutbound.ForceIPv4v6;
        await vm.ToProfileItem().TargetStrategy.Should().BeEqualTo(AetherOutbound.ForceIPv4v6);
    }

    [Test]
    public async Task ACommandIsStoredOnlyWhenItSaysMoreThanTheSettings()
    {
        var vm = await Editor(new FakeSource());
        await vm.ToProfileItem().GetProtocolExtra().AetherCommand.Should().BeNull();

        // The command the settings build, typed back in, is no command of its own.
        var built = vm.BuiltCommand;
        vm.Command = $" {built} ";
        await vm.ToProfileItem().GetProtocolExtra().AetherCommand.Should().BeNull();
        await vm.CommandIsCustom.Should().BeFalse();

        vm.CommandText = $"{built} --dns 1.1.1.1";
        await vm.CommandIsCustom.Should().BeTrue();
        await vm.ToProfileItem().GetProtocolExtra().AetherCommand.Should().BeEqualTo($"{built} --dns 1.1.1.1");
        var reopened = await Editor(new FakeSource(), vm.ToProfileItem());
        await reopened.Command.Should().BeEqualTo($"{built} --dns 1.1.1.1");
        await reopened.CommandText.Should().BeEqualTo($"{built} --dns 1.1.1.1");

        // "Use the settings" goes back to the command the settings build.
        await vm.UseSettingsCmd.Execute().ToTask();
        await vm.Command.Should().BeEqualTo(string.Empty);
        await vm.CommandText.Should().BeEqualTo(vm.BuiltCommand);
        // The box handing back the command it shows is no edit.
        vm.CommandText = vm.BuiltCommand;
        await vm.Command.Should().BeEqualTo(string.Empty);
    }

    [Test]
    public async Task ACommandIsWeighedOnTheListenPortOfTheSettings()
    {
        var on20808 = await Editor(new FakeSource { Port = 20808 });
        var built = on20808.BuiltCommand;
        await built.Should().Contain("127.0.0.1:20808");
        on20808.Command = built;
        await on20808.ToProfileItem().GetProtocolExtra().AetherCommand.Should().BeNull();

        // On another port the same words say something else than the settings do.
        var on10819 = await Editor(new FakeSource { Port = 10819 });
        on10819.Command = built;
        await on10819.ToProfileItem().GetProtocolExtra().AetherCommand.Should().BeEqualTo(built);
        // Kept as typed, it stays whatever it says.
        on20808.Command = built;
        await on20808.ToProfileItem(keepCommand: true).GetProtocolExtra().AetherCommand.Should().BeEqualTo(built);
    }

    [Test]
    public async Task PsiphonIsOffByDefaultAndItsSettingsAreStoredOnlyWhileItIsOn()
    {
        var vm = await Editor(new FakeSource());
        await vm.PsiphonModeLabels[vm.PsiphonModeIndex].Should().BeEqualTo(ResUI.TbAetherPsiphonModeAuto);
        await vm.ToProfileItem().GetProtocolExtra().AetherPsiphon.Should().BeNull();

        vm.PsiphonModeIndex = AetherPsiphonMode.All.ToList().IndexOf(AetherPsiphonMode.Cdn);
        vm.PsiphonRegion = "DE";
        vm.PsiphonBundledList = false;
        // Settings of a Psiphon that is off are not kept.
        var off = vm.ToProfileItem().GetProtocolExtra();
        await off.AetherPsiphonMode.Should().BeNull();
        await off.AetherPsiphonRegion.Should().BeNull();
        await off.AetherPsiphonBundledList.Should().BeNull();

        vm.PsiphonIndex = AetherPsiphon.All.ToList().IndexOf(AetherPsiphon.Chain);
        var stored = vm.ToProfileItem();
        var extra = stored.GetProtocolExtra();
        await extra.AetherPsiphon.Should().BeEqualTo("chain");
        await extra.AetherPsiphonMode.Should().BeEqualTo("cdn");
        await extra.AetherPsiphonRegion.Should().BeEqualTo("DE");
        await extra.AetherPsiphonBundledList.Should().BeEqualTo(false);
        await extra.AetherPsiphonCdnIps.Should().BeNull();

        var reopened = await Editor(new FakeSource(), stored);
        await reopened.Psiphon.Should().BeEqualTo(AetherPsiphon.Chain);
        await reopened.PsiphonMode.Should().BeEqualTo(AetherPsiphonMode.Cdn);
        await reopened.PsiphonRegion.Should().BeEqualTo("DE");
        await reopened.PsiphonBundledList.Should().BeFalse();
        // On is the default and is stored as nothing.
        reopened.PsiphonBundledList = true;
        await reopened.ToProfileItem().GetProtocolExtra().AetherPsiphonBundledList.Should().BeNull();
    }

    [Test]
    public async Task TorIsOffByDefaultAndItsSettingsAreStoredOnlyWhileItIsOn()
    {
        var vm = await Editor(new FakeSource());
        await vm.TorBridges.Should().BeEqualTo(AetherTorBridges.Auto);
        await vm.ToProfileItem().GetProtocolExtra().AetherTor.Should().BeNull();

        vm.TorBridgesIndex = AetherTorBridges.All.ToList().IndexOf(AetherTorBridges.Own);
        vm.TorBridgeLines = "obfs4 192.0.2.55:38114 316E64 cert=abc iat-mode=0";
        vm.TorRelaysIndex = AetherTorRelays.All.ToList().IndexOf(AetherTorRelays.Only);
        await vm.ToProfileItem().GetProtocolExtra().AetherTorBridges.Should().BeNull();
        await vm.ToProfileItem().GetProtocolExtra().AetherTorBridgeLines.Should().BeNull();
        await vm.ToProfileItem().GetProtocolExtra().AetherTorRelays.Should().BeNull();

        vm.TorIndex = AetherTor.All.ToList().IndexOf(AetherTor.Reverse);
        var stored = vm.ToProfileItem();
        await stored.GetProtocolExtra().AetherTor.Should().BeEqualTo("reverse");
        await stored.GetProtocolExtra().AetherTorBridges.Should().BeEqualTo("own");
        await stored.GetProtocolExtra().AetherTorBridgeLines.Should().BeEqualTo("obfs4 192.0.2.55:38114 316E64 cert=abc iat-mode=0");
        await stored.GetProtocolExtra().AetherTorRelays.Should().BeEqualTo("only");

        var reopened = await Editor(new FakeSource(), stored);
        await reopened.Tor.Should().BeEqualTo(AetherTor.Reverse);
        await reopened.TorBridges.Should().BeEqualTo(AetherTorBridges.Own);
        await reopened.TorBridgeLines.Should().BeEqualTo("obfs4 192.0.2.55:38114 316E64 cert=abc iat-mode=0");
    }

    [Test]
    public async Task TheTuningFieldsStartEmptyAndAreStoredOnlyWhenSet()
    {
        var vm = await Editor(new FakeSource());
        var stored = vm.ToProfileItem().GetProtocolExtra();
        await stored.AetherEch.Should().BeEqualTo(false);
        await stored.AetherFragment.Should().BeEqualTo(false);
        await stored.AetherDns.Should().BeNull();
        await stored.AetherExitLoc.Should().BeNull();
        await stored.AetherFragmentSize.Should().BeNull();

        vm.Ech = true;
        vm.Dns = "1.1.1.1";
        vm.ExitLoc = "!IR";
        vm.Fragment = true;
        vm.FragmentSize = "8-16";
        var tuned = vm.ToProfileItem().GetProtocolExtra();
        await tuned.AetherEch.Should().BeEqualTo(true);
        await tuned.AetherDns.Should().BeEqualTo("1.1.1.1");
        await tuned.AetherExitLoc.Should().BeEqualTo("!IR");
        await tuned.AetherFragment.Should().BeEqualTo(true);
        await tuned.AetherFragmentSize.Should().BeEqualTo("8-16");

        var reopened = await Editor(new FakeSource(), vm.ToProfileItem());
        await reopened.Ech.Should().BeTrue();
        await reopened.Dns.Should().BeEqualTo("1.1.1.1");
        await reopened.ExitLoc.Should().BeEqualTo("!IR");
        await reopened.FragmentSize.Should().BeEqualTo("8-16");
    }

    [Test]
    public async Task TheExitNodeIsTheNameOfAProfileAndIsStoredOnlyWhenOneIsChosen()
    {
        var vm = await Editor(new FakeSource());
        await vm.ToProfileItem().GetProtocolExtra().AetherExitNode.Should().BeNull();

        vm.ExitNode.Name = "germany";
        var chosen = vm.ToProfileItem();
        await chosen.GetProtocolExtra().AetherExitNode.Should().BeEqualTo("germany");
        await (await Editor(new FakeSource(), chosen)).ExitNode.Name.Should().BeEqualTo("germany");
        // The finalMask and the dialMode set before are kept, out of use, for freedom again.
        vm.FinalMask.Text = """{"tcp": []}""";
        vm.DialMode.Text = "custom";
        await vm.ToProfileItem().Finalmask.Should().BeEqualTo("""{"tcp": []}""");
        await vm.ToProfileItem().DialMode.Should().BeEqualTo("custom");
        await vm.ExitNode.IsFreedom.Should().BeFalse();
        vm.ExitNode.Name = " ";
        await vm.ExitNode.IsFreedom.Should().BeTrue();
        await vm.ToProfileItem().GetProtocolExtra().AetherExitNode.Should().BeNull();
    }

    [Test]
    public async Task TheCdnSetsAreChosenOneByOneAndStoredInTheOrderTheCoreTriesThem()
    {
        var vm = await Editor(new FakeSource(), With(new ProtocolExtraItem { AetherProtocol = "masque", AetherPsiphon = "chain" }));
        await vm.PsiphonCdnSetOptions.Count(option => option.IsChecked).Should().BeEqualTo(0);
        await vm.PsiphonCdnSetsSummary.Should().BeEqualTo(ResUI.TbAetherPsiphonCdnSetsAll);
        await vm.PsiphonCdnSetsExpanded.Should().BeFalse();

        vm.PsiphonCdnSetOptions.Single(option => option.Set == AetherPsiphonCdnSet.Fastly).IsChecked = true;
        vm.PsiphonCdnSetOptions.Single(option => option.Set == AetherPsiphonCdnSet.Cloudflare).IsChecked = true;
        await vm.ToProfileItem().GetProtocolExtra().AetherPsiphonCdnSets.Should().BeEqualTo("cloudflare,fastly");
        await vm.PsiphonCdnSetsSummary.Should().BeEqualTo($"{ResUI.TbAetherCdnSetCloudflare}, {ResUI.TbAetherCdnSetFastly}");

        vm.PsiphonCdnSetOptions.Single(option => option.Set == AetherPsiphonCdnSet.Fastly).IsChecked = false;
        await vm.PsiphonCdnSets.Should().BeEqualTo("cloudflare");
        vm.SetPsiphonCdnSet(AetherPsiphonCdnSet.Cloudflare, false);
        await vm.ToProfileItem().GetProtocolExtra().AetherPsiphonCdnSets.Should().BeNull();
        // The boxes show the choice however it was made.
        await vm.PsiphonCdnSetOptions.Any(option => option.IsChecked).Should().BeFalse();
        vm.SetPsiphonCdnSet(AetherPsiphonCdnSet.Github, true);
        await vm.PsiphonCdnSetOptions.Single(option => option.IsChecked).Set.Should().BeEqualTo(AetherPsiphonCdnSet.Github);
        vm.SetPsiphonCdnSet(AetherPsiphonCdnSet.Github, false);

        // A choice from before comes back as it was, folded open, and goes with Psiphon when Psiphon goes.
        var reopened = await Editor(new FakeSource(), With(new ProtocolExtraItem
        {
            AetherProtocol = "masque",
            AetherPsiphon = "chain",
            AetherPsiphonCdnSets = "github,vercel",
        }));
        await reopened.PsiphonCdnSetOptions.Where(option => option.IsChecked).Select(option => option.Set).ToList()
            .Should().BeEquivalentTo([AetherPsiphonCdnSet.Vercel, AetherPsiphonCdnSet.Github], CollectionOrdering.Matching);
        await reopened.PsiphonCdnSetsExpanded.Should().BeTrue();
        reopened.PsiphonIndex = 0;
        await reopened.ToProfileItem().GetProtocolExtra().AetherPsiphonCdnSets.Should().BeNull();
    }

    [Test]
    public async Task TheExitCountriesOnOfferComeFromTheListAndKeepTheOneTheProfileHolds()
    {
        var vm = await Editor(new FakeSource(), With(new ProtocolExtraItem { AetherProtocol = "masque", AetherPsiphon = "chain" }));
        await vm.PsiphonRegionLabels.Should().BeEquivalentTo([ResUI.TbAetherPsiphonRegionAny], CollectionOrdering.Matching);
        await vm.PsiphonRegionIndex.Should().BeEqualTo(0);

        var listed = await Editor(new FakeSource { Regions = ["DE", "US"] }, With(new ProtocolExtraItem
        {
            AetherProtocol = "masque",
            AetherPsiphon = "chain",
            AetherPsiphonRegion = "ir",
        }));
        // Any country first; a country the profile holds that the list lacks stays on offer.
        await listed.PsiphonRegionLabels.Count.Should().BeEqualTo(4);
        await listed.PsiphonRegionLabels[0].Should().BeEqualTo(ResUI.TbAetherPsiphonRegionAny);
        await listed.PsiphonRegionLabels[listed.PsiphonRegionIndex].Should().EndWith("(IR)");
        listed.PsiphonRegionIndex = listed.PsiphonRegionLabels.ToList().FindIndex(label => label.EndsWith("(DE)"));
        await listed.PsiphonRegion.Should().BeEqualTo("DE");
        listed.PsiphonRegionIndex = 0;
        await listed.PsiphonRegion.Should().BeEqualTo(string.Empty);
        await listed.ToProfileItem().GetProtocolExtra().AetherPsiphonRegion.Should().BeNull();
    }

    // VM-1: PattNG names them with getDisplayCountry(locale); RegionInfo.DisplayName would give each country's own name.
    [Test]
    public async Task TheExitCountriesAreNamedAndSortedInTheLanguageOfTheApp()
    {
        var before = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("en-US");
            var english = await Editor(new FakeSource { Regions = ["JP", "DE", "IR"] }, With(new ProtocolExtraItem
            {
                AetherProtocol = "masque",
                AetherPsiphon = "chain",
                AetherPsiphonRegion = "de",
            }));
            await english.PsiphonRegionLabels.Skip(1).ToList().Should().BeEquivalentTo(["Germany (DE)", "Iran (IR)", "Japan (JP)"], CollectionOrdering.Matching);
            await english.PsiphonRegionLabels[english.PsiphonRegionIndex].Should().BeEqualTo("Germany (DE)");

            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("fa-IR");
            var persian = await Editor(new FakeSource { Regions = ["DE"] }, With(new ProtocolExtraItem { AetherProtocol = "masque", AetherPsiphon = "chain" }));
            await persian.PsiphonRegionLabels[1].Should().BeEqualTo("\u0622\u0644\u0645\u0627\u0646 (DE)");
        }
        finally
        {
            CultureInfo.CurrentUICulture = before;
        }
        // The name inside the parentheses that end the name of a culture of no language, which may hold their own.
        await AddServerAetherViewModel.InParentheses("Unknown language (Germany)").Should().BeEqualTo("Germany");
        await AddServerAetherViewModel.InParentheses("Unknown language (Myanmar (Burma)) ").Should().BeEqualTo("Myanmar (Burma)");
        await AddServerAetherViewModel.InParentheses("\u672a\u77e5\u8bed\u8a00\uff08\u5fb7\u56fd\uff09").Should().BeEqualTo("\u5fb7\u56fd");
        await AddServerAetherViewModel.InParentheses("Germany").Should().BeNull();
        await AddServerAetherViewModel.InParentheses("Unknown language ()").Should().BeNull();
        await AddServerAetherViewModel.InParentheses(null).Should().BeNull();
    }

    [Test]
    public async Task TheFoldedSettingsAnnounceThemselvesOnlyWhenOneHoldsAValue()
    {
        var vm = await Editor(new FakeSource());
        await vm.HasOtherSettings.Should().BeFalse();
        await vm.OtherSettingsExpanded.Should().BeFalse();

        // The IP version stands outside the fold, so it does not count.
        vm.IpVersionIndex = 2;
        await vm.HasOtherSettings.Should().BeFalse();
        vm.Dns = "1.1.1.1";
        await vm.HasOtherSettings.Should().BeTrue();
        vm.Dns = string.Empty;
        vm.ExitLoc = "!IR";
        await vm.HasOtherSettings.Should().BeTrue();
        vm.ExitLoc = string.Empty;
        vm.TargetStrategy = "UseIPv4v6";
        await vm.HasOtherSettings.Should().BeTrue();
        // AsIs is no default of Aether's: it counts as a setting of its own.
        vm.TargetStrategy = Global.AsIs;
        await vm.HasOtherSettings.Should().BeTrue();
        vm.TargetStrategy = AetherOutbound.ForceIPv4v6;
        await vm.HasOtherSettings.Should().BeFalse();
        // Where Tor carries the traffic last, AsIs is the default, and ForceIPv4v6 a setting of its own.
        vm.TorIndex = AetherTor.All.ToList().IndexOf(AetherTor.Chain);
        await vm.HasOtherSettings.Should().BeTrue();
        vm.TargetStrategy = Global.AsIs;
        await vm.HasOtherSettings.Should().BeFalse();
        vm.TorIndex = 0;
        vm.TargetStrategy = string.Empty;
        // The exit-node's finalMask and dialMode stand outside the fold.
        vm.FinalMask.Text = """{"tcp": []}""";
        vm.DialMode.Text = "custom";
        await vm.HasOtherSettings.Should().BeFalse();

        // A profile that holds one opens with the fold open.
        var dns = await Editor(new FakeSource(), With(new ProtocolExtraItem { AetherDns = "1.1.1.1" }));
        await dns.OtherSettingsExpanded.Should().BeTrue();
    }

    [Test]
    public async Task TheFingerprintStartsAsChromesAndIsStoredAsChosen()
    {
        var vm = await Editor(new FakeSource());
        await vm.FingerprintLabels[vm.FingerprintIndex].Should().BeEqualTo("Chrome");
        vm.FingerprintIndex = AetherFingerprint.All.ToList().IndexOf(AetherFingerprint.Go);
        var stored = vm.ToProfileItem();
        await stored.GetProtocolExtra().AetherFingerprint.Should().BeEqualTo("go");
        var reopened = await Editor(new FakeSource(), stored);
        await reopened.FingerprintLabels[reopened.FingerprintIndex].Should().BeEqualTo("Go");
    }

    [Test]
    public async Task TheEchResolverAndDomainAreKeptWhetherEchIsOnOrOff()
    {
        var vm = await Editor(new FakeSource());
        vm.EchDns = "https://doq.dns4all.eu/dns-query";
        vm.EchDomain = "ip.gs";
        foreach (var ech in new[] { true, false })
        {
            vm.Ech = ech;
            var stored = vm.ToProfileItem();
            await stored.GetProtocolExtra().AetherEchDns.Should().BeEqualTo("https://doq.dns4all.eu/dns-query");
            await stored.GetProtocolExtra().AetherEchDomain.Should().BeEqualTo("ip.gs");
            var reopened = await Editor(new FakeSource(), stored);
            await reopened.Ech.Should().BeEqualTo(ech);
            await reopened.EchDns.Should().BeEqualTo("https://doq.dns4all.eu/dns-query");
            await reopened.EchDomain.Should().BeEqualTo("ip.gs");
        }
        // A field left empty is the default again.
        vm.EchDns = " ";
        await vm.ToProfileItem().GetProtocolExtra().AetherEchDns.Should().BeNull();
        await (await Editor(new FakeSource(), vm.ToProfileItem())).EchDns.Should().BeEqualTo("udp://1.1.1.1");
    }

    [Test]
    public async Task TheMasqueServerNameIsKeptWhateverTheProtocol()
    {
        var vm = await Editor(new FakeSource());
        vm.MasqueSni = "consumer-masque.cloudflareclient.com";
        foreach (var protocol in AetherProtocol.All)
        {
            vm.ProtocolIndex = AetherProtocol.All.ToList().IndexOf(protocol);
            var stored = vm.ToProfileItem();
            await stored.GetProtocolExtra().AetherMasqueSni.Should().BeEqualTo("consumer-masque.cloudflareclient.com").Because(protocol.Type);
        }
        vm.MasqueSni = " ";
        await vm.ToProfileItem().GetProtocolExtra().AetherMasqueSni.Should().BeNull();
        await (await Editor(new FakeSource(), vm.ToProfileItem())).MasqueSni.Should().BeEqualTo("www.cloudflare.com");
    }

    [Test]
    public async Task TheProfileHeldIsBuiltAgainEqualWhileItsChecksNormalizeACopy()
    {
        var vm = await Editor(new FakeSource { Port = 20808 });
        var held = vm.ToProfileItem();
        var checkedCopy = JsonUtils.DeepCopy(held)!;
        await AetherFmt.Normalize(checkedCopy, null, 20808).Should().BeNull();
        // Normalized, the default ECH resolver is left out, but the profile held keeps it.
        await checkedCopy.GetProtocolExtra().AetherEchDns.Should().BeNull();
        await held.GetProtocolExtra().AetherEchDns.Should().BeEqualTo("udp://1.1.1.1");
        await AddServerAetherViewModel.HoldsChecked(vm.ToProfileItem(), held, 20808).Should().BeTrue();
        vm.Remarks = "edited";
        await AddServerAetherViewModel.HoldsChecked(vm.ToProfileItem(), held, 20808).Should().BeFalse();
    }

    [Test]
    public async Task TheEditorHoldsTheProfileCheckedUntilItIsEdited()
    {
        var checkedProfile = With(new ProtocolExtraItem { AetherProtocol = "masque" });
        await AddServerAetherViewModel.HoldsChecked(JsonUtils.DeepCopy(checkedProfile)!, checkedProfile, 10819).Should().BeTrue();
        var edited = JsonUtils.DeepCopy(checkedProfile)!;
        edited.Remarks = "edited";
        await AddServerAetherViewModel.HoldsChecked(edited, checkedProfile, 10819).Should().BeFalse();
        var wireGuard = With(new ProtocolExtraItem { AetherProtocol = "wg" });
        await AddServerAetherViewModel.HoldsChecked(wireGuard, checkedProfile, 10819).Should().BeFalse();
        // A cleared ECH resolver is the default once saved: the two are one.
        var cleared = With(new ProtocolExtraItem { AetherProtocol = "masque", AetherEch = true });
        var defaulted = With(new ProtocolExtraItem { AetherProtocol = "masque", AetherEch = true, AetherEchDns = "udp://1.1.1.1" });
        await AddServerAetherViewModel.HoldsChecked(defaulted, cleared, 10819).Should().BeTrue();
        var other = With(new ProtocolExtraItem { AetherProtocol = "masque", AetherEch = true, AetherEchDns = "udp://9.9.9.9" });
        await AddServerAetherViewModel.HoldsChecked(other, cleared, 10819).Should().BeFalse();
    }

    [Test]
    public async Task EachProtocolAndCarrierShowsItsOwnFields()
    {
        var vm = await Editor(new FakeSource(), With(new ProtocolExtraItem { AetherProtocol = "wg" }));
        // WireGuard: no transport, SNI, fragment, ECH or fingerprint; an address and a port.
        await vm.WarpUsed.Should().BeTrue();
        await vm.ShowTransport.Should().BeFalse();
        await vm.ShowFragment.Should().BeFalse();
        await vm.ShowEch.Should().BeFalse();
        await vm.ShowObfuscation.Should().BeTrue();
        await vm.ShowEndpoint.Should().BeTrue();
        await vm.ShowHops.Should().BeFalse();

        // MASQUE over HTTP/3: transport, SNI, ECH and fingerprint, obfuscation, no fragment.
        vm.ProtocolIndex = AetherProtocol.All.ToList().IndexOf(AetherProtocol.Masque);
        await vm.ShowTransport.Should().BeTrue();
        await vm.ShowEch.Should().BeTrue();
        await vm.ShowEchFields.Should().BeFalse();
        await vm.ShowObfuscation.Should().BeTrue();
        await vm.ShowFragment.Should().BeFalse();
        vm.Ech = true;
        await vm.ShowEchFields.Should().BeTrue();

        // Over HTTP/2 chosen: the fragment, and no obfuscation.
        vm.TransportIndex = AetherTransport.All.ToList().IndexOf(AetherTransport.Http2);
        await vm.ShowFragment.Should().BeTrue();
        await vm.ShowFragmentSizes.Should().BeFalse();
        vm.Fragment = true;
        await vm.ShowFragmentSizes.Should().BeTrue();
        await vm.ShowObfuscation.Should().BeFalse();

        // HTTP/2 forced by Tor around the tunnel: no obfuscation, and no fragment, which the transport chosen takes.
        vm.TransportIndex = AetherTransport.All.ToList().IndexOf(AetherTransport.Http3);
        vm.TorIndex = AetherTor.All.ToList().IndexOf(AetherTor.Reverse);
        await vm.ShowObfuscation.Should().BeFalse();
        await vm.ShowFragment.Should().BeFalse();
        await vm.TorOn.Should().BeTrue();
        await vm.TorRelaysShown.Should().BeTrue();
        await vm.TorBridgeLinesShown.Should().BeFalse();
        vm.TorBridgesIndex = AetherTorBridges.All.ToList().IndexOf(AetherTorBridges.Own);
        await vm.TorRelaysShown.Should().BeFalse();
        await vm.TorBridgeLinesShown.Should().BeTrue();
        // Without lyrebird, bridges cannot be used.
        await vm.ShowTorTransportsUnavailable.Should().BeTrue();
        vm.TorBridgesIndex = AetherTorBridges.All.ToList().IndexOf(AetherTorBridges.Never);
        await vm.ShowTorTransportsUnavailable.Should().BeFalse();
        // Inside the tunnel, Tor asks for no bridges unless told to.
        vm.TorIndex = AetherTor.All.ToList().IndexOf(AetherTor.Chain);
        vm.TorBridgesIndex = AetherTorBridges.All.ToList().IndexOf(AetherTorBridges.Auto);
        await vm.ShowTorTransportsUnavailable.Should().BeFalse();

        // Tor alone: no WARP tunnel, nothing about one to set.
        vm.TorIndex = AetherTor.All.ToList().IndexOf(AetherTor.Only);
        await vm.WarpUsed.Should().BeFalse();
        await vm.ShowTransport.Should().BeFalse();
        await vm.ShowObfuscation.Should().BeFalse();
        await vm.ShowEndpoint.Should().BeFalse();
        await vm.ShowHops.Should().BeFalse();
        vm.TorIndex = 0;

        // Psiphon alone likewise; without the client, it says so; the CDN fields only where fronting is used.
        vm.PsiphonIndex = AetherPsiphon.All.ToList().IndexOf(AetherPsiphon.Only);
        await vm.WarpUsed.Should().BeFalse();
        await vm.PsiphonOn.Should().BeTrue();
        await vm.ShowPsiphonUnavailable.Should().BeTrue();
        await vm.PsiphonCdnShown.Should().BeTrue();
        await vm.PsiphonCdnSniShown.Should().BeFalse();
        vm.PsiphonCdnIps = "104.16.0.1";
        await vm.PsiphonCdnSniShown.Should().BeTrue();
        vm.PsiphonModeIndex = AetherPsiphonMode.All.ToList().IndexOf(AetherPsiphonMode.Direct);
        await vm.PsiphonCdnShown.Should().BeFalse();
        await vm.PsiphonCdnSniShown.Should().BeFalse();
        vm.PsiphonIndex = 0;

        // Two hops in place of an address and a port; WireGuard over MASQUE's inner one is the endpoint WARP assigns.
        foreach (var protocol in new[] { AetherProtocol.Gool, AetherProtocol.Mim, AetherProtocol.WgOverMasque })
        {
            vm.ProtocolIndex = AetherProtocol.All.ToList().IndexOf(protocol);
            await vm.ShowHops.Should().BeTrue().Because(protocol.Type);
            await vm.ShowEndpoint.Should().BeFalse().Because(protocol.Type);
            await vm.InnerHopHint.Should().BeEqualTo(protocol == AetherProtocol.WgOverMasque ? ResUI.TbAetherGoolPeerHint : ResUI.TbAetherEndpointHint);
        }
    }

    [Test]
    public async Task TheListsNameTheOptionsInTheirOrder()
    {
        var vm = await Editor(new FakeSource());
        await vm.ProtocolLabels.Should().BeEquivalentTo(["MASQUE", "WireGuard", "WARP-in-WARP", "MASQUE-in-MASQUE", "WireGuard over MASQUE"], CollectionOrdering.Matching);
        await vm.TransportLabels.Should().BeEquivalentTo(["HTTP/3", "HTTP/2"], CollectionOrdering.Matching);
        await vm.FingerprintLabels.Should().BeEquivalentTo(["Chrome", "Chrome 120", "Firefox", "Semi-Python", "Go"], CollectionOrdering.Matching);
        await vm.ScanModeLabels.Count.Should().BeEqualTo(AetherScanMode.All.Count);
        await vm.ObfuscationLabels.Count.Should().BeEqualTo(AetherObfuscation.All.Count);
        await vm.PsiphonLabels.Count.Should().BeEqualTo(AetherPsiphon.All.Count);
        await vm.PsiphonModeLabels.Count.Should().BeEqualTo(AetherPsiphonMode.All.Count);
        await vm.TorLabels.Count.Should().BeEqualTo(AetherTor.All.Count);
        await vm.TorBridgesLabels.Count.Should().BeEqualTo(AetherTorBridges.All.Count);
        await vm.TorRelaysLabels.Count.Should().BeEqualTo(AetherTorRelays.All.Count);
        await vm.IpVersionLabels.Count.Should().BeEqualTo(AetherIpVersion.All.Count);
        await vm.PsiphonCdnSetOptions.Count.Should().BeEqualTo(AetherPsiphonCdnSet.All.Count);
        await vm.EchDnsOptions[0].Should().BeEqualTo("udp://1.1.1.1");
        await vm.EchDomainOptions[0].Should().BeEqualTo("cloudflare-ech.com");
        // The profile list names an Aether row by its tunnel, the WARP protocol as the editor names it.
        var tor = With(new ProtocolExtraItem { AetherProtocol = "masque", AetherTor = "reverse" });
        await AetherCore.Of(tor, 10819).PathLabel(AetherLabels.ProtocolLabel).Should().BeEqualTo("TOR → MASQUE");
        var gool = With(new ProtocolExtraItem { AetherProtocol = "wg-over-masque", AetherPsiphon = "chain" });
        await AetherCore.Of(gool, 10819).PathLabel(AetherLabels.ProtocolLabel).Should().BeEqualTo("WireGuard over MASQUE → PSIPHON");
    }

    #endregion what the editor shows (ServerUiStateTest)

    #region scan, keys, session, log (ServerAetherViewModelTest)

    [Test]
    public async Task StartsIdleAndTellsWhetherTheCoreIsThere()
    {
        var vm = await Editor(new FakeSource { Available = false });

        await vm.IsScanning.Should().BeFalse();
        await vm.CoreAvailable.Should().BeFalse();
        await vm.CanScan.Should().BeFalse();
        await vm.CanClearPsiphon.Should().BeFalse();
        await vm.SessionProtocol.Should().BeNull();
        // The key status of the protocol is the first line.
        await Texts(vm).Should().BeEquivalentTo([ResUI.MsgAetherKeyMasqueMissing], CollectionOrdering.Matching);
        await (await Editor(new FakeSource())).CanScan.Should().BeTrue();
    }

    // VM-6: PattNG starts with the core counted as there, so that its note and a disabled Scan show only once it is known
    // to be missing.
    [Test]
    public async Task TheCoreCountsAsThereUntilTheCoreFolderIsRead()
    {
        var source = new FakeSource { Available = false, AvailabilityGate = new TaskCompletionSource() };
        var vm = await Task.Run(() => ViewModelConfig.With(CoreConfigTestFactory.CreateConfig(),
            () => new AddServerAetherViewModel(With(new ProtocolExtraItem { AetherProtocol = "masque", AetherPsiphon = "chain" }), source)));

        await vm.CoreAvailable.Should().BeTrue();
        await vm.CanScan.Should().BeTrue();
        await vm.CanClearPsiphon.Should().BeTrue();

        source.AvailabilityGate!.SetResult();
        await Over(vm.Initialized);
        await vm.CoreAvailable.Should().BeFalse();
        await vm.CanScan.Should().BeFalse();
        await vm.CanClearPsiphon.Should().BeFalse();
    }

    // VM-5: the box shows the command the settings build while none is written by hand, cleared or not (PattNG
    // aetherCommand.ifBlank { builtCommand }).
    [Test]
    public async Task ClearingTheCommandBoxWhileItShowsTheBuiltCommandShowsItAgain()
    {
        var vm = await Editor(new FakeSource());
        var raised = new List<string?>();
        vm.PropertyChanged += (_, e) => raised.Add(e.PropertyName);

        vm.CommandText = string.Empty;

        await raised.Should().Contain(nameof(AddServerAetherViewModel.CommandText));
        await vm.CommandText.Should().BeEqualTo(vm.BuiltCommand);
        await vm.Command.Should().BeEqualTo(string.Empty);
        await vm.CommandIsCustom.Should().BeFalse();
    }

    [Test]
    public async Task TheCommandIsBuiltOnTheListenPortOfTheSettings()
    {
        var vm = await Editor(new FakeSource { Port = 20808 });
        await vm.ListenPort.Should().BeEqualTo(20808);
        await vm.BuiltCommand.Should().Contain("--bind 127.0.0.1:20808");
    }

    [Test]
    public async Task AScanStreamsTheCoreOutputAndPutsTheEndpointItFoundInTheFields()
    {
        var pending = new TaskCompletionSource<AetherRunResult<AetherScanResult>>();
        var source = new FakeSource
        {
            Scanner = (_, onOutput, _) =>
            {
                onOutput("[2026-09-11T10:00:00.000Z INFO  aether] [+] candidate ok 162.159.197.3:443 rtt=84ms");
                onOutput("   ");
                return pending.Task;
            },
        };
        var vm = await Editor(source);

        var scan = vm.ScanAsync();
        await vm.IsScanning.Should().BeTrue();
        await vm.ScanText.Should().BeEqualTo(ResUI.TbAetherScanning);
        await vm.NotScanning.Should().BeFalse();
        await source.Scanned.Single().GetProtocolExtra().AetherProtocol.Should().BeEqualTo("masque");

        var shown = await Notices(async () =>
        {
            pending.SetResult(new AetherRunResult<AetherScanResult>(AetherRunOutcome.Done, Found));
            await scan;
        });

        await vm.IsScanning.Should().BeFalse();
        await vm.Address.Should().BeEqualTo("162.159.197.3");
        await vm.Port.Should().BeEqualTo("443");
        await shown.Should().Contain(ResUI.MsgAetherScanSuccess);
        await Texts(vm).Should().BeEquivalentTo(
            [
                ResUI.MsgAetherKeyMasqueMissing,
                ResUI.MsgAetherScanStarted,
                "[+] candidate ok 162.159.197.3:443 rtt=84ms",
                string.Format(ResUI.MsgAetherScanFound, "162.159.197.3:443"),
            ],
            CollectionOrdering.Matching);
    }

    [Test]
    public async Task AScanThatFindsNothingSaysSo()
    {
        var vm = await Editor(new FakeSource());

        var shown = await Notices(() => vm.ScanAsync());

        await vm.IsScanning.Should().BeFalse();
        var outcome = vm.Log.Entries.Last();
        await outcome.Text.Should().BeEqualTo(ResUI.MsgAetherScanFailed);
        await outcome.Priority.Should().BeEqualTo(AetherLogPriority.Warn);
        await shown.Should().Contain(ResUI.MsgAetherScanFailed);
    }

    [Test]
    public async Task ACoreThatCouldNotStartIsToldBeforeTheScanFails()
    {
        var vm = await Editor(new FakeSource
        {
            Scanner = (_, _, _) => Task.FromResult(new AetherRunResult<AetherScanResult>(AetherRunOutcome.NotStarted)),
        });

        await vm.ScanAsync();

        await Texts(vm).TakeLast(2).ToList().Should().BeEquivalentTo([ResUI.MsgAetherCoreCannotStart, ResUI.MsgAetherScanFailed], CollectionOrdering.Matching);
    }

    [Test]
    public async Task BothHopsOfATwoHopScanAreLoggedTogetherAndPutInTheirFields()
    {
        var hops = new AetherScanResult(new AetherEndpoint("162.159.192.1", 2408), new AetherEndpoint("188.114.96.1", 894));
        await AddServerAetherViewModel.ScanOutcome(hops).Should().BeEqualTo(string.Format(ResUI.MsgAetherScanFoundHops, "162.159.192.1:2408", "188.114.96.1:894"));

        var vm = await Editor(new FakeSource
        {
            Scanner = (_, _, _) => Task.FromResult(new AetherRunResult<AetherScanResult>(AetherRunOutcome.Done, hops)),
        }, With(new ProtocolExtraItem { AetherProtocol = "mim" }));
        await vm.ScanAsync();
        await vm.WiwOuter.Should().BeEqualTo("162.159.192.1:2408");
        await vm.WiwInner.Should().BeEqualTo("188.114.96.1:894");
    }

    [Test]
    public async Task CoreOutputKeepsItsLevelButLosesItsHeader()
    {
        var vm = await Editor(new FakeSource
        {
            Scanner = (_, onOutput, _) =>
            {
                onOutput("[2026-09-11T10:00:00.000Z WARN  aether] [-] scan deadline reached");
                onOutput("Error: NoCleanEndpoint");
                return Task.FromResult(new AetherRunResult<AetherScanResult>(AetherRunOutcome.Done));
            },
        });

        await vm.ScanAsync();

        var output = vm.Log.Entries.Where(entry => !entry.Own).ToList();
        await output.Select(entry => entry.Priority).ToList().Should().BeEquivalentTo([AetherLogPriority.Warn, AetherLogPriority.Error], CollectionOrdering.Matching);
        await output.Select(entry => entry.Text).ToList().Should().BeEquivalentTo(["[-] scan deadline reached", "Error: NoCleanEndpoint"], CollectionOrdering.Matching);
        await output[0].IsWarning.Should().BeTrue();
        await output[1].IsError.Should().BeTrue();
    }

    [Test]
    public async Task ASecondActionWaitsForTheFirstToFinish()
    {
        var pending = new TaskCompletionSource<AetherRunResult<AetherScanResult>>();
        var source = new FakeSource { Scanner = (_, _, _) => pending.Task };
        var vm = await Editor(source);
        var opened = 0;
        vm.OpenKeysInteraction.RegisterHandler(interaction =>
        {
            opened++;
            interaction.SetOutput(RxVoid.Default);
        });

        var scan = vm.ScanAsync();
        await vm.ScanAsync();
        await vm.ClearPsiphonDataAsync();
        await vm.OpenKeysAsync();
        await source.Scanned.Count.Should().BeEqualTo(1);
        await source.Clears.Should().BeEqualTo(0);
        // A scan holds the exit a run of the WARP keys window dials out through: the window waits for it to end.
        await opened.Should().BeEqualTo(0);
        await vm.CanScan.Should().BeFalse();
        await vm.CanClearPsiphon.Should().BeFalse();

        pending.SetResult(new AetherRunResult<AetherScanResult>(AetherRunOutcome.Done));
        await Over(scan);
        await vm.ScanAsync();
        await source.Scanned.Count.Should().BeEqualTo(2);
        await vm.OpenKeysAsync();
        await opened.Should().BeEqualTo(1);
    }

    [Test]
    public async Task CancellingAScanStopsItAndReturnsToIdle()
    {
        var stopped = false;
        var vm = await Editor(new FakeSource
        {
            Scanner = async (_, _, ct) =>
            {
                try
                {
                    await Task.Delay(Timeout.Infinite, ct);
                    return new AetherRunResult<AetherScanResult>(AetherRunOutcome.Done);
                }
                finally
                {
                    stopped = true;
                }
            },
        });

        var scan = vm.ScanAsync();
        vm.CancelScan();
        await Over(scan);

        await stopped.Should().BeTrue();
        await vm.IsScanning.Should().BeFalse();
        await Texts(vm).Last().Should().BeEqualTo(ResUI.MsgAetherScanCancelled);
        // Nothing runs: a cancel says nothing.
        vm.CancelScan();
        await Texts(vm).Count(text => text == ResUI.MsgAetherScanCancelled).Should().BeEqualTo(1);
    }

    [Test]
    public async Task ACancelledScanStaysBusyUntilItHasStopped()
    {
        var stopped = new TaskCompletionSource();
        var source = new FakeSource
        {
            Scanner = async (_, _, ct) =>
            {
                try
                {
                    await Task.Delay(Timeout.Infinite, ct);
                    return new AetherRunResult<AetherScanResult>(AetherRunOutcome.Done);
                }
                finally
                {
                    // The core is still being ended, as a real one takes a moment to.
                    await stopped.Task;
                }
            },
        };
        var vm = await Editor(source);

        var scan = vm.ScanAsync();
        vm.CancelScan();

        await vm.IsScanning.Should().BeTrue();
        await vm.ScanAsync();
        await vm.ClearPsiphonDataAsync();
        vm.CancelScan();
        await source.Scanned.Count.Should().BeEqualTo(1);
        await source.Clears.Should().BeEqualTo(0);
        await Texts(vm).Count(text => text == ResUI.MsgAetherScanCancelled).Should().BeEqualTo(1);

        stopped.SetResult();
        await Over(scan);

        await vm.IsScanning.Should().BeFalse();
        var again = vm.ScanAsync();
        await source.Scanned.Count.Should().BeEqualTo(2);
        vm.CancelScan();
        await Over(again);
    }

    [Test]
    public async Task ClosingTheWindowCancelsTheScanAndNoLongerFollowsTheSession()
    {
        var source = new FakeSource
        {
            Scanner = async (_, _, ct) =>
            {
                await Task.Delay(Timeout.Infinite, ct);
                return new AetherRunResult<AetherScanResult>(AetherRunOutcome.Done);
            },
        };
        var vm = await Editor(source);
        await source.Followed.Should().BeTrue();

        var scan = vm.ScanAsync();
        vm.OnClosed();
        await Over(scan);

        await vm.IsScanning.Should().BeFalse();
        await source.Followed.Should().BeFalse();
    }

    // VM-3: a scan cancelled while it looks its exit-node or its keys up ends there, as PattNG's coroutine does: no line
    // about the exit-node after the cancel, no question about the keys, no scan.
    [Test]
    public async Task AScanCancelledBeforeItStartedSaysAndAsksNothingMore()
    {
        var source = new FakeSource { KeysGate = new TaskCompletionSource() };
        source.MissingFiles.Add(AetherPaths.MasqueFile);
        var vm = await Editor(source);
        var asked = 0;
        vm.KeysMissingInteraction.RegisterHandler(interaction =>
        {
            asked++;
            interaction.SetOutput(EAetherKeysChoice.Anyway);
        });

        var scan = vm.ScanAsync();
        await source.KeyChecks.Should().BeEqualTo(1);
        vm.CancelScan();
        source.KeysGate!.SetResult();
        await Over(scan);

        await asked.Should().BeEqualTo(0);
        await source.Scanned.Count.Should().BeEqualTo(0);
        await vm.IsScanning.Should().BeFalse();
        await Texts(vm).Last().Should().BeEqualTo(ResUI.MsgAetherScanCancelled);

        // While the exit-node is looked up: no word on a name that finds no profile after the cancel.
        var lookup = new FakeSource { LookupGate = new TaskCompletionSource() };
        var named = await Editor(lookup, With(new ProtocolExtraItem { AetherProtocol = "masque", AetherExitNode = "germany" }));
        var looked = named.ScanAsync();
        await lookup.Lookups_.Should().BeEqualTo(1);
        named.CancelScan();
        lookup.LookupGate!.SetResult();
        await Over(looked);

        await lookup.Scanned.Count.Should().BeEqualTo(0);
        await Texts(named).Last().Should().BeEqualTo(ResUI.MsgAetherScanCancelled);
        await named.Log.Entries.Any(entry => entry.Priority == AetherLogPriority.Error).Should().BeFalse();
    }

    // VM-7: a window closed while a scan looks its keys up asks nothing more.
    [Test]
    public async Task AWindowClosedWhileAScanLooksItsKeysUpAsksNothing()
    {
        var source = new FakeSource { KeysGate = new TaskCompletionSource() };
        source.MissingFiles.Add(AetherPaths.MasqueFile);
        var vm = await Editor(source);
        var asked = 0;
        vm.KeysMissingInteraction.RegisterHandler(interaction =>
        {
            asked++;
            interaction.SetOutput(EAetherKeysChoice.Anyway);
        });

        var scan = vm.ScanAsync();
        await source.KeyChecks.Should().BeEqualTo(1);
        vm.OnClosed();
        source.KeysGate!.SetResult();
        await Over(scan);

        await asked.Should().BeEqualTo(0);
        await source.Scanned.Count.Should().BeEqualTo(0);
    }

    [Test]
    public async Task TheKeyStatusIsLoggedOnceUntilItChanges()
    {
        var source = new FakeSource();
        source.Identities[AetherProtocol.Masque] = new AetherIdentityStatus(AetherProtocol.Masque, OldKey);
        var vm = await Editor(source);

        await vm.ShowIdentityAsync(AetherProtocol.Masque);
        await vm.ShowIdentityAsync(AetherProtocol.Masque);
        await vm.ShowIdentityAsync(AetherProtocol.WireGuard);

        await Texts(vm).Should().BeEquivalentTo(
            [
                string.Format(ResUI.MsgAetherKeyMasqueReady, "a1b2c3d4…", "172.16.0.2", "2606:4700:110:8a36::1"),
                ResUI.MsgAetherKeyWireguardMissing,
            ],
            CollectionOrdering.Matching);
    }

    [Test]
    public async Task AChangeOfProtocolLogsTheKeysOfTheNewOne()
    {
        var vm = await Editor(new FakeSource());

        vm.ProtocolIndex = AetherProtocol.All.ToList().IndexOf(AetherProtocol.Gool);

        await Texts(vm).Should().BeEquivalentTo(
            [ResUI.MsgAetherKeyMasqueMissing, ResUI.MsgAetherKeyOuterMissing, ResUI.MsgAetherKeyInnerMissing],
            CollectionOrdering.Matching);
    }

    [Test]
    public async Task ATwoHopProtocolReportsBothHopKeys()
    {
        foreach (var protocol in new[] { AetherProtocol.Gool, AetherProtocol.Mim, AetherProtocol.WgOverMasque })
        {
            await AddServerAetherViewModel.KeyLines(new AetherIdentityStatus(protocol, OldKey)).Should().BeEquivalentTo(
                [
                    string.Format(ResUI.MsgAetherKeyOuterReady, "a1b2c3d4…", "172.16.0.2", "2606:4700:110:8a36::1"),
                    ResUI.MsgAetherKeyInnerMissing,
                ],
                CollectionOrdering.Matching).Because(protocol.Type);
        }
        // A device id of eight characters or fewer is shown whole.
        await AddServerAetherViewModel.KeyLine(OldKey with { DeviceId = "abcd" }, "{0}", "missing").Should().BeEqualTo("abcd");
    }

    [Test]
    public async Task ALiveSessionIsFollowedAsItStartsAndEnds()
    {
        var source = new FakeSource { Session = AetherProtocol.Masque };
        var vm = await Editor(source);
        await vm.SessionProtocol.Should().BeEqualTo(AetherProtocol.Masque);
        await vm.ScanBlocked.Should().BeTrue();
        await vm.ShowScanBlocked.Should().BeTrue();
        await vm.CanScan.Should().BeFalse();
        await vm.CanClearPsiphon.Should().BeFalse();

        source.Session = null;
        source.RaiseSessionChanged();
        await vm.SessionProtocol.Should().BeNull();
        await vm.ScanBlocked.Should().BeFalse();
        await vm.CanScan.Should().BeTrue();
        await vm.CanClearPsiphon.Should().BeTrue();

        // A WireGuard session uses another key than this MASQUE profile.
        source.Session = AetherProtocol.WireGuard;
        source.RaiseSessionChanged();
        await vm.ScanBlocked.Should().BeFalse();
        await vm.CanClearPsiphon.Should().BeFalse();
    }

    [Test]
    public async Task PsiphonDataIsNotClearedUnderALiveSessionAndTheLogTellsTheOutcome()
    {
        var source = new FakeSource();
        var vm = await Editor(source);

        source.Session = AetherProtocol.Masque;
        await vm.ClearPsiphonDataAsync();
        await source.Clears.Should().BeEqualTo(0);
        var blocked = vm.Log.Entries.Last();
        await blocked.Text.Should().BeEqualTo(ResUI.MsgAetherPsiphonClearBlocked);
        await blocked.Priority.Should().BeEqualTo(AetherLogPriority.Warn);

        source.Session = null;
        await vm.ClearPsiphonDataAsync();
        await source.Clears.Should().BeEqualTo(1);
        await vm.Log.Entries.Last().Text.Should().BeEqualTo(ResUI.MsgAetherPsiphonCleared);
        await vm.Log.Entries.Last().Priority.Should().BeEqualTo(AetherLogPriority.Info);

        source.Clearer = () => AetherPsiphonClear.Failed;
        await vm.ClearPsiphonDataAsync();
        await vm.Log.Entries.Last().Text.Should().BeEqualTo(ResUI.MsgAetherPsiphonClearFailed);
        await vm.Log.Entries.Last().Priority.Should().BeEqualTo(AetherLogPriority.Error);

        // A test, a scan or a key run holds the data under a lock.
        source.Clearer = () => AetherPsiphonClear.Blocked;
        await vm.ClearPsiphonDataAsync();
        await vm.Log.Entries.Last().Text.Should().BeEqualTo(ResUI.MsgAetherPsiphonClearBlocked);
    }

    [Test]
    public async Task AScanIsNotStartedOnTheKeyOfALiveSession()
    {
        var source = new FakeSource { Scanner = (_, _, _) => Task.FromResult(new AetherRunResult<AetherScanResult>(AetherRunOutcome.Done, Found)) };
        var vm = await Editor(source);

        // Started after the editor opened: checked at the tap.
        source.Session = AetherProtocol.Masque;
        await vm.ScanAsync();
        await source.Scanned.Count.Should().BeEqualTo(0);
        await vm.IsScanning.Should().BeFalse();
        await vm.SessionProtocol.Should().BeEqualTo(AetherProtocol.Masque);
        var blocked = vm.Log.Entries.Last();
        await blocked.Text.Should().BeEqualTo(ResUI.MsgAetherScanBlocked);
        await blocked.Priority.Should().BeEqualTo(AetherLogPriority.Warn);

        // MASQUE-in-MASQUE and WireGuard over MASQUE share the MASQUE key.
        source.Session = AetherProtocol.WgOverMasque;
        await vm.ScanAsync();
        await source.Scanned.Count.Should().BeEqualTo(0);

        // A WireGuard session uses another key than this MASQUE profile, so the scan goes ahead.
        source.Session = AetherProtocol.WireGuard;
        await vm.ScanAsync();
        await source.Scanned.Count.Should().BeEqualTo(1);
    }

    [Test]
    public async Task AScanDisturbsOnlyASessionThatSharesItsKey()
    {
        // PattNG AetherEditorRepositoryTest: WireGuard over MASQUE uses the MASQUE key outside and a WireGuard key of its own inside.
        await AetherIdentityManager.SharesIdentity(AetherProtocol.Masque, AetherProtocol.WgOverMasque).Should().BeTrue();
        await AetherIdentityManager.SharesIdentity(AetherProtocol.WgOverMasque, AetherProtocol.Masque).Should().BeTrue();
        await AetherIdentityManager.SharesIdentity(AetherProtocol.WireGuard, AetherProtocol.WgOverMasque).Should().BeFalse();
        await AetherIdentityManager.SharesIdentity(AetherProtocol.WgOverMasque, AetherProtocol.Gool).Should().BeFalse();
        await AetherIdentityManager.SharesIdentity(AetherProtocol.Gool, AetherProtocol.WireGuard).Should().BeTrue();
        await AetherIdentityManager.SharesIdentity(AetherProtocol.Mim, AetherProtocol.Masque).Should().BeTrue();
    }

    [Test]
    public async Task AScanWhoseKeysAreMissingAsksFirstAndGoesAheadWhenToldTo()
    {
        var source = new FakeSource { Scanner = (_, _, _) => Task.FromResult(new AetherRunResult<AetherScanResult>(AetherRunOutcome.Done, Found)) };
        source.MissingFiles.Add(AetherPaths.MasqueFile);
        var vm = await Editor(source);
        var asked = new List<bool>();
        var answer = EAetherKeysChoice.Cancel;
        vm.KeysMissingInteraction.RegisterHandler(interaction =>
        {
            asked.Add(interaction.Input.Scan);
            interaction.SetOutput(answer);
        });

        await vm.ScanAsync();
        await source.Scanned.Count.Should().BeEqualTo(0);
        await vm.IsScanning.Should().BeFalse();
        await asked.Should().BeEquivalentTo([true], CollectionOrdering.Matching);
        // Asking logs nothing.
        await Texts(vm).Should().BeEquivalentTo([ResUI.MsgAetherKeyMasqueMissing], CollectionOrdering.Matching);

        answer = EAetherKeysChoice.Anyway;
        await vm.ScanAsync();
        await source.Scanned.Count.Should().BeEqualTo(1);
        await asked.Count.Should().BeEqualTo(2);
        await vm.Address.Should().BeEqualTo("162.159.197.3");
    }

    [Test]
    public async Task GettingTheKeysFirstOpensTheWarpKeysWindow()
    {
        var source = new FakeSource();
        source.MissingFiles.Add(AetherPaths.MasqueFile);
        var vm = await Editor(source);
        vm.KeysMissingInteraction.RegisterHandler(interaction => interaction.SetOutput(EAetherKeysChoice.GetKeys));
        var opened = 0;
        vm.OpenKeysInteraction.RegisterHandler(interaction =>
        {
            opened++;
            interaction.SetOutput(RxVoid.Default);
        });

        await vm.ScanAsync();
        await opened.Should().BeEqualTo(1);
        await source.Scanned.Count.Should().BeEqualTo(0);

        vm.Remarks = "warp";
        await vm.SaveAsync();
        await opened.Should().BeEqualTo(2);
        await source.Saved.Count.Should().BeEqualTo(0);

        // The button does the same, and the key status is read again once the window is closed.
        source.Identities[AetherProtocol.Masque] = new AetherIdentityStatus(AetherProtocol.Masque, OldKey);
        await vm.OpenKeysCmd.Execute().ToTask();
        await opened.Should().BeEqualTo(3);
        await Texts(vm).Last().Should().BeEqualTo(string.Format(ResUI.MsgAetherKeyMasqueReady, "a1b2c3d4…", "172.16.0.2", "2606:4700:110:8a36::1"));
    }

    [Test]
    public async Task TheProfilesThatCanBeTheExitNodeAreRead()
    {
        var source = new FakeSource { Nodes = [new AetherExitNode("germany", 1), new AetherExitNode("france", 2)] };
        var vm = await Editor(source);
        await vm.ExitNode.Nodes.Should().BeEquivalentTo(source.Nodes, CollectionOrdering.Matching);
        await vm.ExitNode.Labels.Should().BeEquivalentTo([ResUI.TbAetherExitNodeFreedom, "germany", "france"], CollectionOrdering.Matching);
    }

    [Test]
    public async Task AScanDoesNotDialOutThroughAnExitNodeNameThatFindsNoProfileOrSeveral()
    {
        var source = new FakeSource();
        var vm = await Editor(source);
        vm.ExitNode.Name = "germany ";

        // Renamed or deleted since the editor opened.
        await vm.ScanAsync();
        await source.Scanned.Count.Should().BeEqualTo(0);
        await vm.IsScanning.Should().BeFalse();
        await vm.Log.Entries.Last().Text.Should().BeEqualTo(string.Format(ResUI.MsgAetherExitNodeNotFound, "germany"));
        await vm.Log.Entries.Last().Priority.Should().BeEqualTo(AetherLogPriority.Error);

        // The name of two profiles by now.
        source.Lookups["germany"] = ExitNodeLookup.SameName.Instance;
        await vm.ScanAsync();
        await source.Scanned.Count.Should().BeEqualTo(0);
        await vm.Log.Entries.Last().Text.Should().BeEqualTo(string.Format(ResUI.MsgAetherExitNodeDuplicate, "germany"));

        source.Lookups["germany"] = new ExitNodeLookup.One(new ProfileItem { Remarks = "germany" }, "digest");
        await vm.ScanAsync();
        await source.Scanned.Count.Should().BeEqualTo(1);
    }

    [Test]
    public async Task AScanNeedsOnlyTheKeysOfItsProtocol()
    {
        var source = new FakeSource();
        source.MissingFiles.Add(AetherPaths.MasqueFile);
        source.MissingFiles.Add(AetherPaths.MasqueInnerFile);
        var vm = await Editor(source, With(new ProtocolExtraItem { AetherProtocol = "wg" }));
        var asked = 0;
        vm.KeysMissingInteraction.RegisterHandler(interaction =>
        {
            asked++;
            interaction.SetOutput(EAetherKeysChoice.Cancel);
        });

        await vm.ScanAsync();
        await source.Scanned.Count.Should().BeEqualTo(1);
        await asked.Should().BeEqualTo(0);

        vm.ProtocolIndex = AetherProtocol.All.ToList().IndexOf(AetherProtocol.Mim);
        await vm.ScanAsync();
        await source.Scanned.Count.Should().BeEqualTo(1);
        await asked.Should().BeEqualTo(1);

        // Psiphon alone has no WARP tunnel to scan for: the editor offers no scan then.
        vm.PsiphonIndex = AetherPsiphon.All.ToList().IndexOf(AetherPsiphon.Only);
        await vm.WarpUsed.Should().BeFalse();
    }

    [Test]
    public async Task WireGuardOverMasqueAsksWhenItsOuterMasqueKeyOrItsInnerWireGuardKeyIsMissing()
    {
        var source = new FakeSource();
        var vm = await Editor(source, With(new ProtocolExtraItem { AetherProtocol = "wg-over-masque" }));
        var asked = new List<bool>();
        vm.KeysMissingInteraction.RegisterHandler(interaction =>
        {
            asked.Add(interaction.Input.Scan);
            interaction.SetOutput(EAetherKeysChoice.Cancel);
        });

        foreach (var missing in new[] { AetherPaths.MasqueFile, AetherPaths.MasqueGoolFile })
        {
            source.MissingFiles.Clear();
            source.MissingFiles.Add(missing);
            asked.Clear();

            await vm.SaveAsync();
            await vm.ScanAsync();
            await asked.Should().BeEquivalentTo([false, true], CollectionOrdering.Matching).Because(missing);
            await source.Saved.Count.Should().BeEqualTo(0).Because(missing);
            await source.Scanned.Count.Should().BeEqualTo(0).Because(missing);
        }

        // With both of its keys there nothing is asked; the keys of the other protocols do not count.
        source.MissingFiles.Clear();
        source.MissingFiles.Add(AetherPaths.WireGuardFile);
        source.MissingFiles.Add(AetherPaths.WireGuardInnerFile);
        source.MissingFiles.Add(AetherPaths.MasqueInnerFile);
        asked.Clear();
        await vm.ScanAsync();
        await vm.SaveAsync();
        await asked.Count.Should().BeEqualTo(0);
        await source.Scanned.Count.Should().BeEqualTo(1);
        await source.Saved.Count.Should().BeEqualTo(1);
    }

    [Test]
    public async Task TheLogKeepsOnlyTheLatestEntries()
    {
        var vm = await Editor(new FakeSource
        {
            Scanner = (_, onOutput, _) =>
            {
                for (var line = 0; line < AetherLogViewModel.Capacity + 50; line++)
                {
                    onOutput($"line {line}");
                }
                return Task.FromResult(new AetherRunResult<AetherScanResult>(AetherRunOutcome.Done));
            },
        });

        await vm.ScanAsync();

        var entries = vm.Log.Entries.ToList();
        await entries.Count.Should().BeEqualTo(AetherLogViewModel.Capacity);
        await entries.Select(entry => entry.Id).ToList().Should().BeEquivalentTo(entries.Select(entry => entry.Id).Order().ToList(), CollectionOrdering.Matching);
        await entries.Any(entry => entry.Text == "line 0").Should().BeFalse();
        await vm.Log.Text.Should().EndWith(ResUI.MsgAetherScanFailed);
    }

    /// <summary>A UI thread's context that runs what is posted to it only when told to, in the order it came.</summary>
    private sealed class QueuedContext : SynchronizationContext
    {
        private readonly ConcurrentQueue<(SendOrPostCallback Work, object? State)> _posted = new();

        public int Pending => _posted.Count;

        public override void Post(SendOrPostCallback d, object? state)
        {
            _posted.Enqueue((d, state));
        }

        public void Pump()
        {
            while (_posted.TryDequeue(out var posted))
            {
                posted.Work(posted.State);
            }
        }
    }

    // UIPM-6: the core's output comes from its reader thread, and the list the panel shows is the UI's: it is put in on
    // the UI thread, in the order it came. WPF gives each dispatcher operation a context of its own, so a word said on the
    // UI thread later is posted as well, behind what came before it.
    [Test]
    public async Task TheLogPutsInWhatComesFromAnotherThreadOnTheUiThreadInItsOrder()
    {
        var ui = new QueuedContext();
        var before = SynchronizationContext.Current;
        AetherLogViewModel log;
        SynchronizationContext.SetSynchronizationContext(ui);
        try
        {
            log = new AetherLogViewModel(ResUI.TbAetherLogEmpty);
            // On the UI thread, in the context it was made in: at once.
            log.Append(AetherLogPriority.Info, "own");
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(before);
        }
        await log.Entries.Select(entry => entry.Text).ToList().Should().BeEquivalentTo(["own"], CollectionOrdering.Matching);

        await Task.Run(() =>
        {
            log.AppendOutput("first");
            log.AppendOutput("second");
        });
        await log.Entries.Count.Should().BeEqualTo(1);
        await ui.Pending.Should().BeEqualTo(2);

        SynchronizationContext.SetSynchronizationContext(new QueuedContext());
        try
        {
            log.Append(AetherLogPriority.Warn, "later");
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(before);
        }
        await log.Entries.Count.Should().BeEqualTo(1);
        await ui.Pending.Should().BeEqualTo(3);

        ui.Pump();
        await log.Entries.Select(entry => entry.Text).ToList().Should().BeEquivalentTo(["own", "first", "second", "later"], CollectionOrdering.Matching);
        await log.Entries.Select(entry => entry.Id).ToList().Should().BeEquivalentTo(log.Entries.Select(entry => entry.Id).Order().ToList(), CollectionOrdering.Matching);
    }

    #endregion scan, keys, session, log (ServerAetherViewModelTest)

    #region save

    [Test]
    public async Task ASaveNeedsRemarks()
    {
        var source = new FakeSource();
        var vm = await Editor(source);
        vm.Remarks = " ";

        var shown = await Notices(vm.SaveAsync);

        await shown.Should().Contain(ResUI.PleaseFillRemarks);
        await source.Saved.Count.Should().BeEqualTo(0);
        await source.KeyChecks.Should().BeEqualTo(0);
    }

    [Test]
    public async Task ABrokenFinalMaskIsRefusedEvenBehindANamedExitNode()
    {
        var source = new FakeSource();
        source.Lookups["germany"] = new ExitNodeLookup.One(new ProfileItem { Remarks = "germany" }, "digest");
        var vm = await Editor(source);
        vm.FinalMask.Text = "[1, 2]";
        vm.ExitNode.Name = "germany";

        var shown = await Notices(vm.SaveAsync);

        await shown.Should().Contain(string.Format(ResUI.MsgInvalidProperty, ResUI.TbAetherExitFinalMask));
        await source.Saved.Count.Should().BeEqualTo(0);
        // Refused before the exit-node is looked up.
        await source.Lookups_.Should().BeEqualTo(0);
    }

    [Test]
    public async Task ASettingTheCoreWouldRefuseStopsTheSaveWithItsMessage()
    {
        var cases = new (Action<AddServerAetherViewModel> Set, string Message)[]
        {
            (vm => { vm.Address = "example.com"; vm.Port = "443"; }, ResUI.MsgAetherInvalidEndpoint),
            (vm => { vm.Address = "162.159.192.1"; vm.Port = "70000"; }, ResUI.MsgAetherInvalidEndpoint),
            (vm => vm.MasqueSni = "1.2.3.4", ResUI.MsgAetherInvalidMasqueSni),
            (vm => { vm.Ech = true; vm.EchDns = "ftp://x"; }, ResUI.MsgAetherInvalidEchDns),
            (vm => vm.Dns = "not a resolver", ResUI.MsgAetherInvalidDns),
            (vm => vm.ExitLoc = "Germany", ResUI.MsgAetherInvalidExitLoc),
            (vm =>
            {
                vm.TorIndex = AetherTor.All.ToList().IndexOf(AetherTor.Chain);
                vm.TorBridgesIndex = AetherTorBridges.All.ToList().IndexOf(AetherTorBridges.Own);
            }, ResUI.MsgAetherTorBridgesMissing),
            (vm => vm.Command = "aether --protocol masque --bind localhost", ResUI.MsgAetherInvalidCommand),
        };
        foreach (var (set, message) in cases)
        {
            var source = new FakeSource();
            var vm = await Editor(source);
            set(vm);

            var shown = await Notices(vm.SaveAsync);

            await shown.Should().Contain(message).Because(message);
            await source.Saved.Count.Should().BeEqualTo(0).Because(message);
            await source.KeyChecks.Should().BeEqualTo(0).Because(message);
        }
    }

    [Test]
    public async Task TheCoreCannotListenOnAPortOfTheApp()
    {
        // The local proxy moved onto the Aether listen port.
        var source = new FakeSource { Taken = [10819] };
        var vm = await Editor(source);

        var shown = await Notices(vm.SaveAsync);

        await shown.Should().Contain(string.Format(ResUI.MsgAetherListenPortTaken, 10819));
        await source.Saved.Count.Should().BeEqualTo(0);
    }

    [Test]
    public async Task ASaveLooksTheExitNodeUpAfreshAndIsRefusedForOneItCannotUse()
    {
        var problems = new ExitNodeLookup.Problem[]
        {
            ExitNodeLookup.NotFound.Instance, ExitNodeLookup.SameName.Instance, ExitNodeLookup.NoOutbound.Instance,
            ExitNodeLookup.EchUnusable.Instance,
        };
        foreach (var problem in problems)
        {
            var source = new FakeSource();
            source.Lookups["germany"] = problem;
            var vm = await Editor(source);
            vm.ExitNode.Name = " germany ";

            var shown = await Notices(vm.SaveAsync);

            await shown.Should().Contain(AetherExitNodes.MessageOf(problem, "germany")).Because(problem.MessageKey);
            await source.Saved.Count.Should().BeEqualTo(0).Because(problem.MessageKey);
            // Refused before the keys are looked at.
            await source.KeyChecks.Should().BeEqualTo(0).Because(problem.MessageKey);
        }

        var found = new FakeSource();
        found.Lookups["germany"] = new ExitNodeLookup.One(new ProfileItem { Remarks = "germany" }, "digest");
        var named = await Editor(found);
        named.ExitNode.Name = "germany";
        await named.SaveAsync();
        await found.Saved.Single().GetProtocolExtra().AetherExitNode.Should().BeEqualTo("germany");

        // Freedom is looked up nowhere.
        var freedom = new FakeSource();
        await (await Editor(freedom)).SaveAsync();
        await freedom.Lookups_.Should().BeEqualTo(0);
        await freedom.Saved.Count.Should().BeEqualTo(1);
    }

    [Test]
    public async Task ASaveGoesOnOnlyWhenTheKeysTheProfileNeedsAreThereOrTheUserSaysSo()
    {
        var source = new FakeSource();
        var vm = await Editor(source);
        var asked = 0;
        var answer = EAetherKeysChoice.Cancel;
        vm.KeysMissingInteraction.RegisterHandler(interaction =>
        {
            asked++;
            interaction.SetOutput(answer);
        });

        // A MASQUE profile needs the MASQUE key, and no inner hop key.
        source.MissingFiles.Add(AetherPaths.MasqueInnerFile);
        source.MissingFiles.Add(AetherPaths.WireGuardFile);
        var mim = await Editor(source, With(new ProtocolExtraItem { AetherProtocol = "mim" }));
        mim.KeysMissingInteraction.RegisterHandler(interaction =>
        {
            asked++;
            interaction.SetOutput(EAetherKeysChoice.Cancel);
        });
        await mim.SaveAsync();
        await asked.Should().BeEqualTo(1);
        await source.Saved.Count.Should().BeEqualTo(0);

        // A command written by hand counts as it runs.
        vm.Command = "aether --bind 127.0.0.1:10819 --protocol wg";
        await vm.SaveAsync();
        await asked.Should().BeEqualTo(2);
        await source.Saved.Count.Should().BeEqualTo(0);

        // Psiphon alone needs no WARP key at all.
        vm.Command = string.Empty;
        vm.PsiphonIndex = AetherPsiphon.All.ToList().IndexOf(AetherPsiphon.Only);
        foreach (var file in AetherPaths.KeyFiles)
        {
            source.MissingFiles.Add(file);
        }
        await vm.SaveAsync();
        await asked.Should().BeEqualTo(2);
        await source.Saved.Count.Should().BeEqualTo(1);

        // Saved anyway, the core registers what it lacks on its own.
        var anyway = new FakeSource();
        anyway.MissingFiles.Add(AetherPaths.MasqueFile);
        var go = await Editor(anyway);
        go.KeysMissingInteraction.RegisterHandler(interaction => interaction.SetOutput(EAetherKeysChoice.Anyway));
        await go.SaveAsync();
        await anyway.Saved.Count.Should().BeEqualTo(1);
    }

    [Test]
    public async Task WhatASaveStoresIsTheProfileNormalized()
    {
        var source = new FakeSource();
        var item = With(new ProtocolExtraItem { AetherProtocol = "masque" }, "warp");
        var vm = await Editor(source, item);
        vm.Address = " 162.159.192.1 ";
        vm.Port = "۲۴۰۸";
        vm.Remarks = "warp 2";
        var closed = 0;
        vm.RequestClose += (_, _) => closed++;

        var shown = await Notices(vm.SaveAsync);

        await shown.Should().Contain(ResUI.OperationSuccess);
        await closed.Should().BeEqualTo(1);
        var stored = source.Saved.Single();
        await stored.Remarks.Should().BeEqualTo("warp 2");
        await stored.ConfigType.Should().BeEqualTo(EConfigType.Aether);
        await stored.Port.Should().BeEqualTo(2408);
        // The defaults shown filled in are stored as none, so that the profile follows them.
        await stored.GetProtocolExtra().AetherEchDns.Should().BeNull();
        await stored.GetProtocolExtra().AetherEchDomain.Should().BeNull();
        await stored.GetProtocolExtra().AetherMasqueSni.Should().BeNull();
        // A new profile gets the id of the one stored, so that the caller reloads when it is the active one.
        await item.IndexId.Should().BeEqualTo(stored.IndexId);
        // The editor saves nothing once a save has closed it.
        await vm.SaveAsync();
        await source.Saved.Count.Should().BeEqualTo(1);
        await closed.Should().BeEqualTo(1);
    }

    [Test]
    public async Task AnExistingProfileIsEditedInACopyUntilItIsSaved()
    {
        var source = new FakeSource();
        var item = With(new ProtocolExtraItem { AetherProtocol = "masque", AetherDns = "1.1.1.1" }, "warp");
        item.IndexId = "existing";
        var vm = await Editor(source, item);

        vm.Remarks = "edited";
        vm.Dns = "9.9.9.9";
        await item.Remarks.Should().BeEqualTo("warp");
        await item.GetProtocolExtra().AetherDns.Should().BeEqualTo("1.1.1.1");

        await vm.SaveAsync();
        var stored = source.Saved.Single();
        await stored.IndexId.Should().BeEqualTo("existing");
        await stored.Remarks.Should().BeEqualTo("edited");
        await stored.GetProtocolExtra().AetherDns.Should().BeEqualTo("9.9.9.9");
    }

    // VM-2: a profile edited while its checks ran is checked again, remarks included (PattNG requestSave).
    [Test]
    public async Task RemarksClearedWhileTheKeysWereCheckedRefuseTheSave()
    {
        var source = new FakeSource { KeysGate = new TaskCompletionSource() };
        var vm = await Editor(source);

        var shown = await Notices(async () =>
        {
            var save = vm.SaveAsync();
            await source.KeyChecks.Should().BeEqualTo(1);
            vm.Remarks = "  ";
            var gate = source.KeysGate!;
            source.KeysGate = null;
            gate.SetResult();
            await Over(save);
        });

        await shown.Should().Contain(ResUI.PleaseFillRemarks);
        await source.Saved.Count.Should().BeEqualTo(0);
    }

    // VM-4: the WARP keys window waits for a running scan to end, so the question of a save made meanwhile does not
    // offer it; once the scan is over it does.
    [Test]
    public async Task ASaveWhileAScanRunsDoesNotOfferTheWarpKeysWindow()
    {
        var pending = new TaskCompletionSource<AetherRunResult<AetherScanResult>>();
        var source = new FakeSource { Scanner = (_, _, _) => pending.Task };
        source.MissingFiles.Add(AetherPaths.MasqueFile);
        var vm = await Editor(source);
        var questions = new List<AetherKeysQuestion>();
        vm.KeysMissingInteraction.RegisterHandler(interaction =>
        {
            questions.Add(interaction.Input);
            interaction.SetOutput(EAetherKeysChoice.GetKeys);
        });
        var opened = 0;
        vm.OpenKeysInteraction.RegisterHandler(interaction =>
        {
            opened++;
            interaction.SetOutput(RxVoid.Default);
        });

        var scan = vm.ScanAsync(anyway: true);
        await vm.IsScanning.Should().BeTrue();
        await vm.SaveAsync();

        await questions.Should().BeEquivalentTo([new AetherKeysQuestion(Scan: false, CanGetKeys: false)], CollectionOrdering.Matching);
        await opened.Should().BeEqualTo(0);
        await source.Saved.Count.Should().BeEqualTo(0);

        pending.SetResult(new AetherRunResult<AetherScanResult>(AetherRunOutcome.Done));
        await Over(scan);
        await vm.SaveAsync();
        await questions.Last().Should().BeEqualTo(new AetherKeysQuestion(Scan: false, CanGetKeys: true));
        await opened.Should().BeEqualTo(1);
        await source.Saved.Count.Should().BeEqualTo(0);
    }

    // VM-7: a window closed while a save looks its keys up saves nothing and asks nothing.
    [Test]
    public async Task AWindowClosedWhileASaveLooksItsKeysUpSavesNothing()
    {
        var source = new FakeSource { KeysGate = new TaskCompletionSource() };
        source.MissingFiles.Add(AetherPaths.MasqueFile);
        var vm = await Editor(source);
        var asked = 0;
        vm.KeysMissingInteraction.RegisterHandler(interaction =>
        {
            asked++;
            interaction.SetOutput(EAetherKeysChoice.Anyway);
        });

        var save = vm.SaveAsync();
        await source.KeyChecks.Should().BeEqualTo(1);
        vm.OnClosed();
        source.KeysGate!.SetResult();
        await Over(save);

        await asked.Should().BeEqualTo(0);
        await source.Saved.Count.Should().BeEqualTo(0);
    }

    [Test]
    public async Task AProfileEditedWhileItsKeysWereCheckedIsCheckedInItsTurn()
    {
        var source = new FakeSource { KeysGate = new TaskCompletionSource() };
        var vm = await Editor(source);

        var save = vm.SaveAsync();
        await source.KeyChecks.Should().BeEqualTo(1);
        vm.Remarks = "edited meanwhile";
        var gate = source.KeysGate!;
        source.KeysGate = null;
        gate.SetResult();
        await save;

        await source.KeyChecks.Should().BeEqualTo(2);
        await source.Saved.Single().Remarks.Should().BeEqualTo("edited meanwhile");
    }

    [Test]
    public async Task TheExitNodesDialModeIsAPresetFieldSavedAsItHolds()
    {
        var (oobName, oob) = Global.DialModePresets[0];
        var profile = With(new ProtocolExtraItem { AetherProtocol = AetherProtocol.Masque.Type });
        profile.DialMode = oob;
        var vm = await Editor(new FakeSource(), profile);

        await vm.DialMode.Text.Should().BeEqualTo(oob);
        await vm.DialMode.Matched;
        await vm.DialMode.HeldName.Should().BeEqualTo(oobName);
        await vm.DialMode.Setting.Should().BeEqualTo("dialMode");
        // Default blanks it, a pick puts the preset back, and a blank one is saved as none.
        await vm.DialMode.ChooseAtAsync(0);
        await vm.ToProfileItem().DialMode.Should().BeEqualTo(string.Empty);
        await vm.DialMode.ChooseAtAsync(1);
        await vm.ToProfileItem().DialMode.Should().BeEqualTo(oob);
        vm.DialMode.Text = " ";
        await vm.ToProfileItem().DialMode.Should().BeEqualTo(string.Empty);
    }

    #endregion save
}
