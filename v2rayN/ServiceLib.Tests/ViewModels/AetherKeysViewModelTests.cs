using ReactiveUI.Primitives;
using ReactiveUI.Primitives.Extensions;
using ServiceLib.Tests.CoreConfig;
using ServiceLib.ViewModels;
using TUnit.Assertions.Enums;

namespace ServiceLib.Tests.ViewModels;

/// <summary>
/// PattN (design 3.4, stage 9): the WARP keys window, from PattNG AetherKeysViewModelTest, with what PattN adds: the
/// settings kept in the app settings, the radios of the kinds, the Get button's state, and the window's closing. The window
/// reads and runs through a fake source: no test reaches the network, starts a core or writes the settings file.
/// </summary>
[NotInParallel("AppManager config")]
public class AetherKeysViewModelTests
{
    private static readonly AetherIdentity OldKey = new("a1b2c3d4e5f6", "172.16.0.2", "2606:4700:110:8a36::1");
    private static readonly AetherIdentity NewKey = new("f6e5d4c3b2a1", "172.16.0.2", "2606:4700:110:8a36::2");

    /// <summary>A run of the core as the source was asked for it, its arguments joined by spaces.</summary>
    private sealed record Run(AetherKeyKind Kind, string Arguments, AetherExit Exit);

    private sealed class FakeSource : IAetherKeysSource
    {
        public bool Available = true;
        public AetherProtocol? Session;
        public AetherKeysSettings Stored = new();
        public readonly List<AetherKeysSettings> Saved = [];
        public List<AetherKey> InUse = AetherPaths.KeyFiles.Select(file => new AetherKey(file, null)).ToList();
        public readonly List<Run> Runs = [];
        public Func<Action<string>, CancellationToken, Task<List<AetherKey>?>> Renewer = (_, _) => Task.FromResult<List<AetherKey>?>(null);
        public List<AetherExitNode> Nodes = [];
        public readonly Dictionary<string, ExitNodeLookup> Found = [];

        public AetherProtocol? SessionProtocol => Session;

        public event Action? SessionChanged;

        public void RaiseSessionChanged()
        {
            SessionChanged?.Invoke();
        }

        public bool Followed => SessionChanged != null;

        public Task<bool> IsCoreAvailableAsync()
        {
            return Task.FromResult(Available);
        }

        public AetherKeysSettings LoadSettings()
        {
            return Stored;
        }

        public Task SaveSettingsAsync(AetherKeysSettings settings)
        {
            Saved.Add(settings);
            return Task.CompletedTask;
        }

        public Task<List<AetherKey>> KeysAsync()
        {
            return Task.FromResult(InUse.ToList());
        }

        public Task<List<AetherKey>?> RenewAsync(AetherKeyKind kind, IReadOnlyList<string> arguments, AetherExit exit, Action<string> onOutput, CancellationToken ct)
        {
            Runs.Add(new Run(kind, string.Join(' ', arguments), exit));
            return Renewer(onOutput, ct);
        }

        public Task<List<AetherExitNode>> ExitNodesAsync()
        {
            return Task.FromResult(Nodes.ToList());
        }

        public Task<ExitNodeLookup> FindExitNodeAsync(string name)
        {
            return Task.FromResult(Found.GetValueOrDefault(name) ?? ExitNodeLookup.NotFound.Instance);
        }
    }

    /// <summary>The window on <paramref name="source" />, made where no UI thread is, and opened.</summary>
    private static async Task<AetherKeysViewModel> Window(FakeSource source)
    {
        var vm = await Task.Run(() => ViewModelConfig.With(CoreConfigTestFactory.CreateConfig(), () => new AetherKeysViewModel(source)));
        await vm.Initialized;
        return vm;
    }

    private static List<string> Texts(AetherKeysViewModel vm)
    {
        return vm.Log.Entries.Select(entry => entry.Text).ToList();
    }

    private static string Arguments(AetherKeysSettings settings)
    {
        return string.Join(' ', AetherKeys.Arguments(settings));
    }

    private static string Missing(string file)
    {
        return AetherKeysViewModel.KeyLine(new AetherKey(file, null));
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

    /// <summary>
    /// <paramref name="run" />, a run of the window, once it is over; a run that never ends fails the test rather than
    /// holding the test run up.
    /// </summary>
    private static Task Over(Task run)
    {
        return run.WaitAsync(TimeSpan.FromSeconds(10));
    }

    /// <summary>A renewal that goes on until it is cancelled, and then ends once <paramref name="stopped" /> is done.</summary>
    private static Func<Action<string>, CancellationToken, Task<List<AetherKey>?>> UntilCancelled(Task? stopped = null, Action? onStop = null)
    {
        return async (_, ct) =>
        {
            try
            {
                await Task.Delay(Timeout.Infinite, ct);
                return null;
            }
            finally
            {
                onStop?.Invoke();
                if (stopped != null)
                {
                    // The core is still being ended, as a real one takes a moment to.
                    await stopped;
                }
            }
        };
    }

    #region PattNG AetherKeysViewModelTest

    [Test]
    public async Task OpensOnTheSavedSettingsAndShowsEveryKeyInUse()
    {
        var source = new FakeSource
        {
            Available = false,
            Stored = new AetherKeysSettings { Kind = AetherKeyKind.Gool, Fingerprint = AetherFingerprint.Firefox, Ech = true },
            InUse =
            [
                new AetherKey(AetherPaths.WireGuardFile, OldKey),
                new AetherKey(AetherPaths.WireGuardInnerFile, null),
                new AetherKey(AetherPaths.MasqueFile, OldKey),
                new AetherKey(AetherPaths.MasqueInnerFile, null),
                new AetherKey(AetherPaths.MasqueGoolFile, OldKey),
            ],
        };
        var vm = await Window(source);

        await vm.Settings.Should().BeEqualTo(source.Stored);
        await vm.CoreAvailable.Should().BeFalse();
        await vm.CanGetKeys.Should().BeFalse();
        await vm.IsRenewing.Should().BeFalse();
        await vm.SessionProtocol.Should().BeNull();
        await source.Saved.Should().BeEmpty();
        await Texts(vm).Should().BeEquivalentTo(
            [
                string.Format(ResUI.MsgAetherKeyWireguardReady, "a1b2c3d4…", "172.16.0.2", "2606:4700:110:8a36::1"),
                ResUI.MsgAetherKeyWireguardInnerMissing,
                string.Format(ResUI.MsgAetherKeyMasqueReady, "a1b2c3d4…", "172.16.0.2", "2606:4700:110:8a36::1"),
                ResUI.MsgAetherKeyMasqueInnerMissing,
                string.Format(ResUI.MsgAetherKeyGoolReady, "a1b2c3d4…", "172.16.0.2", "2606:4700:110:8a36::1"),
            ],
            CollectionOrdering.Matching);
        // The fields show the settings.
        await vm.KindOptions.Single(option => option.IsChecked).Kind.Should().BeEqualTo(AetherKeyKind.Gool);
        await vm.FingerprintLabels[vm.FingerprintIndex].Should().BeEqualTo("Firefox");
        await vm.Ech.Should().BeTrue();
        // Blank, the core's own: the address of the server name, which follows the host, with default under each. To pick,
        // default, which blanks a field, then the two names of the API.
        await vm.ApiAddress.Should().BeEqualTo(string.Empty);
        await vm.ApiSni.Should().BeEqualTo(string.Empty);
        await vm.ApiHost.Should().BeEqualTo(string.Empty);
        await vm.ApiAddressHeldName.Should().BeEqualTo(ResUI.TbPresetDefault);
        await vm.ApiSniHeldName.Should().BeEqualTo(ResUI.TbPresetDefault);
        await vm.ApiHostHeldName.Should().BeEqualTo(ResUI.TbPresetDefault);
        await vm.ApiNameOptions.Should().BeEquivalentTo(
            [
                new ApiNameOption(string.Empty, ResUI.TbPresetDefault),
                new ApiNameOption(AetherKeys.DefaultApiHost, AetherKeys.DefaultApiHost),
                new ApiNameOption(AetherKeys.FallbackApiHost, AetherKeys.FallbackApiHost),
            ],
            CollectionOrdering.Matching);
        await vm.EchDns.Should().BeEqualTo("udp://1.1.1.1");
        await vm.EchDomain.Should().BeEqualTo("cloudflare-ech.com");
        await vm.ExitNode.IsFreedom.Should().BeTrue();
        await vm.FinalMask.Text.Should().BeEqualTo(string.Empty);
        await vm.DialMode.Text.Should().BeEqualTo(string.Empty);
        await vm.CommandText.Should().BeEqualTo(AetherKeys.BuiltCommand(source.Stored));
        await vm.CommandIsCustom.Should().BeFalse();
    }

    [Test]
    public async Task EachChangeIsKeptAndSaved()
    {
        var source = new FakeSource();
        var vm = await Window(source);

        vm.Kind = AetherKeyKind.Mim;
        vm.ApiAddress = "188.114.97.6:443";
        vm.ApiSni = "api.devices.cloudflare.com";
        vm.ApiHost = "api.devices.cloudflare.com";
        vm.Ech = true;
        vm.EchDns = "https://1.1.1.1/dns-query";
        vm.EchDomain = "example.com";
        vm.FingerprintIndex = AetherFingerprint.All.ToList().IndexOf(AetherFingerprint.SemiPython);
        vm.FinalMask.Text = """{"tcp": []}""";
        vm.DialMode.Text = "ForceIP";

        var expected = new AetherKeysSettings
        {
            Kind = AetherKeyKind.Mim,
            EnrollAddress = "188.114.97.6:443",
            ApiSni = "api.devices.cloudflare.com",
            ApiHost = "api.devices.cloudflare.com",
            Ech = true,
            EchDns = "https://1.1.1.1/dns-query",
            EchDomain = "example.com",
            Fingerprint = AetherFingerprint.SemiPython,
            FinalMask = """{"tcp": []}""",
            DialMode = "ForceIP",
        };
        await vm.Settings.Should().BeEqualTo(expected);
        await source.Saved.Count.Should().BeEqualTo(10);
        await source.Saved.Last().Should().BeEqualTo(expected);

        // A change to what is already there saves nothing, nor does a list that picks nothing for a moment.
        vm.Kind = AetherKeyKind.Mim;
        vm.FingerprintIndex = -1;
        vm.ApiAddress = "188.114.97.6:443";
        vm.ApiHost = "api.devices.cloudflare.com";
        await source.Saved.Count.Should().BeEqualTo(10);
    }

    [Test]
    public async Task DefaultInTheListsOfTheApiFieldsBlanksThemForTheCoresOwn()
    {
        var source = new FakeSource();
        var vm = await Window(source);
        vm.ApiAddress = "188.114.97.6:443";
        vm.ApiSni = AetherKeys.FallbackApiHost;
        vm.ApiHost = AetherKeys.FallbackApiHost;
        await Arguments(vm.Settings).Contains("--api-sni").Should().BeTrue();
        // What a field holds then is its text: nothing shows under it.
        await vm.ApiAddressHeldName.Should().BeNull();
        await vm.ApiSniHeldName.Should().BeNull();
        await vm.ApiHostHeldName.Should().BeNull();

        // A pick puts its value in the field, and default's is blank, whatever name the list shows it by.
        var picked = vm.ApiNameOptions[0];
        await picked.Display.Should().BeEqualTo(ResUI.TbPresetDefault);
        vm.ApiAddress = picked.Value;
        vm.ApiSni = picked.Value;
        vm.ApiHost = picked.Value;

        await vm.Settings.EnrollAddress.Should().BeEqualTo(string.Empty);
        await vm.Settings.ApiSni.Should().BeEqualTo(string.Empty);
        await vm.Settings.ApiHost.Should().BeEqualTo(string.Empty);
        await source.Saved.Last().Should().BeEqualTo(vm.Settings);
        await Arguments(vm.Settings).Contains("--api-").Should().BeFalse();
        await vm.ApiAddressHeldName.Should().BeEqualTo(ResUI.TbPresetDefault);
        await vm.ApiSniHeldName.Should().BeEqualTo(ResUI.TbPresetDefault);
        await vm.ApiHostHeldName.Should().BeEqualTo(ResUI.TbPresetDefault);

        // Spaces alone are blank too, as the core leaves them out, as a preset field has them.
        vm.ApiHost = "  ";
        await vm.ApiHostHeldName.Should().BeEqualTo(ResUI.TbPresetDefault);
        await Arguments(vm.Settings).Contains("--api-host").Should().BeFalse();
    }

    [Test]
    public async Task ACommandWrittenBackToTheBuiltOneFollowsTheSettingsAgain()
    {
        var source = new FakeSource();
        var vm = await Window(source);
        var built = AetherKeys.BuiltCommand(vm.Settings);

        vm.CommandText = $"{built} --tor-reverse";
        await vm.Settings.Command.Should().BeEqualTo($"{built} --tor-reverse");
        await AetherKeys.IsCustom(vm.Settings).Should().BeTrue();
        await vm.CommandIsCustom.Should().BeTrue();

        vm.CommandText = built;
        await vm.Settings.Command.Should().BeEqualTo(string.Empty);
        await vm.CommandIsCustom.Should().BeFalse();

        vm.CommandText = "aether --register wg";
        await vm.UseSettingsCmd.Execute().ToTask();
        await vm.Settings.Command.Should().BeEqualTo(string.Empty);
        await source.Saved.Last().Should().BeEqualTo(new AetherKeysSettings());
        // The box shows the command the settings build again, and handing it back is no edit.
        await vm.CommandText.Should().BeEqualTo(AetherKeys.BuiltCommand(vm.Settings));
        var saves = source.Saved.Count;
        vm.CommandText = vm.CommandText;
        await source.Saved.Count.Should().BeEqualTo(saves);
    }

    [Test]
    public async Task GettingKeysRunsTheSettingsAndShowsTheNewKeysOnceTheyAreInPlace()
    {
        var pending = new TaskCompletionSource<List<AetherKey>?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var source = new FakeSource
        {
            Stored = new AetherKeysSettings
            {
                Kind = AetherKeyKind.Gool, Fingerprint = AetherFingerprint.Firefox, FinalMask = """{"tcp": []}""", DialMode = "ForceIP",
            },
        };
        source.Renewer = async (onOutput, _) =>
        {
            onOutput("[2026-10-03T10:00:00.000Z INFO  aether] [+] identities ready: wireguard, wireguard inner");
            return await pending.Task;
        };
        var vm = await Window(source);
        var opened = Texts(vm);

        var run = vm.GetKeysAsync();
        await vm.IsRenewing.Should().BeTrue();
        await vm.CanGetKeys.Should().BeFalse();
        await vm.GetKeysText.Should().BeEqualTo(ResUI.TbAetherRenewing);
        await source.Runs.Should().BeEquivalentTo(
            [new Run(AetherKeyKind.Gool, Arguments(source.Stored), new AetherExit("""{"tcp": []}""", "ForceIP"))],
            CollectionOrdering.Matching);
        // The settings stay as the run took them while it goes on.
        vm.FingerprintIndex = AetherFingerprint.All.ToList().IndexOf(AetherFingerprint.Chrome);
        await vm.Settings.Fingerprint.Should().BeEqualTo(AetherFingerprint.Firefox);
        await vm.FingerprintIndex.Should().BeEqualTo(AetherFingerprint.All.ToList().IndexOf(AetherFingerprint.Firefox));
        await source.Saved.Should().BeEmpty();

        var shown = await Notices(async () =>
        {
            pending.SetResult(
            [
                new AetherKey(AetherPaths.WireGuardFile, NewKey),
                new AetherKey(AetherPaths.WireGuardInnerFile, NewKey),
            ]);
            await Over(run);
        });

        await vm.IsRenewing.Should().BeFalse();
        await vm.GetKeysText.Should().BeEqualTo(ResUI.TbAetherGetKeys);
        await shown.Should().Contain(ResUI.MsgAetherKeyRenewed);
        await Texts(vm).Should().BeEquivalentTo(
            [
                .. opened,
                ResUI.MsgAetherKeyRenewing,
                "[+] identities ready: wireguard, wireguard inner",
                ResUI.MsgAetherKeyRenewed,
                string.Format(ResUI.MsgAetherKeyWireguardReady, "f6e5d4c3…", "172.16.0.2", "2606:4700:110:8a36::2"),
                string.Format(ResUI.MsgAetherKeyWireguardInnerReady, "f6e5d4c3…", "172.16.0.2", "2606:4700:110:8a36::2"),
            ],
            CollectionOrdering.Matching);

        // The window stays, for keys of another kind.
        vm.Kind = AetherKeyKind.Masque;
        source.Renewer = (_, _) => Task.FromResult<List<AetherKey>?>(null);
        await vm.GetKeysAsync();
        await source.Runs.Last().Kind.Should().BeEqualTo(AetherKeyKind.Masque);
    }

    [Test]
    public async Task ACommandWrittenByHandRunsAsWrittenWithTheKeysItNames()
    {
        var source = new FakeSource
        {
            Stored = new AetherKeysSettings { EnrollAddress = "-x", Command = "aether --register mim --psiphon-reverse" },
        };
        var vm = await Window(source);

        await vm.GetKeysAsync();

        await source.Runs.Should().BeEquivalentTo(
            [new Run(AetherKeyKind.Mim, "--register mim --psiphon-reverse", new AetherExit())],
            CollectionOrdering.Matching);
    }

    [Test]
    public async Task TheProfilesThatCanBeTheExitNodeAreReadAndWhatIsChosenIsKept()
    {
        var source = new FakeSource { Nodes = [new AetherExitNode("germany", 1)] };
        var vm = await Window(source);
        await vm.ExitNode.Nodes!.ToList().Should().BeEquivalentTo(source.Nodes, CollectionOrdering.Matching);
        await vm.ExitNode.Labels.ToList().Should().BeEquivalentTo([ResUI.TbAetherExitNodeFreedom, "germany"], CollectionOrdering.Matching);

        vm.ExitNode.SelectedIndex = 1;
        vm.Fragment = true;
        vm.FragmentSize = "8-16";
        vm.FragmentDelay = "5";
        var kept = new AetherKeysSettings { ExitNode = "germany", Fragment = true, FragmentSize = "8-16", FragmentDelay = "5" };
        await vm.Settings.Should().BeEqualTo(kept);
        await source.Saved.Last().Should().BeEqualTo(kept);
        // A profile as the exit-node leaves the finalMask and the dialMode out of use.
        await vm.ExitNode.IsFreedom.Should().BeFalse();
        await vm.Settings.Exit.Should().BeEqualTo(new AetherExit(Node: "germany"));

        vm.ExitNode.SelectedIndex = 0;
        await source.Saved.Last().ExitNode.Should().BeEqualTo(string.Empty);
        await vm.ExitNode.IsFreedom.Should().BeTrue();
    }

    [Test]
    public async Task ARunDoesNotDialOutThroughAnExitNodeNameThatFindsNoProfileOrSeveral()
    {
        var source = new FakeSource { Stored = new AetherKeysSettings { ExitNode = " germany " } };
        var vm = await Window(source);

        // Renamed or deleted since the window opened.
        var shown = await Notices(vm.GetKeysAsync);
        await shown.Should().Contain(string.Format(ResUI.MsgAetherExitNodeNotFound, "germany"));
        await source.Runs.Should().BeEmpty();
        await vm.IsRenewing.Should().BeFalse();

        // The name of two profiles by now.
        source.Found["germany"] = ExitNodeLookup.SameName.Instance;
        shown = await Notices(vm.GetKeysAsync);
        await shown.Should().Contain(string.Format(ResUI.MsgAetherExitNodeDuplicate, "germany"));
        await source.Runs.Should().BeEmpty();

        // Once one profile has it, the run dials out through it.
        source.Found["germany"] = new ExitNodeLookup.One(new ProfileItem { Remarks = "germany" }, "content");
        await vm.GetKeysAsync();
        await source.Runs.Single().Exit.Should().BeEqualTo(new AetherExit(Node: "germany"));
    }

    [Test]
    public async Task AFragmentShapeThatIsNoRangeIsToldAndNothingRuns()
    {
        var source = new FakeSource { Stored = new AetherKeysSettings { Fragment = true, FragmentSize = "0" } };
        var vm = await Window(source);

        var shown = await Notices(vm.GetKeysAsync);

        await shown.Should().Contain(ResUI.MsgAetherInvalidFragment);
        await source.Runs.Should().BeEmpty();
    }

    [Test]
    public async Task SettingsThatCannotRunAreToldAndNothingRuns()
    {
        var source = new FakeSource();
        var vm = await Window(source);
        var opened = Texts(vm);

        vm.ApiAddress = "-x";
        var shown = await Notices(vm.GetKeysAsync);
        await shown.Should().Contain(ResUI.MsgAetherKeysInvalidApiAddress);

        vm.ApiAddress = string.Empty;
        vm.ApiSni = "162.159.137.105";
        shown = await Notices(vm.GetKeysAsync);
        await shown.Should().Contain(ResUI.MsgAetherKeysInvalidApiSni);

        vm.ApiSni = string.Empty;
        vm.ApiHost = "https://api.devices.cloudflare.com";
        shown = await Notices(vm.GetKeysAsync);
        await shown.Should().Contain(ResUI.MsgAetherKeysInvalidApiHost);

        vm.ApiHost = string.Empty;
        vm.CommandText = "aether --protocol wg";
        shown = await Notices(vm.GetKeysAsync);
        await shown.Should().Contain(ResUI.MsgAetherKeysInvalidCommand);

        await source.Runs.Should().BeEmpty();
        await vm.IsRenewing.Should().BeFalse();
        await Texts(vm).Should().BeEquivalentTo(opened, CollectionOrdering.Matching);
    }

    [Test]
    public async Task EachProblemHasItsMessage()
    {
        await AetherKeysViewModel.MessageOf(AetherKeysProblem.InvalidEnrollAddress).Should().BeEqualTo(ResUI.MsgAetherKeysInvalidApiAddress);
        await AetherKeysViewModel.MessageOf(AetherKeysProblem.InvalidApiSni).Should().BeEqualTo(ResUI.MsgAetherKeysInvalidApiSni);
        await AetherKeysViewModel.MessageOf(AetherKeysProblem.InvalidApiHost).Should().BeEqualTo(ResUI.MsgAetherKeysInvalidApiHost);
        await AetherKeysViewModel.MessageOf(AetherKeysProblem.InvalidFragment).Should().BeEqualTo(ResUI.MsgAetherInvalidFragment);
        await AetherKeysViewModel.MessageOf(AetherKeysProblem.InvalidEchDns).Should().BeEqualTo(ResUI.MsgAetherInvalidEchDns);
        await AetherKeysViewModel.MessageOf(AetherKeysProblem.InvalidEchDomain).Should().BeEqualTo(ResUI.MsgAetherInvalidEchDomain);
        // Named by its label, as the Aether editor names it.
        await AetherKeysViewModel.MessageOf(AetherKeysProblem.InvalidFinalMask).Should()
            .BeEqualTo(string.Format(ResUI.MsgInvalidProperty, ResUI.TbAetherExitFinalMask));
        await AetherKeysViewModel.MessageOf(AetherKeysProblem.InvalidCommand).Should().BeEqualTo(ResUI.MsgAetherKeysInvalidCommand);
        foreach (var problem in Enum.GetValues<AetherKeysProblem>())
        {
            await string.IsNullOrWhiteSpace(AetherKeysViewModel.MessageOf(problem)).Should().BeFalse().Because(problem.ToString());
        }
    }

    [Test]
    public async Task ASessionKeepsTheKeysItUsesButNotTheOthers()
    {
        var source = new FakeSource();
        var vm = await Window(source);
        var opened = Texts(vm);

        // Every key would be replaced, the session's among them.
        source.Session = AetherProtocol.Masque;
        await vm.GetKeysAsync();
        await source.Runs.Should().BeEmpty();
        await vm.SessionProtocol.Should().BeEqualTo(AetherProtocol.Masque);
        await vm.IsRenewing.Should().BeFalse();
        var blocked = vm.Log.Entries.Last();
        await blocked.Text.Should().BeEqualTo(ResUI.MsgAetherRenewBlocked);
        await blocked.Priority.Should().BeEqualTo(AetherLogPriority.Warn);
        await Texts(vm).Count.Should().BeEqualTo(opened.Count + 1);

        // The WireGuard keys are not the session's.
        vm.Kind = AetherKeyKind.Gool;
        await vm.GetKeysAsync();
        await source.Runs.Single().Kind.Should().BeEqualTo(AetherKeyKind.Gool);

        source.Session = null;
        source.RaiseSessionChanged();
        await vm.SessionProtocol.Should().BeNull();
    }

    [Test]
    public async Task AFailedRunSaysTheKeysInUseWereKept()
    {
        var vm = await Window(new FakeSource());

        var shown = await Notices(vm.GetKeysAsync);

        await vm.IsRenewing.Should().BeFalse();
        await shown.Should().NotContain(ResUI.MsgAetherKeyRenewed);
        var failure = vm.Log.Entries.Last();
        await failure.Text.Should().BeEqualTo(ResUI.MsgAetherKeyRenewFailed);
        await failure.Priority.Should().BeEqualTo(AetherLogPriority.Error);
    }

    [Test]
    public async Task CancellingStopsTheRunAndShowsTheKeysThatChanged()
    {
        var stopped = false;
        var source = new FakeSource();
        source.Renewer = async (_, ct) =>
        {
            try
            {
                // The new keys were in place by the time the run was stopped.
                source.InUse = source.InUse.Select(key => key.File == AetherPaths.MasqueFile ? new AetherKey(key.File, NewKey) : key).ToList();
                await Task.Delay(Timeout.Infinite, ct);
                return null;
            }
            finally
            {
                stopped = true;
            }
        };
        var vm = await Window(source);
        var opened = Texts(vm);

        var shown = await Notices(async () =>
        {
            var run = vm.GetKeysAsync();
            vm.Cancel();
            await Over(run);
        });

        await stopped.Should().BeTrue();
        await vm.IsRenewing.Should().BeFalse();
        await shown.Should().NotContain(ResUI.MsgAetherKeyRenewed);
        var cancelled = vm.Log.Entries.First(entry => entry.Text == ResUI.MsgAetherKeyRenewCancelled);
        await cancelled.Priority.Should().BeEqualTo(AetherLogPriority.Warn);
        await Texts(vm).Should().BeEquivalentTo(
            [
                .. opened,
                ResUI.MsgAetherKeyRenewing,
                ResUI.MsgAetherKeyRenewCancelled,
                string.Format(ResUI.MsgAetherKeyMasqueReady, "f6e5d4c3…", "172.16.0.2", "2606:4700:110:8a36::2"),
            ],
            CollectionOrdering.Matching);
        await opened.First().Should().BeEqualTo(Missing(AetherPaths.WireGuardFile));
    }

    [Test]
    public async Task ACancelledRunStaysBusyUntilItHasStopped()
    {
        var stopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var source = new FakeSource { Renewer = UntilCancelled(stopped.Task) };
        var vm = await Window(source);

        var run = vm.GetKeysAsync();
        vm.Cancel();

        // Nothing else starts, nothing changes, and a second cancel adds nothing.
        await vm.IsRenewing.Should().BeTrue();
        await vm.GetKeysAsync();
        vm.Kind = AetherKeyKind.WireGuard;
        vm.Cancel();
        await source.Runs.Count.Should().BeEqualTo(1);
        await vm.Settings.Kind.Should().BeEqualTo(AetherKeyKind.AllKeys);
        await vm.KindOptions.Single(option => option.IsChecked).Kind.Should().BeEqualTo(AetherKeyKind.AllKeys);
        await Texts(vm).Count(text => text == ResUI.MsgAetherKeyRenewCancelled).Should().BeEqualTo(1);

        stopped.SetResult();
        await Over(run);

        await vm.IsRenewing.Should().BeFalse();
        source.Renewer = (_, _) => Task.FromResult<List<AetherKey>?>(null);
        await vm.GetKeysAsync();
        await source.Runs.Count.Should().BeEqualTo(2);
    }

    [Test]
    public async Task CancellingWhenNoRunGoesOnDoesNothing()
    {
        var source = new FakeSource();
        var vm = await Window(source);
        var opened = Texts(vm);
        vm.Cancel();
        await Texts(vm).Should().BeEquivalentTo(opened, CollectionOrdering.Matching);

        source.Renewer = (_, _) => Task.FromResult<List<AetherKey>?>([new AetherKey(AetherPaths.MasqueFile, NewKey)]);
        vm.Kind = AetherKeyKind.Masque;
        await vm.GetKeysAsync();
        var finished = Texts(vm);
        vm.Cancel();

        await Texts(vm).Should().BeEquivalentTo(finished, CollectionOrdering.Matching);
        await finished.Last().Should().BeEqualTo(string.Format(ResUI.MsgAetherKeyMasqueReady, "f6e5d4c3…", "172.16.0.2", "2606:4700:110:8a36::2"));
    }

    #endregion PattNG AetherKeysViewModelTest

    #region PattN

    // keys-1: the window's own source reads its settings from the app settings, and puts them back there before the
    // settings file is written; a test's writes no file.
    [Test]
    public async Task TheWindowsOwnSourceKeepsItsSettingsInTheAppSettings()
    {
        var config = CoreConfigTestFactory.CreateConfig();
        config.AetherItem = new AetherItem { PsiphonRegions = "DE,US", KeysKind = "masque", KeysExitNode = "germany", KeysCommand = "aether --register masque" };
        var written = new List<Config>();
        var source = new AetherKeysSource(config, saved =>
        {
            written.Add(saved);
            return Task.FromResult(0);
        });

        var loaded = source.LoadSettings();
        await loaded.Should().BeEqualTo(new AetherKeysSettings { Kind = AetherKeyKind.Masque, ExitNode = "germany", Command = "aether --register masque" });

        await source.SaveSettingsAsync(loaded with { Kind = AetherKeyKind.WireGuard, ExitNode = "spain" });
        await written.Count.Should().BeEqualTo(1);
        await ReferenceEquals(written[0], config).Should().BeTrue();
        await config.AetherItem!.KeysKind.Should().BeEqualTo("wg");
        await config.AetherItem!.KeysExitNode.Should().BeEqualTo("spain");
        await config.AetherItem!.PsiphonRegions.Should().BeEqualTo("DE,US");
        await source.LoadSettings().Should().BeEqualTo(loaded with { Kind = AetherKeyKind.WireGuard, ExitNode = "spain" });

        // Settings never stored read as the defaults, and the first save makes a place for them. A file that could not be
        // written leaves them in the app settings all the same.
        var fresh = CoreConfigTestFactory.CreateConfig();
        fresh.AetherItem = null;
        var unwritten = new AetherKeysSource(fresh, _ => Task.FromResult(-1));
        await unwritten.LoadSettings().Should().BeEqualTo(new AetherKeysSettings());
        await unwritten.SaveSettingsAsync(new AetherKeysSettings { Kind = AetherKeyKind.Gool });
        await (fresh.AetherItem?.KeysKind).Should().BeEqualTo("gool");
    }

    [Test]
    public async Task TheSettingsAreKeptInTheAppSettingsWithTheEchDefaultsLeftOut()
    {
        // Never stored, each reads as its default.
        await AetherKeysSource.SettingsOf(null).Should().BeEqualTo(new AetherKeysSettings());
        await AetherKeysSource.SettingsOf(new AetherItem()).Should().BeEqualTo(new AetherKeysSettings());

        var settings = new AetherKeysSettings
        {
            Kind = AetherKeyKind.WgOverMasque,
            EnrollAddress = string.Empty,
            ApiSni = " front.example.com ",
            ApiHost = "api.devices.cloudflare.com",
            Fragment = true,
            FragmentSize = "8-16",
            FragmentDelay = " 5 ",
            Ech = true,
            EchDns = " udp://1.1.1.1 ",
            EchDomain = "crypto.cloudflare.com ",
            Fingerprint = AetherFingerprint.Go,
            ExitNode = "germany",
            FinalMask = """{"tcp": []}""",
            DialMode = "ForceIP",
            Command = "aether --register wg",
        };
        var item = new AetherItem { PsiphonRegions = "DE,US" };
        AetherKeysSource.Store(item, settings);

        await item.KeysKind.Should().BeEqualTo("wg-over-masque");
        await item.KeysFingerprint.Should().BeEqualTo("go");
        // A blank API address stays blank, which sends none: the core's own address.
        await item.KeysApiAddress.Should().BeEqualTo(string.Empty);
        // The server name and the host are kept as written, as the API address is.
        await item.KeysApiSni.Should().BeEqualTo(" front.example.com ");
        await item.KeysApiHost.Should().BeEqualTo("api.devices.cloudflare.com");
        await item.KeysFragmentDelay.Should().BeEqualTo(" 5 ");
        // The ECH DNS and domain are stored trimmed, and the default not at all, so that it follows the default.
        await item.KeysEchDns.Should().BeNull();
        await item.KeysEchDomain.Should().BeEqualTo("crypto.cloudflare.com");
        // What the app keeps beside them stays.
        await item.PsiphonRegions.Should().BeEqualTo("DE,US");

        // Through the settings file and back.
        var read = AetherKeysSource.SettingsOf(JsonUtils.Deserialize<AetherItem>(JsonUtils.Serialize(item)));
        await read.Should().BeEqualTo(settings with { EchDns = AetherArguments.DefaultEchDns, EchDomain = "crypto.cloudflare.com" });

        // A blank ECH DNS is stored as none as well, and a kind or a fingerprint no build wrote reads as the default.
        AetherKeysSource.Store(item, settings with { EchDns = "  " });
        await item.KeysEchDns.Should().BeNull();
        item.KeysKind = "from-a-newer-version";
        item.KeysFingerprint = "lynx";
        await AetherKeysSource.SettingsOf(item).Kind.Should().BeEqualTo(AetherKeyKind.AllKeys);
        await AetherKeysSource.SettingsOf(item).Fingerprint.Should().BeEqualTo(AetherFingerprint.Chrome);
    }

    [Test]
    public async Task TheKindsAreRadiosThatFollowTheSettings()
    {
        var source = new FakeSource();
        var vm = await Window(source);

        await vm.KindOptions.Select(option => option.Label).ToList().Should().BeEquivalentTo(
            [ResUI.TbAetherKeysKindAll, "WireGuard", "MASQUE", "WARP-in-WARP", "MASQUE-in-MASQUE", "WireGuard over MASQUE"],
            CollectionOrdering.Matching);
        await vm.KindOptions.Select(option => option.Kind).ToList().Should().BeEquivalentTo(AetherKeyKind.All.ToList(), CollectionOrdering.Matching);
        await vm.KindOptions[0].IsChecked.Should().BeTrue();

        // A click takes its kind; the radio it unchecks is no choice of its own.
        vm.KindOptions[2].IsChecked = true;
        vm.KindOptions[0].IsChecked = false;
        await vm.Kind.Should().BeEqualTo(AetherKeyKind.Masque);
        await vm.KindOptions.Single(option => option.IsChecked).Kind.Should().BeEqualTo(AetherKeyKind.Masque);
        await source.Saved.Count.Should().BeEqualTo(1);
        await source.Saved.Last().Kind.Should().BeEqualTo(AetherKeyKind.Masque);

        // A kind set otherwise shows on the radios.
        vm.Kind = AetherKeyKind.WgOverMasque;
        await vm.KindOptions.Single(option => option.IsChecked).Kind.Should().BeEqualTo(AetherKeyKind.WgOverMasque);

        // While a run goes on, a click is undone.
        var stopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        source.Renewer = UntilCancelled(stopped.Task);
        var run = vm.GetKeysAsync();
        vm.KindOptions[1].IsChecked = true;
        await vm.Kind.Should().BeEqualTo(AetherKeyKind.WgOverMasque);
        await vm.KindOptions.Single(option => option.IsChecked).Kind.Should().BeEqualTo(AetherKeyKind.WgOverMasque);
        vm.Cancel();
        stopped.SetResult();
        await Over(run);
        await source.Saved.Count.Should().BeEqualTo(2);
    }

    [Test]
    public async Task GettingKeysWaitsForTheCoreAndForASessionOnTheirKeysToEnd()
    {
        var source = new FakeSource { Session = AetherProtocol.Masque };
        var vm = await Window(source);

        // Every key, the session's among them.
        await vm.SessionProtocol.Should().BeEqualTo(AetherProtocol.Masque);
        await vm.Blocked.Should().BeTrue();
        await vm.CanGetKeys.Should().BeFalse();

        vm.Kind = AetherKeyKind.WireGuard;
        await vm.Blocked.Should().BeFalse();
        await vm.CanGetKeys.Should().BeTrue();

        // A command written by hand counts by the keys it names.
        vm.CommandText = "aether --register mim";
        await vm.Blocked.Should().BeTrue();
        await vm.UseSettingsCmd.Execute().ToTask();
        await vm.Blocked.Should().BeFalse();

        // The session is followed as it ends, and as it starts.
        vm.Kind = AetherKeyKind.AllKeys;
        await vm.Blocked.Should().BeTrue();
        source.Session = null;
        source.RaiseSessionChanged();
        await vm.Blocked.Should().BeFalse();
        await vm.CanGetKeys.Should().BeTrue();
        source.Session = AetherProtocol.WgOverMasque;
        source.RaiseSessionChanged();
        await vm.Blocked.Should().BeTrue();

        // Without the core, nothing can run.
        var none = await Window(new FakeSource { Available = false });
        await none.CoreAvailable.Should().BeFalse();
        await none.Blocked.Should().BeFalse();
        await none.CanGetKeys.Should().BeFalse();
    }

    [Test]
    public async Task ClosingTheWindowCancelsTheRunAndStopsFollowingTheSession()
    {
        var cancelled = false;
        var source = new FakeSource { Renewer = UntilCancelled(onStop: () => cancelled = true) };
        var vm = await Window(source);
        await source.Followed.Should().BeTrue();
        var run = vm.GetKeysAsync();
        await vm.IsRenewing.Should().BeTrue();

        vm.OnClosed();
        await Over(run);

        await cancelled.Should().BeTrue();
        await vm.IsRenewing.Should().BeFalse();
        await source.Followed.Should().BeFalse();
        // The window is gone: no word of a cancel the user asked for, and nothing more runs.
        await Texts(vm).Should().NotContain(ResUI.MsgAetherKeyRenewCancelled);
        await vm.GetKeysAsync();
        await source.Runs.Count.Should().BeEqualTo(1);
    }

    [Test]
    public async Task TheFinalMaskIsAPresetFieldThatIsSavedAndCheckedAsTheEditorChecksIt()
    {
        var source = new FakeSource();
        var vm = await Window(source);

        await vm.FinalMask.Setting.Should().BeEqualTo("finalMask");
        await vm.FinalMask.ChooseAtAsync(1);
        await vm.Settings.FinalMask.Should().BeEqualTo(FieldPresets.FinalMask.TextOf(0));
        await source.Saved.Last().FinalMask.Should().BeEqualTo(FieldPresets.FinalMask.TextOf(0));

        // A broken one is refused, whatever the exit-node.
        vm.FinalMask.Text = "{";
        var shown = await Notices(vm.GetKeysAsync);
        await shown.Should().Contain(string.Format(ResUI.MsgInvalidProperty, ResUI.TbAetherExitFinalMask));
        await source.Runs.Should().BeEmpty();
    }

    [Test]
    public async Task TheDialModeIsAPresetFieldThatIsSaved()
    {
        var source = new FakeSource { Stored = new AetherKeysSettings { DialMode = FieldPresets.DialMode.TextOf(0)! } };
        var vm = await Window(source);

        await vm.DialMode.Setting.Should().BeEqualTo("dialMode");
        await vm.DialMode.Text.Should().BeEqualTo(FieldPresets.DialMode.TextOf(0));
        await vm.DialMode.Matched;
        await vm.DialMode.HeldName.Should().BeEqualTo(FieldPresets.DialMode.Names[0]);
        // Default blanks it, which is saved; a pick puts the preset back.
        await vm.DialMode.ChooseAtAsync(0);
        await vm.Settings.DialMode.Should().BeEqualTo(string.Empty);
        await source.Saved.Last().DialMode.Should().BeEqualTo(string.Empty);
        await vm.DialMode.ChooseAtAsync(1);
        await vm.Settings.DialMode.Should().BeEqualTo(FieldPresets.DialMode.TextOf(0));
    }

    #endregion PattN
}
