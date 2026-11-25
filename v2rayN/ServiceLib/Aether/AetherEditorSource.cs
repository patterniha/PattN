namespace ServiceLib.Aether;

/// <summary>What the Aether editor finds in the core folder as it opens (PattNG isSupported, isPsiphonSupported, isTorTransportsSupported).</summary>
public sealed record AetherEditorAvailability(bool Core, bool Psiphon, bool TorTransports);

/// <summary>
/// PattN: what the Aether editor reads and runs beyond its own fields (PattNG ui/server/AetherEditorRepository.kt,
/// AetherEditorSource): the programs of the core folder, the live session, the keys, the exit-nodes, a scan, the Psiphon
/// data. <see cref="AetherEditorSource" /> is PattN's own; the tests give one of theirs, which reaches no network and runs
/// no core.
/// </summary>
public interface IAetherEditorSource
{
    /// <summary>The Aether listen port of the settings, which the command of a profile is built on.</summary>
    int ListenPort { get; }

    /// <summary>
    /// The loopback ports the core of a profile cannot listen on (design 3.2.4, critique 10): the local ports of the app,
    /// the mixed port and the six after it, and the port of the secondary-socks inbound the core dials out through.
    /// </summary>
    IReadOnlyCollection<int> TakenPorts { get; }

    /// <summary>The protocol of the live session, scanning or connected; null without one.</summary>
    AetherProtocol? SessionProtocol { get; }

    /// <summary>Raised, on any thread, when a session starts or ends (see <see cref="AetherCoreManager.SessionChanged" />).</summary>
    event Action? SessionChanged;

    /// <summary>Which programs the core folder holds; read off the UI thread.</summary>
    Task<AetherEditorAvailability> AvailabilityAsync();

    /// <summary>
    /// The exit countries on offer, ISO codes sorted: those of the Psiphon server list in the Aether folder and those
    /// Psiphon last reported.
    /// </summary>
    Task<List<string>> PsiphonRegionsAsync();

    /// <summary>The names of the profiles a core can dial out through in place of freedom, see <see cref="AetherExit.NodesOf" />.</summary>
    Task<List<AetherExitNode>> ExitNodesAsync();

    /// <summary>What the profile named <paramref name="name" /> gives as the exit-node now, as a session looks it up.</summary>
    Task<ExitNodeLookup> FindExitNodeAsync(string name);

    /// <summary>Which of <paramref name="files" />, key files of the identity folder, are not there or not readable as keys.</summary>
    Task<List<string>> MissingKeysAsync(IReadOnlyList<string> files);

    /// <summary>The keys a tunnel of <paramref name="protocol" /> uses.</summary>
    Task<AetherIdentityStatus> IdentityStatusAsync(AetherProtocol protocol);

    /// <summary>Scans for an endpoint of <paramref name="profile" />, see <see cref="AetherScanner.ScanAsync(ProfileItem, Action{string}?, CancellationToken)" />.</summary>
    Task<AetherRunResult<AetherScanResult>> ScanAsync(ProfileItem profile, Action<string> onOutput, CancellationToken ct);

    /// <summary>Forgets what Psiphon has learned, unless a core runs on it, see <see cref="AetherCoreManager.ClearPsiphonData" />.</summary>
    Task<AetherPsiphonClear> ClearPsiphonDataAsync();

    /// <summary>Stores <paramref name="profile" />, normalized, as a new or an edited profile; true once it is stored.</summary>
    Task<bool> SaveAsync(ProfileItem profile);
}

/// <summary>The Aether editor's source in PattN: the settings, the database, the core folder and the core manager.</summary>
public sealed class AetherEditorSource(Config config) : IAetherEditorSource
{
    private static AetherCoreManager Cores => AetherCoreManager.Instance;

    public int ListenPort => Cores.ListenPort;

    public IReadOnlyCollection<int> TakenPorts =>
        AetherPorts.LocalPortsOf(AppManager.Instance.GetLocalPort(EInboundProtocol.socks))
            .Append(AetherPorts.SecondarySocksPortOf(ListenPort))
            .ToHashSet();

    public AetherProtocol? SessionProtocol => Cores.Session?.Protocol;

    public event Action? SessionChanged
    {
        add => Cores.SessionChanged += value;
        remove => Cores.SessionChanged -= value;
    }

    public Task<AetherEditorAvailability> AvailabilityAsync()
    {
        return Task.Run(() => new AetherEditorAvailability(
            AetherBinaries.IsCoreAvailable(),
            AetherBinaries.IsPsiphonAvailable(),
            AetherBinaries.IsLyrebirdAvailable()));
    }

    public Task<List<string>> PsiphonRegionsAsync()
    {
        return Task.Run(() =>
        {
            var regions = new SortedSet<string>(StringComparer.Ordinal);
            try
            {
                var workDir = AetherPaths.WorkDir;
                Directory.CreateDirectory(workDir);
                var entries = PsiphonServerList.EntriesFile(workDir, workDir, onProblem: problem =>
                    Logging.SaveLog($"AetherEditor: {AetherPaths.PsiphonServersFileName} is not a usable Psiphon list", problem));
                if (entries != null)
                {
                    regions.UnionWith(PsiphonServerList.Regions(File.ReadAllText(entries)));
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Logging.SaveLog("AetherEditor: the Psiphon server list could not be read", ex);
            }
            regions.UnionWith(PsiphonServerList.Remembered(config.AetherItem));
            return regions.ToList();
        });
    }

    public async Task<List<AetherExitNode>> ExitNodesAsync()
    {
        return AetherExit.NodesOf(await ConfigDbQuery.ProfileItems(string.Empty) ?? []);
    }

    public async Task<ExitNodeLookup> FindExitNodeAsync(string name)
    {
        // As the exit of a scan or a key run looks it up (AetherExitService.GenerateAsync): in a context of its own, so
        // that a profile Xray cannot build, or whose ECH outbound cannot go beside it, is refused here as it is there.
        var (context, _) = await CoreConfigContextBuilder.Build(config, AetherExitHost.ContextProfile(), refuseRuleTargets: false);
        return await CoreConfigContextBuilder.LookUpAetherExitNodeAsync(context, name);
    }

    public Task<List<string>> MissingKeysAsync(IReadOnlyList<string> files)
    {
        return AetherIdentityManager.MissingAsync(files);
    }

    public Task<AetherIdentityStatus> IdentityStatusAsync(AetherProtocol protocol)
    {
        return AetherIdentityManager.StatusAsync(protocol);
    }

    public Task<AetherRunResult<AetherScanResult>> ScanAsync(ProfileItem profile, Action<string> onOutput, CancellationToken ct)
    {
        return AetherScanner.ScanAsync(profile, onOutput, ct);
    }

    public Task<AetherPsiphonClear> ClearPsiphonDataAsync()
    {
        return Task.Run(Cores.ClearPsiphonData);
    }

    public async Task<bool> SaveAsync(ProfileItem profile)
    {
        return await ConfigDbHandler.AddServer(profile) == 0;
    }
}
