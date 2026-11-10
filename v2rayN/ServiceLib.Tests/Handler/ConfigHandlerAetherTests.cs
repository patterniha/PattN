using ServiceLib.Tests.CoreConfig;

namespace ServiceLib.Tests.Handler;

// PattN: Aether profiles as ConfigHandler stores them: imported from aether:// links, a subscription's overrides
// applied as they come, Xray to run them, the columns they do not use cleared, told apart by every setting, and usable
// without an endpoint. Each test works in a subscription id of its own in the test database. The tests do not run beside
// others: sqlite-net shares one connection, whose multi-row inserts, each a transaction, cannot overlap.
[NotInParallel]
public class ConfigHandlerAetherTests
{
    private const string MasqueLink = "aether://162.159.198.1:443?protocol=masque&scan=verified&ip=both#WARP%20MASQUE";
    private const string ScanLink = "aether://?protocol=wg&scan=balanced#WARP%20scan";
    private const string HopsLink = "aether://?protocol=gool&outer=162.159.192.1%3A2408&inner=162.159.192.5%3A894#WARP%20hops";

    private static Config Setup()
    {
        var config = CoreConfigTestFactory.CreateConfig();
        CoreConfigTestFactory.BindAppManagerConfig(config);
        SQLiteHelper.Instance.CreateTable<SubItem>();
        SQLiteHelper.Instance.CreateTable<ProfileItem>();
        return config;
    }

    private static string NewSubId()
    {
        return $"sub-{Guid.NewGuid():N}";
    }

    private static async Task<List<ProfileItem>> Profiles(string subId)
    {
        return await AppManager.Instance.ProfileItems(subId) ?? [];
    }

    private static async Task AssertStoredAsAether(ProfileItem profile)
    {
        await profile.ConfigType.Should().BeEqualTo(EConfigType.Aether).Because(profile.Remarks);
        await profile.CoreType.Should().BeEqualTo(ECoreType.Xray).Because(profile.Remarks);
        await profile.Network.Should().BeEqualTo(Global.DefaultNetwork).Because(profile.Remarks);
        await profile.IsValid().Should().BeTrue().Because(profile.Remarks);
    }

    [Test]
    public async Task AetherLinksAreImportedAsAetherProfilesThatXrayRuns()
    {
        var config = Setup();
        var subId = NewSubId();

        var count = await ConfigHandler.AddBatchServers(config, string.Join("\n", MasqueLink, ScanLink, HopsLink), subId, false);
        var profiles = await Profiles(subId);

        await count.Should().BeEqualTo(3);
        await profiles.Count.Should().BeEqualTo(3);
        foreach (var profile in profiles)
        {
            await AssertStoredAsAether(profile);
            await profile.IsSub.Should().BeFalse();
        }

        var masque = profiles.Single(profile => profile.Remarks == "WARP MASQUE");
        await masque.Address.Should().BeEqualTo("162.159.198.1");
        await masque.Port.Should().BeEqualTo(443);
        await masque.GetProtocolExtra().AetherProtocol.Should().BeEqualTo("masque");
        await masque.GetProtocolExtra().AetherScanMode.Should().BeEqualTo("verified");
        await masque.GetProtocolExtra().AetherIpVersion.Should().BeEqualTo("both");

        var scan = profiles.Single(profile => profile.Remarks == "WARP scan");
        await scan.Address.Should().BeEqualTo(string.Empty);
        await scan.Port.Should().BeEqualTo(0);
        await scan.GetProtocolExtra().AetherProtocol.Should().BeEqualTo("wg");

        var hops = profiles.Single(profile => profile.Remarks == "WARP hops");
        await hops.Address.Should().BeEqualTo(string.Empty);
        await hops.Port.Should().BeEqualTo(0);
        await hops.GetProtocolExtra().AetherWiwOuter.Should().BeEqualTo("162.159.192.1:2408");
        await hops.GetProtocolExtra().AetherWiwInner.Should().BeEqualTo("162.159.192.5:894");
    }

    [Test]
    public async Task ASubscriptionsOverridesReachItsAetherProfilesAsTheyCome()
    {
        // As PattNG applies them: without a check, the core scanning when the address is no IP.
        var config = Setup();
        var subId = NewSubId();
        await SQLiteHelper.Instance.ReplaceAsync(new SubItem
        {
            Id = subId,
            Remarks = "aether",
            Url = "http://127.0.0.1/aether",
            OverrideAddress = " engage.cloudflareclient.com ",
            OverridePort = 2408,
        });

        var count = await ConfigHandler.AddBatchServers(config, Utils.Base64Encode(string.Join("\n", MasqueLink, ScanLink)), subId, true);
        var profiles = await Profiles(subId);

        await count.Should().BeEqualTo(2);
        await profiles.Count.Should().BeEqualTo(2);
        foreach (var profile in profiles)
        {
            await AssertStoredAsAether(profile);
            await profile.IsSub.Should().BeTrue();
            await profile.Address.Should().BeEqualTo("engage.cloudflareclient.com").Because(profile.Remarks);
            await profile.Port.Should().BeEqualTo(2408).Because(profile.Remarks);
        }
        await profiles.Single(profile => profile.Remarks == "WARP MASQUE").GetProtocolExtra().AetherProtocol.Should().BeEqualTo("masque");
    }

    [Test]
    public async Task AnAetherProfileKeepsItsSettingsAndItsEndpointAndNothingElse()
    {
        var config = Setup();
        var profile = AetherFmt.Resolve(MasqueLink, out _)!;
        profile.Subid = NewSubId();
        // What a profile of another type, or a hand-made one, may carry; none of it is an Aether setting.
        profile.CoreType = ECoreType.sing_box;
        profile.Address = " 162.159.198.1 ";
        profile.Password = "secret";
        profile.Username = "user";
        profile.Network = nameof(ETransport.ws);
        profile.StreamSecurity = Global.StreamSecurity;
        profile.Sni = "sni.example";
        profile.Alpn = "h2";
        profile.Fingerprint = "chrome";
        profile.CipherSuites = "TLS_AES_128_GCM_SHA256";
        profile.CurvePreferences = "X25519";
        profile.EnableSessionResumption = true;
        profile.AllowInsecure = Global.StringTrue;
        profile.PublicKey = "public-key";
        profile.ShortId = "short-id";
        profile.SpiderX = "/spider";
        profile.Mldsa65Verify = "mldsa";
        profile.Cert = "certificate";
        profile.CertSha = "sha";
        profile.EchConfigList = "cloudflare-ech.com+https://1.1.1.1/dns-query";
        profile.EchOutbound = """{"tag": "ech-out", "protocol": "freedom"}""";
        profile.VerifyPeerCertByName = "name.example";
        profile.MuxEnabled = true;
        profile.SetTransportExtra(new TransportExtraItem { Host = "host.example", Path = "/ws" });
        // What it keeps beside its Aether settings: the exit-node's finalMask and dialMode, its outbound's targetStrategy.
        profile.Finalmask = """{"tcp":[]}""";
        profile.DialMode = "code-1";
        profile.TargetStrategy = "UseIPv4";
        var extra = profile.GetProtocolExtra();

        await (await ConfigHandler.AddServer(config, profile)).Should().BeEqualTo(0);
        var stored = (await AppManager.Instance.GetProfileItem(profile.IndexId))!;

        await stored.Should().NotBeNull();
        await AssertStoredAsAether(stored);
        await stored.Address.Should().BeEqualTo("162.159.198.1");
        await stored.Port.Should().BeEqualTo(443);
        await (stored.GetProtocolExtra() == extra).Should().BeTrue();
        await stored.Finalmask.Should().BeEqualTo("""{"tcp":[]}""");
        await stored.DialMode.Should().BeEqualTo("code-1");
        await stored.TargetStrategy.Should().BeEqualTo("UseIPv4");
        foreach (var (name, value) in new (string, string?)[]
                 {
                     (nameof(ProfileItem.Password), stored.Password),
                     (nameof(ProfileItem.Username), stored.Username),
                     (nameof(ProfileItem.StreamSecurity), stored.StreamSecurity),
                     (nameof(ProfileItem.Sni), stored.Sni),
                     (nameof(ProfileItem.Alpn), stored.Alpn),
                     (nameof(ProfileItem.Fingerprint), stored.Fingerprint),
                     (nameof(ProfileItem.CipherSuites), stored.CipherSuites),
                     (nameof(ProfileItem.CurvePreferences), stored.CurvePreferences),
                     (nameof(ProfileItem.AllowInsecure), stored.AllowInsecure),
                     (nameof(ProfileItem.PublicKey), stored.PublicKey),
                     (nameof(ProfileItem.ShortId), stored.ShortId),
                     (nameof(ProfileItem.SpiderX), stored.SpiderX),
                     (nameof(ProfileItem.Mldsa65Verify), stored.Mldsa65Verify),
                     (nameof(ProfileItem.Cert), stored.Cert),
                     (nameof(ProfileItem.CertSha), stored.CertSha),
                     (nameof(ProfileItem.EchConfigList), stored.EchConfigList),
                     (nameof(ProfileItem.EchOutbound), stored.EchOutbound),
                     (nameof(ProfileItem.VerifyPeerCertByName), stored.VerifyPeerCertByName),
                 })
        {
            await value.IsNullOrEmpty().Should().BeTrue().Because($"{name}: {value}");
        }
        await stored.MuxEnabled.Should().BeNull();
        await stored.EnableSessionResumption.Should().BeFalse();
        await (stored.GetTransportExtra() == new TransportExtraItem()).Should().BeTrue();

        // An edit through the editor's path keeps the profile and takes its new settings.
        var edited = JsonUtils.DeepCopy(stored)!;
        edited.SetProtocolExtra(extra with { AetherProtocol = "wg", AetherScanMode = "thorough" });
        edited.Address = "162.159.192.1";
        edited.Port = 2408;
        edited.DialMode = string.Empty;

        await (await ConfigHandler.AddServer(config, edited)).Should().BeEqualTo(0);
        var stored2 = (await AppManager.Instance.GetProfileItem(profile.IndexId))!;

        await AssertStoredAsAether(stored2);
        await stored2.Address.Should().BeEqualTo("162.159.192.1");
        await stored2.Port.Should().BeEqualTo(2408);
        await stored2.GetProtocolExtra().AetherProtocol.Should().BeEqualTo("wg");
        await stored2.GetProtocolExtra().AetherScanMode.Should().BeEqualTo("thorough");
        await stored2.DialMode.Should().BeEqualTo(string.Empty);
        await stored2.Finalmask.Should().BeEqualTo("""{"tcp":[]}""");
    }

    [Test]
    public async Task AnAetherProfileIsStoredAsItComes()
    {
        // As PattNG imports a link: settings the core would not take are kept for the editor to refuse on its next
        // save, and nothing is normalized here.
        var config = Setup();
        var profile = new ProfileItem
        {
            ConfigType = EConfigType.Aether,
            Remarks = "broken",
            Subid = NewSubId(),
            Address = "not an address",
            Port = 0,
            Finalmask = "fragment",
        };
        profile.SetProtocolExtra(new ProtocolExtraItem
        {
            AetherProtocol = "masque",
            AetherMasqueSni = "not a domain",
            AetherFragmentSize = "0-99999",
            AetherDns = "dns.example",
        });
        var extra = profile.GetProtocolExtra();

        await (await ConfigHandler.AddAetherServer(config, profile)).Should().BeEqualTo(0);
        var stored = (await AppManager.Instance.GetProfileItem(profile.IndexId))!;

        await stored.Should().NotBeNull();
        await stored.Address.Should().BeEqualTo("not an address");
        await stored.Finalmask.Should().BeEqualTo("fragment");
        await (stored.GetProtocolExtra() == extra).Should().BeTrue();
    }

    [Test]
    public async Task DuplicateAetherProfilesAreThoseWithEverySettingAlike()
    {
        var config = Setup();
        var subId = NewSubId();
        string[] links =
        [
            MasqueLink,
            // The same profile under another name: a duplicate.
            "aether://162.159.198.1:443?protocol=masque&scan=verified&ip=both#Copy",
            // Each differs from it in one setting.
            "aether://162.159.198.1:443?protocol=masque&scan=thorough&ip=both#Scan%20mode",
            "aether://162.159.198.1:443?protocol=masque&scan=verified&ip=both&dialMode=code-1#Dial%20mode",
            "aether://162.159.198.1:443?protocol=masque&scan=verified&ip=both&fm=%7B%22tcp%22%3A%5B%5D%7D#Final%20mask",
            "aether://162.159.198.1:443?protocol=masque&scan=verified&ip=both&tor=chain#Tor",
            "aether://162.159.198.2:443?protocol=masque&scan=verified&ip=both#Endpoint",
        ];
        await ConfigHandler.AddBatchServers(config, string.Join("\n", links), subId, false);

        // The same profile again, edited by hand: the columns an Aether profile does not use are cleared on the way in,
        // so it is a duplicate too.
        var edited = AetherFmt.Resolve(MasqueLink, out _)!;
        edited.Remarks = "Edited";
        edited.Subid = subId;
        edited.Password = "secret";
        edited.StreamSecurity = Global.StreamSecurity;
        edited.Sni = "sni.example";
        await (await ConfigHandler.AddAetherServer(config, edited)).Should().BeEqualTo(0);

        // And with its outbound's targetStrategy chosen: another profile.
        var strategy = AetherFmt.Resolve(MasqueLink, out _)!;
        strategy.Remarks = "Target strategy";
        strategy.Subid = subId;
        strategy.TargetStrategy = "UseIPv4";
        await (await ConfigHandler.AddAetherServer(config, strategy)).Should().BeEqualTo(0);

        var (total, kept) = await ConfigHandler.DedupServerList(config, subId);
        var remarks = (await Profiles(subId)).Select(profile => profile.Remarks).ToList();

        await total.Should().BeEqualTo(9);
        await kept.Should().BeEqualTo(7);
        await remarks.Count(name => name is "WARP MASQUE" or "Copy" or "Edited").Should().BeEqualTo(1).Because(string.Join(", ", remarks));
        foreach (var name in new[] { "Scan mode", "Dial mode", "Final mask", "Tor", "Endpoint", "Target strategy" })
        {
            await remarks.Contains(name).Should().BeTrue().Because(name);
        }
    }

    [Test]
    public async Task ADefaultProfileIsPickedAmongAetherProfilesThatScan()
    {
        var config = Setup();
        config.IndexId = $"gone-{Guid.NewGuid():N}";
        List<ProfileItemModel> models =
        [
            new() { IndexId = $"group-{Guid.NewGuid():N}", ConfigType = EConfigType.PolicyGroup, Port = 0 },
            new() { IndexId = $"scan-{Guid.NewGuid():N}", ConfigType = EConfigType.Aether, Port = 0 },
        ];

        await (await ConfigHandler.SetDefaultServer(config, models)).Should().BeEqualTo(0);

        await config.IndexId.Should().BeEqualTo(models[1].IndexId);
    }

    [Test]
    public async Task ADefaultProfileIsPickedFromTheDatabaseWhenTheListIsEmpty()
    {
        // The database holds other tests' profiles as well, so only the kind of profile picked is known: one with a
        // port, or an Aether one, which this test makes sure exists.
        var config = Setup();
        var scan = AetherFmt.Resolve(ScanLink, out _)!;
        scan.Subid = NewSubId();
        await (await ConfigHandler.AddAetherServer(config, scan)).Should().BeEqualTo(0);
        config.IndexId = $"gone-{Guid.NewGuid():N}";

        await (await ConfigHandler.SetDefaultServer(config, [])).Should().BeEqualTo(0);
        var picked = await AppManager.Instance.GetProfileItem(config.IndexId);

        await picked.Should().NotBeNull();
        await (picked!.Port > 0 || picked.ConfigType == EConfigType.Aether).Should().BeTrue().Because(picked.ConfigType.ToString());
    }
}
