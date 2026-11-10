using ServiceLib.Tests.CoreConfig;

namespace ServiceLib.Tests.Handler;

// PattN: curvePreferences and enableSessionResumption are stored in columns of their own, beside cipherSuites: what a
// share link carries reaches the database, a save through the editor's path keeps what the editor holds, and the types
// whose editor disables cipherSuites (Hysteria2, Naive, MASQUE) store neither, as Aether does not. Each test works in a
// subscription id of its own in the test database, whose profiles it removes again. The tests do not run beside others:
// sqlite-net shares one connection, whose multi-row inserts, each a transaction, cannot overlap.
[NotInParallel]
public class ConfigHandlerCurvePreferencesTests
{
    private const string Id = "5783a3e7-e373-51cd-8642-c83782b807c5";

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

    /// <summary>Removes what the test stored under <paramref name="subId" />, so that the test database does not grow with each run.</summary>
    private static async Task Remove(string subId)
    {
        foreach (var profile in await AppManager.Instance.ProfileItems(subId) ?? [])
        {
            await SQLiteHelper.Instance.DeleteAsync(profile);
        }
    }

    [Test]
    public async Task ShareLinksStoreThemAndASaveKeepsWhatTheEditorHolds()
    {
        var config = Setup();
        var subId = NewSubId();
        var links = string.Join("\n",
            $"vless://{Id}@example.com:443?encryption=none&security=tls&type=raw&fp=unsafe&cp=X25519MLKEM768%2CX25519&esr=1#both",
            $"vless://{Id}@example.com:443?encryption=none&security=tls&type=raw&fp=unsafe#neither");

        try
        {
            await (await ConfigHandler.AddBatchServers(config, links, subId, false)).Should().BeEqualTo(2);
            var profiles = (await AppManager.Instance.ProfileItems(subId) ?? []).ToDictionary(profile => profile.Remarks);

            await profiles["both"].CurvePreferences.Should().BeEqualTo("X25519MLKEM768,X25519");
            await profiles["both"].EnableSessionResumption.Should().BeTrue();
            await profiles["neither"].CurvePreferences.Should().BeEqualTo(string.Empty);
            await profiles["neither"].EnableSessionResumption.Should().BeFalse();

            // The editor's path: AddServer copies them onto the stored profile, either way.
            var edited = JsonUtils.DeepCopy(profiles["both"])!;
            edited.CurvePreferences = "X25519";
            edited.EnableSessionResumption = false;
            await (await ConfigHandler.AddServer(config, edited)).Should().BeEqualTo(0);
            var stored = (await AppManager.Instance.GetProfileItem(edited.IndexId))!;
            await stored.CurvePreferences.Should().BeEqualTo("X25519");
            await stored.EnableSessionResumption.Should().BeFalse();

            var turnedOn = JsonUtils.DeepCopy(profiles["neither"])!;
            turnedOn.CurvePreferences = "X25519MLKEM768";
            turnedOn.EnableSessionResumption = true;
            await (await ConfigHandler.AddServer(config, turnedOn)).Should().BeEqualTo(0);
            var stored2 = (await AppManager.Instance.GetProfileItem(turnedOn.IndexId))!;
            await stored2.CurvePreferences.Should().BeEqualTo("X25519MLKEM768");
            await stored2.EnableSessionResumption.Should().BeTrue();
        }
        finally
        {
            await Remove(subId);
        }
    }

    [Test]
    public async Task AHysteria2ProfileStoresNeither()
    {
        var config = Setup();
        var subId = NewSubId();
        var profile = new ProfileItem
        {
            Remarks = "hy2",
            Address = "example.com",
            Port = 443,
            Password = "password",
            Subid = subId,
            StreamSecurity = Global.StreamSecurity,
            CipherSuites = "TLS_AES_128_GCM_SHA256",
            CurvePreferences = "X25519",
            EnableSessionResumption = true,
        };

        try
        {
            await (await ConfigHandler.AddHysteria2Server(config, profile)).Should().BeEqualTo(0);
            var stored = (await AppManager.Instance.GetProfileItem(profile.IndexId))!;

            await stored.CipherSuites.Should().BeEqualTo(string.Empty);
            await stored.CurvePreferences.Should().BeEqualTo(string.Empty);
            await stored.EnableSessionResumption.Should().BeFalse();
        }
        finally
        {
            await Remove(subId);
        }
    }
}
