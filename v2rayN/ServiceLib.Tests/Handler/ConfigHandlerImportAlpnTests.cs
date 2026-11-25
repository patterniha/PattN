using ServiceLib.Tests.CoreConfig;

namespace ServiceLib.Tests.Handler;

// PattN: an import gives a WebSocket or HTTPUpgrade profile under TLS the alpn it connects with, http/1.1, in place of
// any other (PattNG parseBatchConfig with TlsSettingsCheck.fixImportedAlpn): share links and subscriptions, and v2rayN's
// own lines. Each test works in a subscription id of its own in the test database, whose profiles it removes again. The
// tests do not run beside others: sqlite-net shares one connection, whose multi-row inserts, each a transaction, cannot
// overlap. The fix holds whatever core runs the profile (X1), and for SOCKS and HTTP as well (R10-1).
[NotInParallel]
public class ConfigHandlerImportAlpnTests
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

    private static async Task<Dictionary<string, ProfileItem>> Profiles(string subId)
    {
        return (await ConfigDbQuery.ProfileItems(subId) ?? []).ToDictionary(profile => profile.Remarks);
    }

    /// <summary>Removes what the test imported under <paramref name="subId" />, so that the test database does not grow with each run.</summary>
    private static async Task Remove(string subId)
    {
        foreach (var profile in await ConfigDbQuery.ProfileItems(subId) ?? [])
        {
            await SQLiteHelper.Instance.DeleteAsync(profile);
        }
    }

    [Test]
    public async Task ShareLinksOfWebSocketAndHttpUpgradeUnderTlsGetHttp1()
    {
        var config = Setup();
        var subId = NewSubId();
        var links = string.Join("\n",
            $"vless://{Id}@example.com:443?encryption=none&security=tls&type=ws&alpn=h2%2Chttp%2F1.1&path=%2F#ws-h2",
            $"vless://{Id}@example.com:443?encryption=none&security=tls&type=httpupgrade&alpn=h3#httpupgrade-h3",
            $"trojan://password@example.com:443?security=tls&type=ws&alpn=h2#trojan-ws-h2",
            $"vless://{Id}@example.com:443?encryption=none&security=tls&type=ws&alpn=http%2F1.1#ws-http1",
            $"vless://{Id}@example.com:443?encryption=none&security=tls&type=ws#ws-none",
            $"vless://{Id}@example.com:443?encryption=none&security=tls&type=grpc&alpn=h2&serviceName=grpc#grpc-h2",
            $"vless://{Id}@example.com:443?encryption=none&security=none&type=ws&alpn=h2#plain-ws-h2");

        try
        {
            var count = await ConfigDbHandler.AddBatchServers(links, subId, false);
            var profiles = await Profiles(subId);

            await count.Should().BeEqualTo(7);
            await profiles["ws-h2"].Alpn.Should().BeEqualTo("http/1.1");
            await profiles["httpupgrade-h3"].Alpn.Should().BeEqualTo("http/1.1");
            await profiles["trojan-ws-h2"].Alpn.Should().BeEqualTo("http/1.1");
            // http/1.1 alone, or none, stays as it came; so does the alpn of another transport, or outside TLS.
            await profiles["ws-http1"].Alpn.Should().BeEqualTo("http/1.1");
            await (profiles["ws-none"].Alpn ?? string.Empty).Should().BeEqualTo(string.Empty);
            await profiles["grpc-h2"].Alpn.Should().BeEqualTo("h2");
            await profiles["plain-ws-h2"].Alpn.Should().BeEqualTo("h2");
        }
        finally
        {
            await Remove(subId);
        }
        await (await Profiles(subId)).Count.Should().BeEqualTo(0);
    }

    [Test]
    public async Task V2rayNsOwnLinesGetHttp1Too()
    {
        var config = Setup();
        var subId = NewSubId();
        ProfileItem Line(string remarks, EConfigType type, ECoreType core) => new()
        {
            IndexId = Guid.NewGuid().ToString("N"),
            ConfigType = type,
            CoreType = core,
            Remarks = remarks,
            Address = "example.com",
            Port = 443,
            Password = Id,
            Network = "ws",
            StreamSecurity = Global.StreamSecurity,
            Alpn = "h2,http/1.1",
        };
        // PattN: whatever core runs it (X1), and SOCKS too, whose TLS the editor shows (R10-1).
        var uri = InnerFmt.ToUri(
        [
            Line("inner-ws-h2", EConfigType.VLESS, ECoreType.Xray),
            Line("inner-sing-box-ws-h2", EConfigType.VLESS, ECoreType.sing_box),
            Line("inner-socks-ws-h2", EConfigType.SOCKS, ECoreType.Xray),
        ]);

        try
        {
            var count = await ConfigDbHandler.AddBatchServers(uri!, subId, false);
            var profiles = await Profiles(subId);

            await count.Should().BeEqualTo(3);
            await profiles["inner-ws-h2"].Alpn.Should().BeEqualTo("http/1.1");
            await profiles["inner-sing-box-ws-h2"].CoreType.Should().BeEqualTo(ECoreType.sing_box);
            await profiles["inner-sing-box-ws-h2"].Alpn.Should().BeEqualTo("http/1.1");
            await profiles["inner-socks-ws-h2"].Alpn.Should().BeEqualTo("http/1.1");
        }
        finally
        {
            await Remove(subId);
        }
        await (await Profiles(subId)).Count.Should().BeEqualTo(0);
    }
}
