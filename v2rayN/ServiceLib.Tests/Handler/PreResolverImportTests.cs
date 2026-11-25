using ServiceLib.Tests.CoreConfig;

namespace ServiceLib.Tests.Handler;

// PattN: a subscription's pre-resolver replaces the address of each imported profile with its IP (2dust/v2rayN#10625);
// a TLS profile without a server name of its own keeps the name it was given as its SNI, and a WebSocket one as its Host,
// so that the certificate is checked against that name, not against the IP. The system resolver answers "localhost"
// without any network. The test does not run beside others: sqlite-net shares one connection (ConfigHandlerImportAlpnTests).
[NotInParallel]
public class PreResolverImportTests
{
    private const string Id = "5783a3e7-e373-51cd-8642-c83782b807c5";

    [Test]
    public async Task APreResolvedTlsProfileKeepsItsNameAsSniAndHost()
    {
        CoreConfigTestFactory.BindAppManagerConfig(CoreConfigTestFactory.CreateConfig());
        SQLiteHelper.Instance.CreateTable<SubItem>();
        SQLiteHelper.Instance.CreateTable<ProfileItem>();
        var subItem = new SubItem { Id = $"sub-{Guid.NewGuid():N}", Remarks = "pre-resolved", PreResolver = "system" };
        await SQLiteHelper.Instance.InsertAsync(subItem);
        var links = string.Join("\n",
            $"vless://{Id}@localhost:443?encryption=none&security=tls&type=ws&path=%2F#ws-tls",
            $"vless://{Id}@localhost:443?encryption=none&security=tls&sni=sni.example&type=ws&host=host.example&path=%2F#ws-tls-named");

        try
        {
            var count = await ConfigDbHandler.AddBatchServers(links, subItem.Id, true);
            var profiles = (await ConfigDbQuery.ProfileItems(subItem.Id) ?? []).ToDictionary(profile => profile.Remarks);

            await count.Should().BeEqualTo(2);
            var plain = profiles["ws-tls"];
            await Utils.IsIpAddress(plain.Address).Should().BeTrue();
            await plain.Sni.Should().BeEqualTo("localhost");
            await plain.GetTransportExtra().Host.Should().BeEqualTo("localhost");
            // A name the link gives is kept.
            var named = profiles["ws-tls-named"];
            await Utils.IsIpAddress(named.Address).Should().BeTrue();
            await named.Sni.Should().BeEqualTo("sni.example");
            await named.GetTransportExtra().Host.Should().BeEqualTo("host.example");
        }
        finally
        {
            foreach (var profile in await ConfigDbQuery.ProfileItems(subItem.Id) ?? [])
            {
                await SQLiteHelper.Instance.DeleteAsync(profile);
            }
            await SQLiteHelper.Instance.DeleteAsync(subItem);
        }
    }
}
