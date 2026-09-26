using ServiceLib.Discovery.Protocol;

namespace ServiceLib.Tests.Reviver;

public partial class DiscoveryRpcModelTests
{
    [Test]
    public async Task ResolverCatalogAuditDto_ShouldPreserveFreshnessEvidence()
    {
        var audit = JsonSerializer.Deserialize<DiscoveryResolverCatalogAudit>(
            """
            {
              "version":"2026-09-23",
              "valid":true,
              "maxAgeDays":90,
              "staleCount":1,
              "entries":[
                {"id":"cloudflare-standard","verifiedDate":"2026-09-23","ageDays":0,"stale":false},
                {"id":"google-standard","verifiedDate":"2026-01-01","ageDays":265,"stale":true}
              ]
            }
            """);

        await audit.Should().NotBeNull();
        await audit!.Valid.Should().BeTrue();
        await audit.Version.Should().BeEqualTo("2026-09-23");
        await audit.StaleCount.Should().BeEqualTo(1);
        await audit.Entries[1].Stale.Should().BeTrue();
    }
}
