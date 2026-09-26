using System.Text;
using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;

namespace ServiceLib.Tests.Reviver;

public class ProviderAsnCatalogAuditServiceTests
{
    [Test]
    public async Task Audit_ShouldReportFreshnessCoverageAndNormalizedDuplicates()
    {
        var catalog = JsonProviderAsnEndpointCatalog.FromBytes(Encoding.UTF8.GetBytes(
            """
            {
              "schemaVersion":1,
              "id":"provider-test",
              "version":"2026-05",
              "source":"unit-test",
              "updatedAt":"2026-05-01T00:00:00Z",
              "entries":[
                {
                  "address":"203.0.113.10",
                  "provider":"Example CDN",
                  "asn":"AS64500",
                  "pop":"edge-a",
                  "sourceId":"duplicate-source",
                  "logicalHosts":["front.example"],
                  "network":"ws",
                  "streamSecurity":"tls"
                },
                {
                  "address":"203.0.113.10",
                  "provider":"Example CDN",
                  "asn":"AS64500",
                  "pop":"edge-a",
                  "sourceId":"duplicate-source",
                  "logicalHosts":["FRONT.EXAMPLE."],
                  "network":"WS",
                  "streamSecurity":"TLS"
                },
                {
                  "address":"2001:db8::10",
                  "enabled":false
                }
              ]
            }
            """));

        var audit = catalog.Audit(
            new DateTimeOffset(2026, 9, 23, 0, 0, 0, TimeSpan.Zero),
            new ProviderAsnCatalogAuditPolicy { MaximumAge = TimeSpan.FromDays(120) });

        await audit.Valid.Should().BeTrue();
        await audit.FreshnessKnown.Should().BeTrue();
        await audit.Stale.Should().BeTrue();
        await audit.TotalEntries.Should().BeEqualTo(3);
        await audit.EnabledEntries.Should().BeEqualTo(2);
        await audit.DisabledEntries.Should().BeEqualTo(1);
        await audit.IPv4Entries.Should().BeEqualTo(2);
        await audit.IPv6Entries.Should().BeEqualTo(1);
        await audit.UniqueAddresses.Should().BeEqualTo(2);
        await audit.ProviderCount.Should().BeEqualTo(1);
        await audit.AsnCount.Should().BeEqualTo(1);
        await audit.PopCount.Should().BeEqualTo(1);
        await audit.HostScopedEntries.Should().BeEqualTo(2);
        await audit.BroadScopeEntries.Should().BeEqualTo(1);
        await audit.MissingProviderEntries.Should().BeEqualTo(1);
        await audit.MissingAsnEntries.Should().BeEqualTo(1);
        await audit.DuplicateSourceIdGroups.Should().BeEqualTo(1);
        await audit.ExactDuplicateGroups.Should().BeEqualTo(1);
        await audit.Warnings.Contains("catalog-stale").Should().BeTrue();
        await audit.Warnings.Contains("duplicate-source-ids").Should().BeTrue();
        await audit.Warnings.Contains("exact-duplicate-entries").Should().BeTrue();
        await audit.Warnings.Contains("broad-scope-entries-present").Should().BeTrue();
    }

    [Test]
    public async Task Audit_ShouldMarkMissingFreshnessAsUnknownWithoutInvalidatingCatalog()
    {
        var catalog = JsonProviderAsnEndpointCatalog.FromBytes(Encoding.UTF8.GetBytes(
            """
            {
              "schemaVersion":1,
              "id":"provider-test",
              "version":"v1",
              "source":"unit-test",
              "entries":[{"address":"203.0.113.10"}]
            }
            """));

        var audit = catalog.Audit(new DateTimeOffset(2026, 9, 23, 0, 0, 0, TimeSpan.Zero));

        await audit.Valid.Should().BeTrue();
        await audit.FreshnessKnown.Should().BeFalse();
        await audit.Stale.Should().BeFalse();
        await audit.Warnings.Contains("catalog-updated-at-missing").Should().BeTrue();
    }

    [Test]
    public async Task Audit_ShouldRejectMateriallyFutureUpdatedAt()
    {
        var catalog = JsonProviderAsnEndpointCatalog.FromBytes(Encoding.UTF8.GetBytes(
            """
            {
              "schemaVersion":1,
              "id":"provider-test",
              "version":"v1",
              "source":"unit-test",
              "updatedAt":"2026-09-23T03:00:00Z",
              "entries":[{"address":"203.0.113.10"}]
            }
            """));

        var audit = catalog.Audit(
            new DateTimeOffset(2026, 9, 23, 0, 0, 0, TimeSpan.Zero),
            new ProviderAsnCatalogAuditPolicy { MaximumFutureClockSkew = TimeSpan.FromMinutes(10) });

        await audit.Valid.Should().BeFalse();
        await audit.Errors.Contains("catalog-updated-at-in-future").Should().BeTrue();
    }
}
