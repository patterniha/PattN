using ServiceLib.Discovery.Protocol;

namespace ServiceLib.Tests.Reviver;

public partial class DiscoveryRpcModelTests
{
    [Test]
    public async Task DnsTrustAnchorAuditDto_ShouldPreserveFreshnessAndRolloverState()
    {
        var result = JsonSerializer.Deserialize<DiscoveryDnsTrustAnchorAudit>(
            """
            {
              "version":"iana-root-anchors-2024-11-05/verified-2026-09-24",
              "sourceUrl":"https://data.iana.org/root-anchors/root-anchors.xml",
              "sourceUpdatedDate":"2024-11-05",
              "verifiedDate":"2026-09-24",
              "rolloverDate":"2026-10-11",
              "ageDays":0,
              "maxAgeDays":90,
              "daysUntilRollover":16,
              "rolloverReviewRequired":false,
              "stale":false,
              "valid":true,
              "reviewRequired":false,
              "status":"current",
              "keyTags":[20326,38696],
              "errors":[]
            }
            """);

        await result.Should().NotBeNull();
        await result!.Valid.Should().BeTrue();
        await result.ReviewRequired.Should().BeFalse();
        await result.Status.Should().BeEqualTo("current");
        await result.VerifiedDate.Should().BeEqualTo("2026-09-24");
        await result.RolloverDate.Should().BeEqualTo("2026-10-11");
        await result.KeyTags.Should().BeEquivalentTo([20326, 38696]);
    }
}
