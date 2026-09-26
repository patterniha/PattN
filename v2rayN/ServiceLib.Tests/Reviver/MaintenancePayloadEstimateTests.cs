using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;
using ServiceLib.Models.Entities;

namespace ServiceLib.Tests.Reviver;

public class MaintenancePayloadEstimateTests
{
    [Test]
    public async Task FormatBytes_ShouldUseBoundedBinaryUnits()
    {
        await MaintenancePayloadEstimate.FormatBytes(0).Should().BeEqualTo("0 B");
        await MaintenancePayloadEstimate.FormatBytes(1024).Should().BeEqualTo("1 KB");
        await MaintenancePayloadEstimate.FormatBytes(1536).Should().BeEqualTo("1.5 KB");
        await MaintenancePayloadEstimate.FormatBytes(1024L * 1024L).Should().BeEqualTo("1 MB");
    }

    [Test]
    public async Task SerializedBytes_ShouldMatchUtf8JsonPayload()
    {
        var row = new EndpointPoolItem
        {
            Id = "pool-1",
            LogicalHost = "front.example",
            Port = 443,
            Network = "ws",
            StreamSecurity = "tls",
            Address = "203.0.113.7",
            Label = "primary",
            Enabled = false,
            Pinned = false,
        };

        var expected = System.Text.Encoding.UTF8.GetByteCount(JsonUtils.Serialize(row, false));
        var actual = MaintenancePayloadEstimateService.SerializedBytes(row);

        await actual.Should().BeEqualTo(expected);
        await (actual > 0).Should().BeTrue();
    }
}
