using ServiceLib.Discovery.Services;
using ServiceLib.Models.Entities;

namespace ServiceLib.Tests.Reviver;

public class EndpointHistoryQueryServiceTests
{
    [Test]
    public async Task BuildDetail_ShouldBoundPointsAndPreserveNewestFirst()
    {
        var now = new DateTimeOffset(2026, 9, 23, 18, 0, 0, TimeSpan.Zero);
        var rows = new[]
        {
            Row("1", now.AddMinutes(-30), true, 1, "[]"),
            Row("2", now.AddMinutes(-10), false, 0, "[\"timeout\"]"),
            Row("3", now.AddMinutes(-1), true, 1, "[]"),
        };

        var detail = EndpointHistoryQueryService.BuildDetail(
            "front.example",
            443,
            "ws",
            "tls",
            "203.0.113.44",
            rows,
            now,
            maxPoints: 2);

        await detail.Points.Count.Should().BeEqualTo(2);
        await detail.Points[0].ObservedAt.Should().BeEqualTo(now.AddMinutes(-1));
        await detail.Points[1].ObservedAt.Should().BeEqualTo(now.AddMinutes(-10));
        await detail.Points[1].Errors[0].Should().BeEqualTo("timeout");
        await detail.Summary.Should().NotBeNull();
        await detail.Summary!.Samples.Should().BeEqualTo(2);
    }

    [Test]
    public async Task BuildDetail_ShouldReturnNullSummaryForNoObservations()
    {
        var detail = EndpointHistoryQueryService.BuildDetail(
            "front.example",
            443,
            "ws",
            "tls",
            "203.0.113.44",
            [],
            DateTimeOffset.UtcNow);

        await detail.Points.Count.Should().BeEqualTo(0);
        await (detail.Summary is null).Should().BeTrue();
    }

    private static EndpointObservationHistoryItem Row(
        string id,
        DateTimeOffset at,
        bool qualified,
        int successes,
        string errors)
        => new()
        {
            Id = id,
            LogicalHost = "front.example",
            Port = 443,
            Network = "ws",
            StreamSecurity = "tls",
            Address = "203.0.113.44",
            Source = "test",
            Attempts = 1,
            Successes = successes,
            ConsecutiveSuccesses = successes,
            Qualified = qualified,
            Reliability = successes,
            MedianLatencyMs = qualified ? 40 : null,
            ErrorsJson = errors,
            ObservedAtUnixMs = at.ToUnixTimeMilliseconds(),
        };
}
