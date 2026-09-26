using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;
using ServiceLib.Models.Entities;

namespace ServiceLib.Tests.Reviver;

public class EndpointHistorySummaryTests
{
    [Test]
    public async Task Summary_ShouldRequireRepeatedQualifiedObservations()
    {
        var now = new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero);
        var policy = new EndpointHistoryPolicy();
        var summary = SqliteEndpointHistoryStore.Summarize(
            [Observation(now, qualified: true, reliability: 1)],
            now,
            policy);

        await summary.QualifiedObservations.Should().BeEqualTo(1);
        await summary.IsHistoricallyGood(policy).Should().BeFalse();
    }

    [Test]
    public async Task Summary_ShouldSuppressEndpointAfterTwoRecentFailures()
    {
        var now = new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero);
        var policy = new EndpointHistoryPolicy();
        var summary = SqliteEndpointHistoryStore.Summarize(
            [
                Observation(now, qualified: false, reliability: 0),
                Observation(now.AddHours(-1), qualified: false, reliability: 0),
                Observation(now.AddDays(-1), qualified: true, reliability: 1),
                Observation(now.AddDays(-2), qualified: true, reliability: 1),
                Observation(now.AddDays(-3), qualified: true, reliability: 1),
            ],
            now,
            policy);

        await summary.RecentFailureStreak.Should().BeEqualTo(2);
        await summary.QualifiedObservations.Should().BeEqualTo(3);
        await summary.IsHistoricallyGood(policy).Should().BeFalse();
    }

    [Test]
    public async Task Summary_ShouldLetRecentSuccessesOutweighOldFailure()
    {
        var now = new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero);
        var policy = new EndpointHistoryPolicy
        {
            MinimumDecayedReliability = 0.75,
        };
        var summary = SqliteEndpointHistoryStore.Summarize(
            [
                Observation(now, qualified: true, reliability: 1, latency: 40),
                Observation(now.AddDays(-1), qualified: true, reliability: 1, latency: 50),
                Observation(now.AddDays(-28), qualified: false, reliability: 0),
            ],
            now,
            policy);

        await (summary.DecayedReliability > 0.9).Should().BeTrue();
        await summary.RecentFailureStreak.Should().BeEqualTo(0);
        await summary.IsHistoricallyGood(policy).Should().BeTrue();
        await (summary.DecayedLatencyMs is > 0 and < 55).Should().BeTrue();
    }

    private static EndpointObservationHistoryItem Observation(
        DateTimeOffset at,
        bool qualified,
        double reliability,
        double? latency = null)
        => new()
        {
            Address = "203.0.113.7",
            Qualified = qualified,
            Reliability = reliability,
            MedianLatencyMs = latency,
            ObservedAtUnixMs = at.ToUnixTimeMilliseconds(),
        };
}
