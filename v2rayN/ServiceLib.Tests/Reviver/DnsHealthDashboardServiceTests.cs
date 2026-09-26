using ServiceLib.Discovery.Services;
using ServiceLib.Models.Entities;

namespace ServiceLib.Tests.Reviver;

public class DnsHealthDashboardServiceTests
{
    [Test]
    public async Task ComputeDecayedHealthScore_ShouldWeightRecentSamplesMoreStrongly()
    {
        var now = new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero);
        var oldGood = new DnsResolverTelemetryItem
        {
            Quality = "strong",
            ReliabilityFloor = 1,
            ObservedAtUnixMs = now.AddDays(-28).ToUnixTimeMilliseconds(),
        };
        var recentBad = new DnsResolverTelemetryItem
        {
            Quality = "unusable",
            ReliabilityFloor = 0,
            ObservedAtUnixMs = now.ToUnixTimeMilliseconds(),
        };

        var score = DnsHealthDashboardService.ComputeDecayedHealthScore(
            [oldGood, recentBad],
            now,
            TimeSpan.FromDays(14));

        await (score < 0.35).Should().BeTrue();
    }

    [Test]
    public async Task ComputeDecayedHealthScore_ShouldCapSuspicionEvidence()
    {
        var now = DateTimeOffset.UtcNow;
        var suspicious = new DnsResolverTelemetryItem
        {
            Quality = "strong",
            ReliabilityFloor = 1,
            InterceptionSuspected = true,
            ObservedAtUnixMs = now.ToUnixTimeMilliseconds(),
        };

        var score = DnsHealthDashboardService.ComputeDecayedHealthScore(
            [suspicious],
            now,
            TimeSpan.FromDays(14));

        await (score <= 0.12).Should().BeTrue();
    }

    [Test]
    public async Task ClassifyHealth_ShouldApplyHysteresisAroundBoundaries()
    {
        await DnsHealthDashboardService.ClassifyHealth(0.70, "healthy").Should().BeEqualTo("healthy");
        await DnsHealthDashboardService.ClassifyHealth(0.60, "degraded").Should().BeEqualTo("degraded");
        await DnsHealthDashboardService.ClassifyHealth(0.80, "watch").Should().BeEqualTo("healthy");
        await DnsHealthDashboardService.ClassifyHealth(0.49, "watch").Should().BeEqualTo("degraded");
        await DnsHealthDashboardService.ClassifyHealth(0.75, "degraded").Should().BeEqualTo("watch");
        await DnsHealthDashboardService.ClassifyHealth(0.50, "healthy").Should().BeEqualTo("watch");
        await DnsHealthDashboardService.ClassifyHealth(0.90, "unavailable").Should().BeEqualTo("watch");
        await DnsHealthDashboardService.ClassifyHealth(0.20, "unavailable").Should().BeEqualTo("degraded");
        await DnsHealthDashboardService.ClassifyHealth(0.20, "suspicious").Should().BeEqualTo("degraded");
    }

    [Test]
    public async Task ClassifyHealth_ShouldNotHideSuspicionOrUnavailability()
    {
        await DnsHealthDashboardService.ClassifyHealth(1, "healthy", interceptionSuspected: true)
            .Should().BeEqualTo("suspicious");
        await DnsHealthDashboardService.ClassifyHealth(0, "degraded", unavailable: true)
            .Should().BeEqualTo("unavailable");
        await DnsHealthDashboardService.ClassifyHealth(0.95, "healthy", unavailable: true)
            .Should().BeEqualTo("unavailable");
    }
}
