using ServiceLib.Discovery.Services;
using ServiceLib.Models.Entities;

namespace ServiceLib.Tests.Reviver;

public class DnsHistoryServiceTests
{
    [Test]
    public async Task TrendDirection_ShouldRemainInsufficientWithSparseHistory()
    {
        var values = Samples(0.9, 0.8, 0.7);
        await DnsHistoryService.TrendDirection(values).Should().BeEqualTo("insufficient");
    }

    [Test]
    public async Task TrendDirection_ShouldDetectImprovementDeclineAndStableBands()
    {
        await DnsHistoryService.TrendDirection(Samples(0.9, 0.9, 0.5, 0.5))
            .Should().BeEqualTo("improving");
        await DnsHistoryService.TrendDirection(Samples(0.4, 0.4, 0.9, 0.9))
            .Should().BeEqualTo("declining");
        await DnsHistoryService.TrendDirection(Samples(0.75, 0.72, 0.70, 0.69))
            .Should().BeEqualTo("stable");
    }

    private static IReadOnlyList<DnsResolverTelemetryItem> Samples(params double[] scores)
        => scores.Select((score, index) => new DnsResolverTelemetryItem
        {
            ResolverCatalogId = "resolver",
            Name = "Resolver",
            HealthScore = score,
            ReliabilityFloor = score,
            ObservedAtUnixMs = DateTimeOffset.UtcNow.AddMinutes(-index).ToUnixTimeMilliseconds(),
        }).ToArray();
}
