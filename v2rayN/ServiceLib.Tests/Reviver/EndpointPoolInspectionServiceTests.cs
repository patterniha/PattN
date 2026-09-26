using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;
using ServiceLib.Models.Entities;

namespace ServiceLib.Tests.Reviver;

public class EndpointPoolInspectionServiceTests
{
    [Test]
    public async Task Inspect_ShouldJoinExplicitPoolStateWithHistoricalEvidence()
    {
        var now = new DateTimeOffset(2026, 9, 23, 20, 0, 0, TimeSpan.Zero);
        var admin = new FakeAdmin([
            new EndpointPoolItem
            {
                Id = "pool-1",
                LogicalHost = "front.example",
                HttpHost = "origin.example",
                Port = 443,
                Network = "ws",
                StreamSecurity = "tls",
                Address = "203.0.113.10",
                Label = "primary",
                Enabled = true,
                Pinned = true,
                Provider = "Example CDN",
                CreatedAtUnixMs = now.AddDays(-10).ToUnixTimeMilliseconds(),
                UpdatedAtUnixMs = now.AddHours(-1).ToUnixTimeMilliseconds(),
            }
        ]);
        var history = new FakeHistory(new EndpointHistoryDetail
        {
            LogicalHost = "front.example",
            Port = 443,
            Network = "ws",
            StreamSecurity = "tls",
            Address = "203.0.113.10",
            Points =
            [
                new EndpointHistoryPoint
                {
                    ObservedAt = now.AddMinutes(-5),
                    Qualified = true,
                    Attempts = 3,
                    Successes = 3,
                    ConsecutiveSuccesses = 3,
                    Reliability = 1,
                    MedianLatencyMs = 40,
                }
            ],
            Summary = new EndpointHistorySummary
            {
                Address = "203.0.113.10",
                Samples = 4,
                QualifiedObservations = 4,
                RecentFailureStreak = 0,
                DecayedReliability = 0.95,
                DecayedLatencyMs = 42,
                LastObservedAt = now.AddMinutes(-5),
            },
        });

        var rows = await new EndpointPoolInspectionService(admin, history).InspectAsync(
            new EndpointPoolInspectionQuery
            {
                LogicalHost = "front.example",
                MaxItems = 20,
            });

        await rows.Count.Should().BeEqualTo(1);
        await rows[0].Pinned.Should().BeTrue();
        await rows[0].Label.Should().BeEqualTo("primary");
        await rows[0].CurrentObservationState.Should().BeEqualTo("qualified");
        await rows[0].HistoricallyGood.Should().BeTrue();
        await rows[0].History!.DecayedReliability.Should().BeEqualTo(0.95);
        await history.LastRequest!.LogicalHost.Should().BeEqualTo("front.example");
        await history.LastRequest.HttpHost.Should().BeEqualTo("origin.example");
        await rows[0].HttpHost.Should().BeEqualTo("origin.example");
        await history.LastAddress.Should().BeEqualTo("203.0.113.10");
    }

    [Test]
    public async Task Inspect_ShouldExposeUnknownCurrentStateWithoutHistory()
    {
        var admin = new FakeAdmin([
            new EndpointPoolItem
            {
                Id = "pool-1",
                LogicalHost = "front.example",
                Port = 443,
                Network = "ws",
                StreamSecurity = "tls",
                Address = "203.0.113.10",
                Enabled = false,
                UpdatedAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            }
        ]);
        var history = new FakeHistory(new EndpointHistoryDetail
        {
            LogicalHost = "front.example",
            Port = 443,
            Network = "ws",
            StreamSecurity = "tls",
            Address = "203.0.113.10",
        });

        var rows = await new EndpointPoolInspectionService(admin, history).InspectAsync();

        await rows[0].CurrentObservationState.Should().BeEqualTo("unknown");
        await rows[0].HistoricallyGood.Should().BeFalse();
    }

    private sealed class FakeAdmin(IReadOnlyList<EndpointPoolItem> rows) : IEndpointPoolAdminStore
    {
        public Task<IReadOnlyList<EndpointPoolItem>> ListAsync(
            EndpointPoolQuery? query = null,
            CancellationToken cancellationToken = default)
            => Task.FromResult(rows);

        public Task<EndpointPoolItem?> UpdateAsync(
            EndpointPoolUpdate update,
            CancellationToken cancellationToken = default)
            => Task.FromResult<EndpointPoolItem?>(rows.FirstOrDefault(x => x.Id == update.Id));
    }

    private sealed class FakeHistory(EndpointHistoryDetail detail) : IEndpointHistoryQueryService
    {
        public DiscoveryCandidateRequest? LastRequest { get; private set; }
        public string? LastAddress { get; private set; }

        public Task<EndpointHistoryDetail> GetAsync(
            DiscoveryCandidateRequest request,
            string address,
            TimeSpan? maxAge = null,
            int maxPoints = 50,
            CancellationToken cancellationToken = default)
        {
            LastRequest = request;
            LastAddress = address;
            return Task.FromResult(detail);
        }
    }
}
