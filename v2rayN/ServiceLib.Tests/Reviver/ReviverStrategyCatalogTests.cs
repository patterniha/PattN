using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;
using ServiceLib.Reviver.Models;
using ServiceLib.Reviver.Normalization;
using ServiceLib.Reviver.Services;
using ServiceLib.Reviver.Strategies;

namespace ServiceLib.Tests.Reviver;

public class ReviverStrategyCatalogTests
{
    [Test]
    public async Task CreateDefault_ShouldIncludeDnsEndpointAndCoreStrategies()
    {
        var strategies = ReviverStrategyCatalog.CreateDefault(
            new EmptyCandidateProvider(),
            new EmptyDnsEvidenceProvider(),
            new ProfileCoreCompatibility());

        await strategies.Any(x => x.Id == "dns-address-family").Should().BeTrue();
        await strategies.Any(x => x.Id == "endpoint-replacement").Should().BeTrue();
        await strategies.Any(x => x.Id == "core-fallback").Should().BeTrue();
    }

    [Test]
    public async Task CreateDefault_ShouldRemainEvidenceGatedAndNonSpeculative()
    {
        var strategies = ReviverStrategyCatalog.CreateDefault(
            new EmptyCandidateProvider(),
            new EmptyDnsEvidenceProvider(),
            new ProfileCoreCompatibility());

        var ids = strategies.Select(x => x.Id).OrderBy(x => x, StringComparer.Ordinal).ToArray();
        await ids.SequenceEqual(new[]
        {
            "core-fallback",
            "dns-address-family",
            "endpoint-replacement",
        }).Should().BeTrue();
        await strategies.All(x => x.Confidence != ERepairConfidence.Speculative).Should().BeTrue();
    }

    [Test]
    public async Task DnsFailurePriorities_ShouldPlaceAddressFamilyRepairBeforeEndpointReplacement()
    {
        var strategies = ReviverStrategyCatalog.CreateDefault(
            new EmptyCandidateProvider(),
            new EmptyDnsEvidenceProvider(),
            new ProfileCoreCompatibility());

        var ordered = strategies
            .Where(x => x.PriorityFor(ERepairFailureClass.DnsResolutionFailure) < 1000)
            .OrderBy(x => x.PriorityFor(ERepairFailureClass.DnsResolutionFailure))
            .ThenBy(x => x.Confidence)
            .ThenBy(x => x.Id, StringComparer.Ordinal)
            .Select(x => x.Id)
            .ToArray();

        await ordered[0].Should().BeEqualTo("dns-address-family");
        await ordered.Contains("endpoint-replacement").Should().BeTrue();
    }

    [Test]
    public async Task CreateDefaultObservers_ShouldBindDnsHistoryWhenProvided()
    {
        var store = new EmptyHistoryStore();
        var observers = ReviverStrategyCatalog.CreateDefaultObservers(store);

        await observers.Count.Should().BeEqualTo(1);
        await (observers[0] is DnsRepairHistoryObserver).Should().BeTrue();
        await ReviverStrategyCatalog.CreateDefaultObservers(null).Count.Should().BeEqualTo(0);
    }

    private sealed class EmptyCandidateProvider : IDiscoveryCandidateProvider
    {
        public async IAsyncEnumerable<DiscoveryEndpointCandidate> GetCandidatesAsync(
            DiscoveryCandidateRequest request,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            yield break;
        }
    }

    private sealed class EmptyHistoryStore : IDnsRepairHistoryStore
    {
        public Task RecordObservationAsync(string profileId, string sessionId, DnsRepairObservation observation, CancellationToken cancellationToken = default)
            => Task.CompletedTask;

        public Task RecordCandidateAsync(RepairCandidate candidate, CancellationToken cancellationToken = default)
            => Task.CompletedTask;

        public Task<DnsRepairHistorySummary> SummarizeAsync(string host, TimeSpan? maxAge = null, CancellationToken cancellationToken = default)
            => Task.FromResult(new DnsRepairHistorySummary { Host = host });

        public Task PruneAsync(TimeSpan maxAge, CancellationToken cancellationToken = default)
            => Task.CompletedTask;
    }

    private sealed class EmptyDnsEvidenceProvider : IDnsRepairEvidenceProvider
    {
        public Task<DnsRepairObservation> InspectAsync(string host, CancellationToken cancellationToken = default)
            => Task.FromResult(new DnsRepairObservation
            {
                Host = host,
                IPv4 = new DnsFamilyObservation { Family = "ipv4" },
                IPv6 = new DnsFamilyObservation { Family = "ipv6" },
            });
    }
}
