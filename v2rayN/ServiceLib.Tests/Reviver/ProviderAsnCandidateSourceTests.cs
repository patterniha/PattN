using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Protocol;
using ServiceLib.Discovery.Services;

namespace ServiceLib.Tests.Reviver;

public class ProviderAsnCandidateSourceTests
{
    [Test]
    public async Task Source_ShouldEmitOnlyScopedLiteralIpEntries()
    {
        var catalog = new StaticProviderAsnEndpointCatalog(
        [
            new ProviderAsnEndpointCatalogEntry
            {
                Address = "203.0.113.10",
                Provider = "Example CDN",
                Asn = "AS64500",
                Pop = "FRA",
                SourceId = "dataset-1",
                LogicalHosts = ["front.example"],
                Network = nameof(ETransport.ws),
                StreamSecurity = Global.StreamSecurity,
            },
            new ProviderAsnEndpointCatalogEntry
            {
                Address = "not-an-ip",
                Provider = "Bad",
                SourceId = "invalid",
                LogicalHosts = ["front.example"],
            },
            new ProviderAsnEndpointCatalogEntry
            {
                Address = "203.0.113.20",
                Provider = "Other",
                SourceId = "wrong-host",
                LogicalHosts = ["other.example"],
            },
            new ProviderAsnEndpointCatalogEntry
            {
                Address = "2001:db8::10",
                Provider = "Example CDN",
                Asn = "AS64500",
                SourceId = "dataset-2",
                LogicalHosts = ["front.example"],
                Network = nameof(ETransport.ws),
                StreamSecurity = Global.StreamSecurity,
            },
        ]);

        var source = new ProviderAsnCandidateSource(catalog);
        var request = new DiscoveryCandidateRequest
        {
            OriginalAddress = "origin.example",
            OriginalPort = 443,
            LogicalHost = "front.example",
            Network = nameof(ETransport.ws),
            StreamSecurity = Global.StreamSecurity,
            MaxCandidates = 8,
        };

        var values = new List<DiscoveryEndpointCandidate>();
        await foreach (var value in source.GetCandidatesAsync(request))
        {
            values.Add(value);
        }

        await values.Count.Should().BeEqualTo(2);
        await values[0].Source.Should().BeEqualTo("catalog.provider-asn");
        await values[0].Provider.Should().BeEqualTo("Example CDN");
        await values[0].Asn.Should().BeEqualTo("AS64500");
        await values[0].Metadata["catalogSourceId"].Should().BeEqualTo("dataset-1");
        await values.Select(x => x.Address).Contains("2001:db8::10").Should().BeTrue();
    }

    [Test]
    public async Task Source_ShouldHonorExplicitPortAndSecurityScope()
    {
        var catalog = new StaticProviderAsnEndpointCatalog(
        [
            new ProviderAsnEndpointCatalogEntry
            {
                Address = "203.0.113.10",
                Port = 8443,
                SourceId = "wrong-port",
            },
            new ProviderAsnEndpointCatalogEntry
            {
                Address = "203.0.113.11",
                SourceId = "wrong-security",
                StreamSecurity = Global.StreamSecurityReality,
            },
            new ProviderAsnEndpointCatalogEntry
            {
                Address = "203.0.113.12",
                SourceId = "match",
                Port = 443,
                StreamSecurity = Global.StreamSecurity,
            },
        ]);

        var source = new ProviderAsnCandidateSource(catalog);
        var request = new DiscoveryCandidateRequest
        {
            OriginalAddress = "origin.example",
            OriginalPort = 443,
            LogicalHost = "front.example",
            Network = nameof(ETransport.ws),
            StreamSecurity = Global.StreamSecurity,
            MaxCandidates = 8,
        };

        var values = new List<DiscoveryEndpointCandidate>();
        await foreach (var value in source.GetCandidatesAsync(request))
        {
            values.Add(value);
        }

        await values.Count.Should().BeEqualTo(1);
        await values[0].Address.Should().BeEqualTo("203.0.113.12");
    }

    [Test]
    public async Task Source_ShouldCarryCatalogAuditAsAdvisoryMetadataWithoutSuppressingCandidate()
    {
        var catalog = new StaticProviderAsnEndpointCatalog(
        [
            new ProviderAsnEndpointCatalogEntry
            {
                Address = "203.0.113.10",
                Provider = "Example CDN",
                SourceId = "entry-1",
                LogicalHosts = ["front.example"],
            },
        ]);
        var audit = new ProviderAsnCatalogAudit
        {
            CatalogId = "catalog-1",
            CatalogVersion = "v1",
            Source = "unit",
            Sha256 = new string('a', 64),
            AuditedAt = new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero),
            FreshnessKnown = true,
            Stale = true,
            AgeDays = 150,
            TotalEntries = 1,
            EnabledEntries = 1,
            DuplicateSourceIdGroups = 2,
            ExactDuplicateGroups = 1,
            BroadScopeEntries = 3,
            Warnings = ["catalog-stale"],
        };

        var source = new ProviderAsnCandidateSource(catalog, audit: audit);
        var values = new List<DiscoveryEndpointCandidate>();
        await foreach (var value in source.GetCandidatesAsync(
            new DiscoveryCandidateRequest
            {
                OriginalAddress = "origin.example",
                OriginalPort = 443,
                LogicalHost = "front.example",
                MaxCandidates = 4,
            }))
        {
            values.Add(value);
        }

        await values.Count.Should().BeEqualTo(1);
        await values[0].Metadata["catalogAuditValid"].Should().BeEqualTo("true");
        await values[0].Metadata["catalogFreshnessKnown"].Should().BeEqualTo("true");
        await values[0].Metadata["catalogStale"].Should().BeEqualTo("true");
        await values[0].Metadata["catalogAgeDays"].Should().BeEqualTo("150");
        await values[0].Metadata["catalogDuplicateSourceIdGroups"].Should().BeEqualTo("2");
        await values[0].Metadata["catalogExactDuplicateGroups"].Should().BeEqualTo("1");
        await values[0].Metadata["catalogBroadScopeEntries"].Should().BeEqualTo("3");
        await values[0].Metadata["catalogAuditWarnings"].Should().BeEqualTo("catalog-stale");
    }

    [Test]
    public async Task StaticCatalog_ShouldFilterScopeBeforeApplyingBudget()
    {
        var catalog = new StaticProviderAsnEndpointCatalog(
        [
            new ProviderAsnEndpointCatalogEntry
            {
                Address = "203.0.113.1",
                SourceId = "wrong-1",
                LogicalHosts = ["other.example"],
            },
            new ProviderAsnEndpointCatalogEntry
            {
                Address = "203.0.113.2",
                SourceId = "wrong-2",
                LogicalHosts = ["other.example"],
            },
            new ProviderAsnEndpointCatalogEntry
            {
                Address = "203.0.113.3",
                SourceId = "match",
                LogicalHosts = ["front.example"],
            },
        ]);

        var values = await catalog.ListAsync(
            new DiscoveryCandidateRequest
            {
                OriginalAddress = "origin.example",
                OriginalPort = 443,
                LogicalHost = "front.example",
                MaxCandidates = 1,
            },
            maxItems: 1);

        await values.Count.Should().BeEqualTo(1);
        await values[0].SourceId.Should().BeEqualTo("match");
    }

    [Test]
    public async Task Composition_ShouldAcceptOptionalProviderCatalogWithoutRequiringOne()
    {
        var engine = new EmptyProbeClient();
        var history = new EmptyHistoryStore();
        var pool = new EmptyPoolStore();

        var without = DiscoveryCandidateComposition.CreateDefault(engine, history, pool);
        await without.Should().NotBeNull();

        var withCatalog = DiscoveryCandidateComposition.CreateDefault(
            engine,
            history,
            pool,
            new StaticProviderAsnEndpointCatalog([]));
        await withCatalog.Should().NotBeNull();
    }

    private sealed class EmptyProbeClient : IDiscoveryEndpointProbeClient
    {
        public Task<DiscoveryEndpointProbeResponse> ProbeEndpointsAsync(
            DiscoveryEndpointProbeRequest request,
            CancellationToken cancellationToken = default)
            => Task.FromResult(new DiscoveryEndpointProbeResponse());
    }

    private sealed class EmptyHistoryStore : IEndpointHistoryStore
    {
        public Task RecordProbeAsync(
            DiscoveryCandidateRequest request,
            DiscoveryEndpointCandidate sourceCandidate,
            DiscoveryEndpointProbeResult observation,
            CancellationToken cancellationToken = default)
            => Task.CompletedTask;

        public Task<IReadOnlyList<DiscoveryEndpointCandidate>> GetHistoricallyGoodAsync(
            DiscoveryCandidateRequest request,
            EndpointHistoryPolicy? policy = null,
            CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<DiscoveryEndpointCandidate>>([]);

        public Task PruneAsync(TimeSpan maxAge, CancellationToken cancellationToken = default)
            => Task.CompletedTask;
    }

    private sealed class EmptyPoolStore : IEndpointPoolStore
    {
        public Task<IReadOnlyList<DiscoveryEndpointCandidate>> GetCandidatesAsync(
            DiscoveryCandidateRequest request,
            int maxCandidates,
            CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<DiscoveryEndpointCandidate>>([]);

        public Task<EndpointPoolItem> UpsertAsync(
            DiscoveryCandidateRequest request,
            DiscoveryEndpointCandidate candidate,
            bool pinned = false,
            string? label = null,
            CancellationToken cancellationToken = default)
            => Task.FromResult(new EndpointPoolItem());

        public Task RemoveAsync(string id, CancellationToken cancellationToken = default)
            => Task.CompletedTask;
    }
}
