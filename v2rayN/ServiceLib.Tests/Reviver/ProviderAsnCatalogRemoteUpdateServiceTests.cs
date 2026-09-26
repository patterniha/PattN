using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;
using ServiceLib.Models.Entities;

namespace ServiceLib.Tests.Reviver;

public class ProviderAsnCatalogRemoteUpdateServiceTests
{
    [Test]
    public async Task FetchPreview_ShouldUse304WhenLocalAlreadyMatchesCachedRemote()
    {
        await using var fixture = await RemoteFixture.CreateAsync("1");
        var catalog = await JsonProviderAsnEndpointCatalog.LoadAsync(fixture.Path);
        var source = Source(fixture.Registry.Id, catalog.Sha256);
        var sourceStore = new FakeSourceStore(source);
        var transport = new QueueTransport(
        [
            new ProviderAsnCatalogRemoteTransportResponse
            {
                StatusCode = 304,
                FinalUri = new Uri(source.Uri),
                ETag = "\"v1\"",
            }
        ]);
        var service = fixture.CreateService(sourceStore, transport);

        var preview = await service.FetchPreviewAsync(
            fixture.Registry.Id,
            DateTimeOffset.Parse("2026-09-24T10:00:00Z"));

        await preview.ServerNotModified.Should().BeTrue();
        await preview.LocalAlreadyMatchesRemote.Should().BeTrue();
        await preview.HasUpdate.Should().BeFalse();
        await transport.Requests.Count.Should().BeEqualTo(1);
        await transport.Requests[0].Conditional.Should().BeTrue();
        await sourceStore.Item!.LastCheckedAtUnixMs.Should().BeEqualTo(
            DateTimeOffset.Parse("2026-09-24T10:00:00Z").ToUnixTimeMilliseconds());
    }

    [Test]
    public async Task FetchPreview_ShouldRefetchAfterRollbackWhen304CacheIsNewerThanLocal()
    {
        await using var fixture = await RemoteFixture.CreateAsync("1");
        var local = await JsonProviderAsnEndpointCatalog.LoadAsync(fixture.Path);
        var remoteBytes = CatalogBytes("2");
        var remote = JsonProviderAsnEndpointCatalog.FromBytes(remoteBytes);
        var source = Source(fixture.Registry.Id, remote.Sha256);
        var sourceStore = new FakeSourceStore(source);
        var transport = new QueueTransport(
        [
            new ProviderAsnCatalogRemoteTransportResponse
            {
                StatusCode = 304,
                FinalUri = new Uri(source.Uri),
                ETag = "\"v2\"",
            },
            new ProviderAsnCatalogRemoteTransportResponse
            {
                StatusCode = 200,
                FinalUri = new Uri(source.Uri),
                Bytes = remoteBytes,
                ETag = "\"v2\"",
                LastModified = DateTimeOffset.Parse("2026-09-24T09:00:00Z"),
            }
        ]);
        var service = fixture.CreateService(sourceStore, transport);

        var preview = await service.FetchPreviewAsync(fixture.Registry.Id);

        await preview.ServerNotModified.Should().BeTrue();
        await preview.LocalAlreadyMatchesRemote.Should().BeFalse();
        await preview.HasUpdate.Should().BeTrue();
        await preview.UpdatePlan!.BeforeSha256.Should().BeEqualTo(local.Sha256);
        await preview.UpdatePlan.AfterSha256.Should().BeEqualTo(remote.Sha256);
        await preview.UpdatePlan.AfterCatalogVersion.Should().BeEqualTo("2");
        await transport.Requests.Count.Should().BeEqualTo(2);
        await transport.Requests[0].Conditional.Should().BeTrue();
        await transport.Requests[1].Conditional.Should().BeFalse();
    }

    [Test]
    public async Task FetchPreview_ShouldRejectRequiredInvalidSignature()
    {
        await using var fixture = await RemoteFixture.CreateAsync("1");
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var remoteBytes = CatalogBytes("2");
        var remote = JsonProviderAsnEndpointCatalog.FromBytes(remoteBytes);
        var sourceItem = new ProviderAsnCatalogRemoteSourceItem
        {
            RegistryId = fixture.Registry.Id,
            Uri = "https://catalog.example/catalog.json",
            SignatureUri = "https://catalog.example/catalog.json.sig",
            SignaturePolicy = (int)ProviderAsnCatalogSignaturePolicy.Required,
            TrustedKeyId = "release-key-1",
            TrustedPublicKeySpkiBase64 = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo()),
            ConfigurationUpdatedAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        };
        var envelope = new ProviderAsnCatalogSignatureEnvelope
        {
            KeyId = "release-key-1",
            CatalogId = remote.Document.Id,
            CatalogVersion = remote.Document.Version,
            CatalogSha256 = remote.Sha256,
            SignedAt = DateTimeOffset.Parse("2026-09-24T09:00:00Z"),
            SignatureBase64 = Convert.ToBase64String(new byte[64]),
        };
        var signatureBytes = Encoding.UTF8.GetBytes(JsonUtils.Serialize(envelope, false));
        var transport = new QueueTransport(
        [
            new ProviderAsnCatalogRemoteTransportResponse
            {
                StatusCode = 200,
                FinalUri = new Uri(sourceItem.Uri),
                Bytes = remoteBytes,
            },
            new ProviderAsnCatalogRemoteTransportResponse
            {
                StatusCode = 200,
                FinalUri = new Uri(sourceItem.SignatureUri),
                Bytes = signatureBytes,
            }
        ]);
        var service = fixture.CreateService(new FakeSourceStore(sourceItem), transport);

        var threw = false;
        try
        {
            await service.FetchPreviewAsync(fixture.Registry.Id);
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.Message.Contains("signature policy failed", StringComparison.OrdinalIgnoreCase);
        }

        await threw.Should().BeTrue();
        await (await File.ReadAllTextAsync(fixture.Path)).Should().Contain("\"version\":\"1\"");
    }


    [Test]
    public async Task FetchPreview_ShouldPropagateConfiguredTlsSpkiPinsToTransport()
    {
        await using var fixture = await RemoteFixture.CreateAsync("1");
        var pin = new string('a', 64);
        var remoteBytes = CatalogBytes("2");
        var sourceStore = new FakeSourceStore(null);
        var transport = new QueueTransport(
        [
            new ProviderAsnCatalogRemoteTransportResponse
            {
                StatusCode = 200,
                FinalUri = new Uri("https://catalog.example/catalog.json"),
                Bytes = remoteBytes,
            }
        ]);
        var service = fixture.CreateService(sourceStore, transport);

        await service.ConfigureAsync(
            fixture.Registry.Id,
            new ProviderAsnCatalogRemoteSourceConfig
            {
                Uri = "https://catalog.example/catalog.json",
                TlsSpkiPinsSha256 = [pin],
            });

        var preview = await service.FetchPreviewAsync(fixture.Registry.Id);

        await preview.HasUpdate.Should().BeTrue();
        await transport.Requests.Count.Should().BeEqualTo(1);
        await transport.Requests[0].TlsSpkiPinsSha256.SequenceEqual([pin]).Should().BeTrue();
        await sourceStore.Item.Should().NotBeNull();
        await ProviderAsnCatalogTransportPinning.DeserializePins(
                sourceStore.Item!.TlsSpkiPinsSha256Json)
            .SequenceEqual([pin]).Should().BeTrue();
    }

    [Test]
    public async Task Apply_ShouldPersistRevisionLinkedRemoteProvenanceAfterSuccessfulApply()
    {
        await using var fixture = await RemoteFixture.CreateAsync("1");
        var remoteBytes = CatalogBytes("2");
        var remote = JsonProviderAsnEndpointCatalog.FromBytes(remoteBytes);
        var sourceStore = new FakeSourceStore(Source(fixture.Registry.Id, string.Empty));
        var provenance = new FakeProvenanceStore();
        var transport = new QueueTransport(
        [
            new ProviderAsnCatalogRemoteTransportResponse
            {
                StatusCode = 200,
                FinalUri = new Uri("https://catalog.example/redirected/catalog.json"),
                Bytes = remoteBytes,
                ETag = "\"v2\"",
                LastModified = DateTimeOffset.Parse("2026-09-24T09:00:00Z"),
            }
        ]);
        var service = fixture.CreateService(sourceStore, transport, provenance);
        var preview = await service.FetchPreviewAsync(
            fixture.Registry.Id,
            DateTimeOffset.Parse("2026-09-24T10:00:00Z"));

        var revision = await service.ApplyAsync(preview);

        await revision.AfterCatalogVersion.Should().BeEqualTo("2");
        await provenance.Item.Should().NotBeNull();
        await provenance.Item!.RevisionId.Should().BeEqualTo(revision.Id);
        await provenance.Item.RegistryId.Should().BeEqualTo(fixture.Registry.Id);
        await provenance.Item.SourceUri.Should().BeEqualTo(sourceStore.Item!.Uri);
        await provenance.Item.SourceFinalUri.Should().BeEqualTo("https://catalog.example/redirected/catalog.json");
        await provenance.Item.RemoteContentSha256.Should().BeEqualTo(remote.Sha256);
        await provenance.Item.ETag.Should().BeEqualTo("\"v2\"");
        await provenance.Item.SignaturePolicySatisfied.Should().BeTrue();

        var projected = await service.GetRevisionProvenanceAsync(revision.Id);
        await projected.Should().NotBeNull();
        await projected!.RevisionId.Should().BeEqualTo(revision.Id);
        await projected.SourceFinalUri.Should().BeEqualTo("https://catalog.example/redirected/catalog.json");
        await projected.RemoteContentSha256.Should().BeEqualTo(remote.Sha256);
    }

    [Test]
    public async Task Apply_ShouldRollbackCatalogWhenProvenancePersistenceFails()
    {
        await using var fixture = await RemoteFixture.CreateAsync("1");
        var remoteBytes = CatalogBytes("2");
        var sourceStore = new FakeSourceStore(Source(fixture.Registry.Id, string.Empty));
        var provenance = new FakeProvenanceStore { FailWrites = true };
        var transport = new QueueTransport(
        [
            new ProviderAsnCatalogRemoteTransportResponse
            {
                StatusCode = 200,
                FinalUri = new Uri(sourceStore.Item!.Uri),
                Bytes = remoteBytes,
                ETag = "\"v2\"",
            }
        ]);
        var service = fixture.CreateService(sourceStore, transport, provenance);
        var preview = await service.FetchPreviewAsync(fixture.Registry.Id);

        var threw = false;
        try
        {
            await service.ApplyAsync(preview);
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.Message.Contains("provenance", StringComparison.OrdinalIgnoreCase)
                    && ex.Message.Contains("rolled back", StringComparison.OrdinalIgnoreCase);
        }

        await threw.Should().BeTrue();
        await (await File.ReadAllTextAsync(fixture.Path)).Should().Contain("\"version\":\"1\"");
        var registry = await fixture.GetRegistryAsync();
        await registry.Should().NotBeNull();
        await registry!.CatalogVersion.Should().BeEqualTo("1");
        await registry.ActiveRevisionId.Should().BeEqualTo(string.Empty);
    }

    [Test]
    public async Task Apply_ShouldRejectWhenRemoteCacheChangesAfterPreview()
    {
        await using var fixture = await RemoteFixture.CreateAsync("1");
        var remoteBytes = CatalogBytes("2");
        var remote = JsonProviderAsnEndpointCatalog.FromBytes(remoteBytes);
        var sourceStore = new FakeSourceStore(Source(fixture.Registry.Id, string.Empty));
        var transport = new QueueTransport(
        [
            new ProviderAsnCatalogRemoteTransportResponse
            {
                StatusCode = 200,
                FinalUri = new Uri(sourceStore.Item!.Uri),
                Bytes = remoteBytes,
                ETag = "\"v2\"",
            }
        ]);
        var service = fixture.CreateService(sourceStore, transport);
        var preview = await service.FetchPreviewAsync(fixture.Registry.Id);
        await preview.HasUpdate.Should().BeTrue();

        sourceStore.Item!.RemoteContentSha256 = new string('f', 64);
        await sourceStore.UpsertAsync(sourceStore.Item);

        var threw = false;
        try
        {
            await service.ApplyAsync(preview);
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.Message.Contains("cache changed", StringComparison.OrdinalIgnoreCase);
        }

        await threw.Should().BeTrue();
        await (await File.ReadAllTextAsync(fixture.Path)).Should().Contain("\"version\":\"1\"");
    }

    [Test]
    public async Task Apply_ShouldRejectSameTimestampConfigurationCollisionAfterPreview()
    {
        await using var fixture = await RemoteFixture.CreateAsync("1");
        var remoteBytes = CatalogBytes("2");
        var sourceStore = new FakeSourceStore(Source(fixture.Registry.Id, string.Empty));
        var transport = new QueueTransport(
        [
            new ProviderAsnCatalogRemoteTransportResponse
            {
                StatusCode = 200,
                FinalUri = new Uri(sourceStore.Item!.Uri),
                Bytes = remoteBytes,
                ETag = "\"v2\"",
            }
        ]);
        var service = fixture.CreateService(sourceStore, transport);
        var preview = await service.FetchPreviewAsync(fixture.Registry.Id);
        await preview.HasUpdate.Should().BeTrue();
        await preview.SourceConfigurationFingerprint.Should().NotBeEmpty();

        var originalRevision = sourceStore.Item!.ConfigurationUpdatedAtUnixMs;
        var fetchedHash = sourceStore.Item.RemoteContentSha256;
        sourceStore.Item.Uri = "https://catalog.example/reconfigured.json";
        sourceStore.Item.ConfigurationUpdatedAtUnixMs = originalRevision; // deterministic millisecond collision
        sourceStore.Item.RemoteContentSha256 = fetchedHash; // identical content under the new trust configuration
        await sourceStore.UpsertAsync(sourceStore.Item);

        var threw = false;
        try
        {
            await service.ApplyAsync(preview);
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.Message.Contains("trust/configuration changed", StringComparison.OrdinalIgnoreCase);
        }

        await threw.Should().BeTrue();
        await (await File.ReadAllTextAsync(fixture.Path)).Should().Contain("\"version\":\"1\"");
    }

    [Test]
    public async Task Get_ShouldRejectInvalidStoredSignaturePolicy_InsteadOfDisplayingNone()
    {
        await using var fixture = await RemoteFixture.CreateAsync("1");
        var source = Source(fixture.Registry.Id, string.Empty);
        source.SignaturePolicy = int.MaxValue;
        var service = fixture.CreateService(
            new FakeSourceStore(source),
            new QueueTransport([]));

        var threw = false;
        try
        {
            await service.GetAsync(fixture.Registry.Id);
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.Message.Contains("signature policy", StringComparison.OrdinalIgnoreCase);
        }

        await threw.Should().BeTrue();
    }

    [Test]
    public async Task Configure_ShouldRejectSharedPinsAcrossDifferentSignatureAuthority()
    {
        await using var fixture = await RemoteFixture.CreateAsync("1");
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var service = fixture.CreateService(
            new FakeSourceStore(null),
            new QueueTransport([]));

        var threw = false;
        try
        {
            await service.ConfigureAsync(
                fixture.Registry.Id,
                new ProviderAsnCatalogRemoteSourceConfig
                {
                    Uri = "https://catalog.example/catalog.json",
                    SignatureUri = "https://signatures.example/catalog.json.sig",
                    SignaturePolicy = ProviderAsnCatalogSignaturePolicy.Required,
                    TrustedKeyId = "release-key-1",
                    TrustedPublicKeySpkiBase64 = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo()),
                    TlsSpkiPinsSha256 = [new string('a', 64)],
                });
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.Message.Contains("different catalog and signature authorities", StringComparison.OrdinalIgnoreCase);
        }

        await threw.Should().BeTrue();
    }

    [Test]
    public async Task Configure_ShouldHonorCrossProcessRemoteOperationLease()
    {
        await using var fixture = await RemoteFixture.CreateAsync("1");
        var sourceStore = new FakeSourceStore(null);
        var service = fixture.CreateService(
            sourceStore,
            new QueueTransport([]));

        var lockPath = Path.Combine(
            Path.GetDirectoryName(fixture.Path)!,
            "." + Path.GetFileName(fixture.Path) + ".pattn-remote.lock");
        await using var heldLease = new FileStream(
            lockPath,
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.None);

        using var timeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));
        var cancelled = false;
        try
        {
            await service.ConfigureAsync(
                fixture.Registry.Id,
                new ProviderAsnCatalogRemoteSourceConfig
                {
                    Uri = "https://catalog.example/catalog.json",
                },
                cancellationToken: timeout.Token);
        }
        catch (OperationCanceledException)
        {
            cancelled = true;
        }

        await cancelled.Should().BeTrue();
        await sourceStore.Item.Should().BeNull();
    }

    [Test]
    public async Task Configure_ShouldRejectNonHttpsRemoteUri()
    {
        await using var fixture = await RemoteFixture.CreateAsync("1");
        var service = fixture.CreateService(
            new FakeSourceStore(null),
            new QueueTransport([]));

        var threw = false;
        try
        {
            await service.ConfigureAsync(
                fixture.Registry.Id,
                new ProviderAsnCatalogRemoteSourceConfig
                {
                    Uri = "http://catalog.example/catalog.json",
                });
        }
        catch (ArgumentException)
        {
            threw = true;
        }

        await threw.Should().BeTrue();
    }

    private static ProviderAsnCatalogRemoteSourceItem Source(
        string registryId,
        string remoteSha)
        => new()
        {
            RegistryId = registryId,
            Uri = "https://catalog.example/catalog.json",
            SignaturePolicy = (int)ProviderAsnCatalogSignaturePolicy.None,
            ETag = "\"cached\"",
            RemoteContentSha256 = remoteSha,
            ConfigurationUpdatedAtUnixMs = DateTimeOffset.Parse("2026-09-24T08:00:00Z").ToUnixTimeMilliseconds(),
            CacheUpdatedAtUnixMs = DateTimeOffset.Parse("2026-09-24T08:30:00Z").ToUnixTimeMilliseconds(),
        };

    private static byte[] CatalogBytes(string version)
        => Encoding.UTF8.GetBytes(
            $$"""
            {
              "schemaVersion":1,
              "id":"catalog-a",
              "version":"{{version}}",
              "source":"remote-test",
              "updatedAt":"2026-09-24T00:00:00Z",
              "entries":[
                {
                  "address":"203.0.113.7",
                  "provider":"Example CDN",
                  "asn":"AS64500",
                  "pop":"test"
                }
              ]
            }
            """);

    private sealed class QueueTransport(
        IReadOnlyList<ProviderAsnCatalogRemoteTransportResponse> responses)
        : IProviderAsnCatalogRemoteTransport
    {
        private readonly Queue<ProviderAsnCatalogRemoteTransportResponse> _responses = new(responses);
        public List<ProviderAsnCatalogRemoteTransportRequest> Requests { get; } = [];

        public Task<ProviderAsnCatalogRemoteTransportResponse> FetchAsync(
            ProviderAsnCatalogRemoteTransportRequest request,
            CancellationToken cancellationToken = default)
        {
            Requests.Add(request);
            if (_responses.Count == 0)
            {
                throw new InvalidOperationException("Unexpected remote fetch.");
            }
            return Task.FromResult(_responses.Dequeue());
        }
    }

    private sealed class FakeSourceStore(ProviderAsnCatalogRemoteSourceItem? item)
        : IProviderAsnCatalogRemoteSourceStore
    {
        public ProviderAsnCatalogRemoteSourceItem? Item { get; private set; } = item;

        public Task<ProviderAsnCatalogRemoteSourceItem?> GetAsync(
            string registryId,
            CancellationToken cancellationToken = default)
            => Task.FromResult(
                Item is not null && Item.RegistryId == registryId ? Item : null);

        public Task<IReadOnlyList<ProviderAsnCatalogRemoteSourceItem>> ListAsync(
            int maxItems = 500,
            CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<ProviderAsnCatalogRemoteSourceItem>>(
                Item is null ? [] : [Item]);

        public Task UpsertAsync(
            ProviderAsnCatalogRemoteSourceItem value,
            CancellationToken cancellationToken = default)
        {
            Item = value;
            return Task.CompletedTask;
        }

        public Task RemoveAsync(
            string registryId,
            CancellationToken cancellationToken = default)
        {
            if (Item?.RegistryId == registryId)
            {
                Item = null;
            }
            return Task.CompletedTask;
        }
    }

    private sealed class FakeProvenanceStore : IProviderAsnCatalogRemoteApplyProvenanceStore
    {
        public ProviderAsnCatalogRemoteApplyProvenanceItem? Item { get; private set; }
        public bool FailWrites { get; init; }

        public Task<ProviderAsnCatalogRemoteApplyProvenanceItem?> GetAsync(
            string revisionId,
            CancellationToken cancellationToken = default)
            => Task.FromResult(
                Item is not null && Item.RevisionId == revisionId ? Item : null);

        public Task<IReadOnlyList<ProviderAsnCatalogRemoteApplyProvenanceItem>> ListByRegistryAsync(
            string registryId,
            int maxItems = 200,
            CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<ProviderAsnCatalogRemoteApplyProvenanceItem>>(
                Item is not null && Item.RegistryId == registryId ? [Item] : []);

        public Task UpsertAsync(
            ProviderAsnCatalogRemoteApplyProvenanceItem item,
            CancellationToken cancellationToken = default)
        {
            if (FailWrites)
            {
                throw new InvalidOperationException("provenance unavailable");
            }
            Item = item;
            return Task.CompletedTask;
        }
    }

    private sealed class FakeRegistryStore : IProviderAsnCatalogRegistryStore
    {
        private ProviderAsnCatalogRegistryItem _registry;
        private readonly Dictionary<string, ProviderAsnCatalogRevisionItem> _revisions = new(StringComparer.Ordinal);

        public FakeRegistryStore(ProviderAsnCatalogRegistryItem registry)
        {
            _registry = registry;
        }

        public Task<IReadOnlyList<ProviderAsnCatalogRegistryItem>> ListAsync(
            ProviderAsnCatalogRegistryQuery? query = null,
            CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<ProviderAsnCatalogRegistryItem>>([_registry]);

        public Task<ProviderAsnCatalogRegistryItem?> GetAsync(
            string id,
            CancellationToken cancellationToken = default)
            => Task.FromResult<ProviderAsnCatalogRegistryItem?>(
                id == _registry.Id ? _registry : null);

        public Task<ProviderAsnCatalogRegistryItem?> FindByPathAsync(
            string normalizedPath,
            CancellationToken cancellationToken = default)
            => Task.FromResult<ProviderAsnCatalogRegistryItem?>(_registry);

        public Task UpsertAsync(
            ProviderAsnCatalogRegistryItem item,
            CancellationToken cancellationToken = default)
        {
            _registry = item;
            return Task.CompletedTask;
        }

        public Task RemoveAsync(string id, CancellationToken cancellationToken = default)
            => Task.CompletedTask;

        public Task<int> RetireAsync(
            ProviderAsnCatalogRegistryItem item,
            bool discardRevisionHistory,
            CancellationToken cancellationToken = default)
            => Task.FromResult(0);

        public Task<IReadOnlyList<ProviderAsnCatalogRevisionItem>> ListRevisionsAsync(
            ProviderAsnCatalogRevisionQuery? query = null,
            CancellationToken cancellationToken = default)
        {
            query ??= new ProviderAsnCatalogRevisionQuery();
            var rows = _revisions.Values
                .Where(x => query.RegistryId.IsNullOrEmpty() || x.RegistryId == query.RegistryId)
                .Where(x => query.IncludeRolledBack || x.RolledBackAtUnixMs is null)
                .OrderByDescending(x => x.AppliedAtUnixMs)
                .Take(query.MaxItems)
                .ToArray();
            return Task.FromResult<IReadOnlyList<ProviderAsnCatalogRevisionItem>>(rows);
        }

        public Task<ProviderAsnCatalogRevisionItem?> GetRevisionAsync(
            string id,
            CancellationToken cancellationToken = default)
            => Task.FromResult(_revisions.TryGetValue(id, out var value) ? value : null);

        public Task InsertRevisionAsync(
            ProviderAsnCatalogRevisionItem item,
            CancellationToken cancellationToken = default)
        {
            if (!_revisions.TryAdd(item.Id, item))
            {
                throw new InvalidOperationException("duplicate revision");
            }
            return Task.CompletedTask;
        }

        public Task UpdateRevisionAsync(
            ProviderAsnCatalogRevisionItem item,
            CancellationToken cancellationToken = default)
        {
            _revisions[item.Id] = item;
            return Task.CompletedTask;
        }
    }

    private sealed class RemoteFixture : IAsyncDisposable
    {
        private RemoteFixture(
            string directory,
            string path,
            ProviderAsnCatalogRegistryItem registry,
            FakeRegistryStore registryStore)
        {
            Directory = directory;
            Path = path;
            Registry = registry;
            RegistryStore = registryStore;
        }

        private string Directory { get; }
        public string Path { get; }
        public ProviderAsnCatalogRegistryItem Registry { get; }
        private FakeRegistryStore RegistryStore { get; }

        public static async Task<RemoteFixture> CreateAsync(string version)
        {
            var directory = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "pattn-remote-" + Guid.NewGuid().ToString("N"));
            System.IO.Directory.CreateDirectory(directory);
            var path = System.IO.Path.Combine(directory, "catalog.json");
            var bytes = CatalogBytes(version);
            await File.WriteAllBytesAsync(path, bytes);
            var catalog = JsonProviderAsnEndpointCatalog.FromBytes(bytes);
            var now = DateTimeOffset.UtcNow;
            var registry = new ProviderAsnCatalogRegistryItem
            {
                Id = "registry-1",
                FilePath = path,
                DisplayName = "Catalog A",
                Enabled = true,
                CatalogId = catalog.Document.Id,
                CatalogVersion = catalog.Document.Version,
                CatalogSource = catalog.Document.Source,
                Sha256 = catalog.Sha256,
                RegisteredAtUnixMs = now.AddDays(-2).ToUnixTimeMilliseconds(),
                UpdatedAtUnixMs = now.AddHours(-1).ToUnixTimeMilliseconds(),
            };
            return new RemoteFixture(
                directory,
                path,
                registry,
                new FakeRegistryStore(registry));
        }

        public ProviderAsnCatalogRemoteUpdateService CreateService(
            IProviderAsnCatalogRemoteSourceStore sources,
            IProviderAsnCatalogRemoteTransport transport,
            IProviderAsnCatalogRemoteApplyProvenanceStore? provenance = null)
            => new(
                new ProviderAsnCatalogRegistryService(RegistryStore),
                sources,
                transport,
                provenance);

        public Task<ProviderAsnCatalogRegistryItem?> GetRegistryAsync()
            => RegistryStore.GetAsync(Registry.Id);

        public ValueTask DisposeAsync()
        {
            if (System.IO.Directory.Exists(Directory))
            {
                System.IO.Directory.Delete(Directory, recursive: true);
            }
            return ValueTask.CompletedTask;
        }
    }
}
