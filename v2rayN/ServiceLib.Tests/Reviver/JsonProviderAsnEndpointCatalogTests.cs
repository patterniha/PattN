using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;

namespace ServiceLib.Tests.Reviver;

public class JsonProviderAsnEndpointCatalogTests
{
    [Test]
    public async Task FromBytes_ShouldProjectVersionedCatalogProvenance()
    {
        var json =
            """
            {
              "schemaVersion": 1,
              "id": "example-provider-catalog",
              "version": "2026-09-23",
              "source": "reviewed-test-dataset",
              "updatedAt": "2026-09-23T12:00:00Z",
              "entries": [
                {
                  "address": "203.0.113.10",
                  "provider": "Example CDN",
                  "asn": "AS64500",
                  "pop": "FRA",
                  "logicalHosts": ["front.example"]
                }
              ]
            }
            """;
        var bytes = Encoding.UTF8.GetBytes(json);
        var catalog = JsonProviderAsnEndpointCatalog.FromBytes(bytes);

        var values = await catalog.ListAsync(
            new DiscoveryCandidateRequest
            {
                OriginalAddress = "origin.example",
                OriginalPort = 443,
                LogicalHost = "front.example",
                MaxCandidates = 4,
            },
            4);

        await values.Count.Should().BeEqualTo(1);
        await values[0].SourceId.Should().BeEqualTo("example-provider-catalog:0");
        await values[0].Metadata["catalogId"].Should().BeEqualTo("example-provider-catalog");
        await values[0].Metadata["catalogVersion"].Should().BeEqualTo("2026-09-23");
        await values[0].Metadata["catalogSource"].Should().BeEqualTo("reviewed-test-dataset");
        await values[0].Metadata["catalogSha256"].Should().BeEqualTo(
            Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant());
        await values[0].Metadata["catalogSourceIdGenerated"].Should().BeEqualTo("true");
        await values[0].Metadata.ContainsKey("catalogUpdatedAt").Should().BeTrue();
    }

    [Test]
    public async Task FromBytes_ShouldRejectInvalidLiteralAddress()
    {
        var json =
            """
            {
              "schemaVersion": 1,
              "id": "bad",
              "version": "1",
              "source": "test",
              "entries": [
                { "address": "not-an-ip" }
              ]
            }
            """;

        var threw = false;
        try
        {
            JsonProviderAsnEndpointCatalog.FromBytes(Encoding.UTF8.GetBytes(json));
        }
        catch (InvalidOperationException)
        {
            threw = true;
        }

        await threw.Should().BeTrue();
    }

    [Test]
    public async Task FromBytes_ShouldRejectNullEntriesCollectionCleanly()
    {
        var json =
            """
            {
              "schemaVersion": 1,
              "id": "bad-null",
              "version": "1",
              "source": "test",
              "entries": null
            }
            """;

        var threw = false;
        try
        {
            JsonProviderAsnEndpointCatalog.FromBytes(Encoding.UTF8.GetBytes(json));
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.Message.Contains("entries", StringComparison.OrdinalIgnoreCase);
        }

        await threw.Should().BeTrue();
    }

    [Test]
    public async Task FromBytes_ShouldNormalizeNullEntryCollections()
    {
        var json =
            """
            {
              "schemaVersion": 1,
              "id": "nullable-entry",
              "version": "1",
              "source": "test",
              "entries": [
                {
                  "address": "203.0.113.10",
                  "logicalHosts": null,
                  "metadata": null
                }
              ]
            }
            """;

        var catalog = JsonProviderAsnEndpointCatalog.FromBytes(Encoding.UTF8.GetBytes(json));
        var values = await catalog.ListAsync(
            new DiscoveryCandidateRequest
            {
                OriginalAddress = "origin.example",
                OriginalPort = 443,
                LogicalHost = "anything.example",
                MaxCandidates = 4,
            },
            4);

        await values.Count.Should().BeEqualTo(1);
        await values[0].LogicalHosts.Count.Should().BeEqualTo(0);
        await values[0].Metadata["catalogId"].Should().BeEqualTo("nullable-entry");
    }

    [Test]
    public async Task FromBytes_ShouldRejectUnsupportedSchema()
    {
        var json =
            """
            {
              "schemaVersion": 99,
              "id": "future",
              "version": "1",
              "source": "test",
              "entries": []
            }
            """;

        var threw = false;
        try
        {
            JsonProviderAsnEndpointCatalog.FromBytes(Encoding.UTF8.GetBytes(json));
        }
        catch (InvalidOperationException)
        {
            threw = true;
        }

        await threw.Should().BeTrue();
    }
}
