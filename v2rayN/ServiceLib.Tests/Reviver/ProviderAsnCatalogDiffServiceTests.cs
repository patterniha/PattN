using System.Text;
using ServiceLib.Discovery.Services;

namespace ServiceLib.Tests.Reviver;

public class ProviderAsnCatalogDiffServiceTests
{
    [Test]
    public async Task Compare_ShouldTrackAddedAndModifiedExplicitSourceIds()
    {
        var before = JsonProviderAsnEndpointCatalog.FromBytes(Encoding.UTF8.GetBytes(
            """
            {
              "schemaVersion":1,
              "id":"catalog",
              "version":"v1",
              "source":"unit",
              "updatedAt":"2026-09-01T00:00:00Z",
              "entries":[
                {"address":"203.0.113.10","sourceId":"edge-1","provider":"A"}
              ]
            }
            """));
        var after = JsonProviderAsnEndpointCatalog.FromBytes(Encoding.UTF8.GetBytes(
            """
            {
              "schemaVersion":1,
              "id":"catalog",
              "version":"v2",
              "source":"unit",
              "updatedAt":"2026-09-02T00:00:00Z",
              "entries":[
                {"address":"203.0.113.20","sourceId":"edge-1","provider":"B"},
                {"address":"203.0.113.30","sourceId":"edge-2","provider":"A"}
              ]
            }
            """));

        var diff = ProviderAsnCatalogDiffService.Compare(before, after);

        await diff.Added.Should().BeEqualTo(1);
        await diff.Removed.Should().BeEqualTo(0);
        await diff.Modified.Should().BeEqualTo(1);
        await diff.Unchanged.Should().BeEqualTo(0);
        var modified = diff.Entries.Single(x => x.ChangeKind == "modified");
        await modified.Identity.Should().BeEqualTo("source:edge-1");
        await modified.ChangedFields.Contains("address").Should().BeTrue();
        await modified.ChangedFields.Contains("provider").Should().BeTrue();
    }

    [Test]
    public async Task Compare_ShouldIgnoreReorderingForGeneratedSourceIds()
    {
        var before = JsonProviderAsnEndpointCatalog.FromBytes(Encoding.UTF8.GetBytes(
            """
            {
              "schemaVersion":1,
              "id":"catalog",
              "version":"v1",
              "source":"unit",
              "entries":[
                {"address":"203.0.113.10","logicalHosts":["front.example"]},
                {"address":"203.0.113.20","logicalHosts":["front.example"]}
              ]
            }
            """));
        var after = JsonProviderAsnEndpointCatalog.FromBytes(Encoding.UTF8.GetBytes(
            """
            {
              "schemaVersion":1,
              "id":"catalog",
              "version":"v2",
              "source":"unit",
              "entries":[
                {"address":"203.0.113.20","logicalHosts":["FRONT.EXAMPLE."]},
                {"address":"203.0.113.10","logicalHosts":["front.example"]}
              ]
            }
            """));

        var diff = ProviderAsnCatalogDiffService.Compare(before, after);

        await diff.Added.Should().BeEqualTo(0);
        await diff.Removed.Should().BeEqualTo(0);
        await diff.Modified.Should().BeEqualTo(0);
        await diff.Unchanged.Should().BeEqualTo(2);
        await diff.Entries.Count.Should().BeEqualTo(0);
    }

    [Test]
    public async Task Compare_ShouldRejectAmbiguousGeneratedIdentities()
    {
        var catalog = JsonProviderAsnEndpointCatalog.FromBytes(Encoding.UTF8.GetBytes(
            """
            {
              "schemaVersion":1,
              "id":"catalog",
              "version":"v1",
              "source":"unit",
              "entries":[
                {"address":"203.0.113.10"},
                {"address":"203.0.113.10"}
              ]
            }
            """));

        var threw = false;
        try
        {
            ProviderAsnCatalogDiffService.Compare(catalog, catalog);
        }
        catch (InvalidOperationException)
        {
            threw = true;
        }

        await threw.Should().BeTrue();
    }
}
