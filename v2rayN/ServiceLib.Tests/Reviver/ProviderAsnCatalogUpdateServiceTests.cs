using System.Text;
using ServiceLib.Discovery.Models;
using ServiceLib.Discovery.Services;

namespace ServiceLib.Tests.Reviver;

public class ProviderAsnCatalogUpdateServiceTests
{
    [Test]
    public async Task PrepareApplyRollback_ShouldRoundTripExistingCatalogWithoutPrepareSideEffects()
    {
        var root = CreateTempDirectory();
        try
        {
            var path = Path.Combine(root, "catalog.json");
            var before = Catalog("catalog", "v1", "203.0.113.10", "2026-09-01T00:00:00Z", "A");
            var after = Catalog("catalog", "v2", "203.0.113.20", "2026-09-02T00:00:00Z", "B");
            await File.WriteAllBytesAsync(path, before);

            var service = new ProviderAsnCatalogUpdateService();
            var plan = await service.PrepareAsync(
                path,
                after,
                now: new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero));

            await (await File.ReadAllBytesAsync(path)).SequenceEqual(before).Should().BeTrue();
            await plan.Diff.Should().NotBeNull();
            await plan.Diff!.Modified.Should().BeEqualTo(1);

            var receipt = await service.ApplyAsync(plan);
            await (await File.ReadAllBytesAsync(path)).SequenceEqual(after).Should().BeTrue();

            await service.RollbackAsync(receipt);
            await (await File.ReadAllBytesAsync(path)).SequenceEqual(before).Should().BeTrue();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Test]
    public async Task Apply_ShouldRejectStalePlanWithoutOverwritingExternalChange()
    {
        var root = CreateTempDirectory();
        try
        {
            var path = Path.Combine(root, "catalog.json");
            var before = Catalog("catalog", "v1", "203.0.113.10", "2026-09-01T00:00:00Z");
            var after = Catalog("catalog", "v2", "203.0.113.20", "2026-09-02T00:00:00Z");
            var external = Catalog("catalog", "external", "203.0.113.99", "2026-09-03T00:00:00Z");
            await File.WriteAllBytesAsync(path, before);

            var service = new ProviderAsnCatalogUpdateService();
            var plan = await service.PrepareAsync(path, after);
            await File.WriteAllBytesAsync(path, external);

            var threw = false;
            try
            {
                await service.ApplyAsync(plan);
            }
            catch (InvalidOperationException)
            {
                threw = true;
            }

            await threw.Should().BeTrue();
            await (await File.ReadAllBytesAsync(path)).SequenceEqual(external).Should().BeTrue();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Test]
    public async Task Rollback_ShouldProtectNewerEditUnlessForced()
    {
        var root = CreateTempDirectory();
        try
        {
            var path = Path.Combine(root, "catalog.json");
            var before = Catalog("catalog", "v1", "203.0.113.10", "2026-09-01T00:00:00Z");
            var after = Catalog("catalog", "v2", "203.0.113.20", "2026-09-02T00:00:00Z");
            var external = Catalog("catalog", "external", "203.0.113.99", "2026-09-03T00:00:00Z");
            await File.WriteAllBytesAsync(path, before);

            var service = new ProviderAsnCatalogUpdateService();
            var receipt = await service.ApplyAsync(await service.PrepareAsync(path, after));
            await File.WriteAllBytesAsync(path, external);

            var threw = false;
            try
            {
                await service.RollbackAsync(receipt);
            }
            catch (InvalidOperationException)
            {
                threw = true;
            }

            await threw.Should().BeTrue();
            await (await File.ReadAllBytesAsync(path)).SequenceEqual(external).Should().BeTrue();

            await service.RollbackAsync(receipt, force: true);
            await (await File.ReadAllBytesAsync(path)).SequenceEqual(before).Should().BeTrue();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Test]
    public async Task Rollback_ShouldDeleteCatalogThatDidNotExistBeforeApply()
    {
        var root = CreateTempDirectory();
        try
        {
            var path = Path.Combine(root, "catalog.json");
            var after = Catalog("catalog", "v1", "203.0.113.20", "2026-09-02T00:00:00Z");
            var service = new ProviderAsnCatalogUpdateService();

            var receipt = await service.ApplyAsync(await service.PrepareAsync(path, after));
            await File.Exists(path).Should().BeTrue();

            await service.RollbackAsync(receipt);
            await File.Exists(path).Should().BeFalse();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Test]
    public async Task ConcurrentApplyPlans_ShouldSerializeAndRejectTheStaleWriter()
    {
        var root = CreateTempDirectory();
        try
        {
            var path = Path.Combine(root, "catalog.json");
            var before = Catalog("catalog", "v1", "203.0.113.10", "2026-09-01T00:00:00Z");
            var afterA = Catalog("catalog", "v2-a", "203.0.113.20", "2026-09-02T00:00:00Z");
            var afterB = Catalog("catalog", "v2-b", "203.0.113.21", "2026-09-02T00:00:00Z");
            await File.WriteAllBytesAsync(path, before);

            var first = new ProviderAsnCatalogUpdateService();
            var second = new ProviderAsnCatalogUpdateService();
            var planA = await first.PrepareAsync(path, afterA);
            var planB = await second.PrepareAsync(path, afterB);

            async Task<bool> ApplyAsync(ProviderAsnCatalogUpdateService service, ProviderAsnCatalogUpdatePlan plan)
            {
                try
                {
                    await service.ApplyAsync(plan);
                    return true;
                }
                catch (InvalidOperationException)
                {
                    return false;
                }
            }

            var results = await Task.WhenAll(
                ApplyAsync(first, planA),
                ApplyAsync(second, planB));

            await results.Count(x => x).Should().BeEqualTo(1);
            var final = await File.ReadAllBytesAsync(path);
            await (final.SequenceEqual(afterA) || final.SequenceEqual(afterB)).Should().BeTrue();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Test]
    public async Task Prepare_ShouldRejectCatalogIdChangeAndOptionalFreshnessRequirement()
    {
        var root = CreateTempDirectory();
        try
        {
            var path = Path.Combine(root, "catalog.json");
            await File.WriteAllBytesAsync(
                path,
                Catalog("catalog-a", "v1", "203.0.113.10", "2026-09-01T00:00:00Z"));

            var service = new ProviderAsnCatalogUpdateService();

            var idThrew = false;
            try
            {
                await service.PrepareAsync(
                    path,
                    Catalog("catalog-b", "v2", "203.0.113.20", "2026-09-02T00:00:00Z"));
            }
            catch (InvalidOperationException)
            {
                idThrew = true;
            }
            await idThrew.Should().BeTrue();

            var freshnessThrew = false;
            try
            {
                await service.PrepareAsync(
                    path,
                    CatalogWithoutUpdatedAt("catalog-a", "v2", "203.0.113.20"),
                    new ProviderAsnCatalogUpdateOptions { RequireFreshNewCatalog = true });
            }
            catch (InvalidOperationException)
            {
                freshnessThrew = true;
            }
            await freshnessThrew.Should().BeTrue();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Test]
    public async Task ApplyAndRollback_ShouldSupportEmptyInvalidPreviousFile()
    {
        var root = CreateTempDirectory();
        try
        {
            var path = Path.Combine(root, "catalog.json");
            await File.WriteAllBytesAsync(path, []);
            var after = Catalog("catalog", "v1", "203.0.113.20", "2026-09-02T00:00:00Z");
            var service = new ProviderAsnCatalogUpdateService();

            var plan = await service.PrepareAsync(path, after);
            await (plan.BeforeCatalogError.Length > 0).Should().BeTrue();

            var receipt = await service.ApplyAsync(plan);
            await (await File.ReadAllBytesAsync(path)).SequenceEqual(after).Should().BeTrue();

            await service.RollbackAsync(receipt);
            await (await File.ReadAllBytesAsync(path)).Length.Should().BeEqualTo(0);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Test]
    public async Task Prepare_ShouldAllowRepairingAmbiguousExistingCatalogWithoutDiff()
    {
        var root = CreateTempDirectory();
        try
        {
            var path = Path.Combine(root, "catalog.json");
            await File.WriteAllBytesAsync(
                path,
                Encoding.UTF8.GetBytes(
                    """
                    {
                      "schemaVersion":1,
                      "id":"catalog",
                      "version":"v1",
                      "source":"unit-test",
                      "entries":[
                        {"address":"203.0.113.10"},
                        {"address":"203.0.113.10"}
                      ]
                    }
                    """));

            var service = new ProviderAsnCatalogUpdateService();
            var plan = await service.PrepareAsync(
                path,
                Catalog("catalog", "v2", "203.0.113.20", "2026-09-02T00:00:00Z"));

            await (plan.Diff is null).Should().BeTrue();
            await plan.BeforeCatalogError.Contains("diff unavailable", StringComparison.OrdinalIgnoreCase)
                .Should().BeTrue();

            await service.ApplyAsync(plan);
            var loaded = await JsonProviderAsnEndpointCatalog.LoadAsync(path);
            await loaded.Document.Version.Should().BeEqualTo("v2");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Test]
    public async Task Rollback_ShouldRejectTamperedReceiptBeforeMutatingFile()
    {
        var root = CreateTempDirectory();
        try
        {
            var path = Path.Combine(root, "catalog.json");
            var before = Catalog("catalog", "v1", "203.0.113.10", "2026-09-01T00:00:00Z");
            var after = Catalog("catalog", "v2", "203.0.113.20", "2026-09-02T00:00:00Z");
            await File.WriteAllBytesAsync(path, before);

            var service = new ProviderAsnCatalogUpdateService();
            var receipt = await service.ApplyAsync(await service.PrepareAsync(path, after));
            var tampered = receipt with
            {
                BeforeBytes = Encoding.UTF8.GetBytes("tampered"),
            };

            var threw = false;
            try
            {
                await service.RollbackAsync(tampered, force: true);
            }
            catch (InvalidOperationException)
            {
                threw = true;
            }

            await threw.Should().BeTrue();
            await (await File.ReadAllBytesAsync(path)).SequenceEqual(after).Should().BeTrue();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static string CreateTempDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "pattn-provider-catalog-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static byte[] Catalog(
        string id,
        string version,
        string address,
        string updatedAt,
        string provider = "")
        => Encoding.UTF8.GetBytes(
            $$"""
            {
              "schemaVersion":1,
              "id":"{{id}}",
              "version":"{{version}}",
              "source":"unit-test",
              "updatedAt":"{{updatedAt}}",
              "entries":[
                {
                  "address":"{{address}}",
                  "sourceId":"edge-1",
                  "provider":"{{provider}}"
                }
              ]
            }
            """);

    private static byte[] CatalogWithoutUpdatedAt(
        string id,
        string version,
        string address)
        => Encoding.UTF8.GetBytes(
            $$"""
            {
              "schemaVersion":1,
              "id":"{{id}}",
              "version":"{{version}}",
              "source":"unit-test",
              "entries":[{"address":"{{address}}","sourceId":"edge-1"}]
            }
            """);
}
