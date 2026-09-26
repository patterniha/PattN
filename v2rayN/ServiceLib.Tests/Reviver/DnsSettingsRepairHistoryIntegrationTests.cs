using ServiceLib.Reviver.Models;
using ServiceLib.Reviver.Promotion;
using ServiceLib.Reviver.Services;

namespace ServiceLib.Tests.Reviver;

public class DnsSettingsRepairHistoryIntegrationTests
{
    [Test]
    public async Task ApplyAndRollback_ShouldWriteHistoryAfterSuccessfulPersistence()
    {
        var history = new CapturingHistoryStore();
        var service = new DnsSettingsRepairService(history, _ => Task.FromResult(0));
        var config = ConfigWithDns();
        var plan = service.Prepare(config, Resolver(), "2026-09-23");

        var receipt = await service.ApplyAsync(config, plan);
        await history.Applied.Count.Should().BeEqualTo(1);
        await history.Applied[0].PlanId.Should().BeEqualTo(receipt.PlanId);
        await service.GetLatestActiveReceiptAsync().Should().NotBeNull();

        await service.RollbackAsync(config, receipt);
        await history.RolledBack.Count.Should().BeEqualTo(1);
    }

    [Test]
    public async Task FailedPersistence_ShouldNotWriteAppliedHistory()
    {
        var history = new CapturingHistoryStore();
        var calls = 0;
        var service = new DnsSettingsRepairService(history, _ =>
        {
            calls++;
            return Task.FromResult(calls == 1 ? -1 : 0);
        });
        var config = ConfigWithDns();
        var plan = service.Prepare(config, Resolver(), "2026-09-23");

        var threw = false;
        try
        {
            await service.ApplyAsync(config, plan);
        }
        catch (InvalidOperationException)
        {
            threw = true;
        }

        await threw.Should().BeTrue();
        await history.Applied.Count.Should().BeEqualTo(0);
    }

    [Test]
    public async Task Apply_WhenHistoryWriteFails_ShouldRestorePreviousSettingsAndNeutralizeHistory()
    {
        var history = new CapturingHistoryStore
        {
            FailAppliedWrites = true,
        };
        var saves = 0;
        var service = new DnsSettingsRepairService(history, _ =>
        {
            saves++;
            return Task.FromResult(0);
        });
        var config = ConfigWithDns();
        var plan = service.Prepare(config, Resolver(), "2026-09-23");

        var message = string.Empty;
        try
        {
            await service.ApplyAsync(config, plan);
        }
        catch (InvalidOperationException ex)
        {
            message = ex.Message;
        }

        await message.Should().Contain("history");
        await config.SimpleDNSItem.RemoteDNS.Should().BeEqualTo("https://old.example/dns-query");
        await config.SimpleDNSItem.BootstrapDNS.Should().BeEqualTo("192.0.2.53");
        await saves.Should().BeEqualTo(2);
        await history.AppliedAttempts.Should().BeEqualTo(1);
        await history.RolledBack.Count.Should().BeEqualTo(1);
    }

    [Test]
    public async Task Rollback_WhenHistoryWriteFails_ShouldRestoreAppliedSettingsAndReactivateHistory()
    {
        var history = new CapturingHistoryStore();
        var saves = 0;
        var service = new DnsSettingsRepairService(history, _ =>
        {
            saves++;
            return Task.FromResult(0);
        });
        var config = ConfigWithDns();
        var plan = service.Prepare(config, Resolver(), "2026-09-23");
        var receipt = await service.ApplyAsync(config, plan);

        history.FailRolledBackWrites = true;

        var message = string.Empty;
        try
        {
            await service.RollbackAsync(config, receipt);
        }
        catch (InvalidOperationException ex)
        {
            message = ex.Message;
        }

        await message.Should().Contain("rollback history");
        await config.SimpleDNSItem.RemoteDNS.Should().BeEqualTo("https://cloudflare-dns.com/dns-query");
        await config.SimpleDNSItem.BootstrapDNS.Should().BeEqualTo("1.1.1.1");
        await saves.Should().BeEqualTo(3);
        await history.Applied.Count.Should().BeEqualTo(2);
        await history.RolledBackAttempts.Should().BeEqualTo(1);
        await history.Applied[^1].AppliedAt.Should().BeGreaterThanOrEqualTo(receipt.AppliedAt);
    }

    private static Config ConfigWithDns()
        => new()
        {
            SimpleDNSItem = new SimpleDNSItem
            {
                RemoteDNS = "https://old.example/dns-query",
                BootstrapDNS = "192.0.2.53",
            },
        };

    private static DnsResolverRecommendation Resolver()
        => new()
        {
            CatalogId = "cloudflare-standard",
            Provider = "Cloudflare",
            Name = "Cloudflare",
            IPv4 = ["1.1.1.1"],
            DohUrl = "https://cloudflare-dns.com/dns-query",
            Policy = "neutral",
            ReferenceEligible = true,
        };

    private sealed class CapturingHistoryStore : IDnsSettingsRepairHistoryStore
    {
        public List<DnsSettingsRepairReceipt> Applied { get; } = [];
        public List<DnsSettingsRepairReceipt> RolledBack { get; } = [];
        public bool FailAppliedWrites { get; set; }
        public bool FailRolledBackWrites { get; set; }
        public int AppliedAttempts { get; private set; }
        public int RolledBackAttempts { get; private set; }

        public Task RecordAppliedAsync(DnsSettingsRepairReceipt receipt, CancellationToken cancellationToken = default)
        {
            AppliedAttempts++;
            if (FailAppliedWrites)
            {
                throw new IOException("simulated applied-history persistence failure");
            }

            Applied.Add(receipt);
            return Task.CompletedTask;
        }

        public Task RecordRolledBackAsync(DnsSettingsRepairReceipt receipt, CancellationToken cancellationToken = default)
        {
            RolledBackAttempts++;
            if (FailRolledBackWrites)
            {
                throw new IOException("simulated rollback-history persistence failure");
            }

            RolledBack.Add(receipt);
            return Task.CompletedTask;
        }

        public Task<DnsSettingsRepairReceipt?> GetLatestActiveAsync(CancellationToken cancellationToken = default)
            => Task.FromResult<DnsSettingsRepairReceipt?>(Applied.LastOrDefault());
    }
}
