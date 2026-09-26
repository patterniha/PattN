using ServiceLib.Reviver.Models;
using ServiceLib.Reviver.Promotion;

namespace ServiceLib.Tests.Reviver;

public class DnsSettingsRepairServiceTests
{
    [Test]
    public async Task Prepare_ShouldChangeOnlyRemoteAndBootstrapDnsWithoutMutatingConfig()
    {
        var config = ConfigWithDns();
        var before = JsonUtils.Serialize(config.SimpleDNSItem, false);
        var service = new DnsSettingsRepairService(_ => Task.FromResult(0));

        var plan = service.Prepare(config, Cloudflare(), "2026-09-23");

        await JsonUtils.Serialize(config.SimpleDNSItem, false).Should().BeEqualTo(before);
        await plan.After.RemoteDNS.Should().BeEqualTo("https://cloudflare-dns.com/dns-query");
        await plan.After.BootstrapDNS.Should().BeEqualTo("1.1.1.1");
        await plan.After.DirectDNS.Should().BeEqualTo("9.9.9.9");
        await plan.Changes.Count.Should().BeEqualTo(2);
        await plan.Changes.Contains(nameof(SimpleDNSItem.RemoteDNS)).Should().BeTrue();
        await plan.Changes.Contains(nameof(SimpleDNSItem.BootstrapDNS)).Should().BeTrue();
    }

    [Test]
    public async Task ApplyAndRollback_ShouldRoundTripWithConflictProtection()
    {
        var config = ConfigWithDns();
        var saves = 0;
        var service = new DnsSettingsRepairService(_ =>
        {
            saves++;
            return Task.FromResult(0);
        });
        var plan = service.Prepare(config, Cloudflare(), "2026-09-23");

        var receipt = await service.ApplyAsync(config, plan);
        await config.SimpleDNSItem.RemoteDNS.Should().BeEqualTo("https://cloudflare-dns.com/dns-query");
        await saves.Should().BeEqualTo(1);

        config.SimpleDNSItem.RemoteDNS = "https://user-change.example/dns-query";
        var conflict = false;
        try
        {
            await service.RollbackAsync(config, receipt);
        }
        catch (InvalidOperationException)
        {
            conflict = true;
        }

        await conflict.Should().BeTrue();
        await config.SimpleDNSItem.RemoteDNS.Should().BeEqualTo("https://user-change.example/dns-query");

        await service.RollbackAsync(config, receipt, force: true);
        await config.SimpleDNSItem.RemoteDNS.Should().BeEqualTo("https://old.example/dns-query");
        await config.SimpleDNSItem.BootstrapDNS.Should().BeEqualTo("192.0.2.53");
    }

    [Test]
    public async Task Apply_ShouldRejectStalePlan()
    {
        var config = ConfigWithDns();
        var service = new DnsSettingsRepairService(_ => Task.FromResult(0));
        var plan = service.Prepare(config, Cloudflare(), "2026-09-23");
        config.SimpleDNSItem.BootstrapDNS = "8.8.8.8";

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
        await config.SimpleDNSItem.BootstrapDNS.Should().BeEqualTo("8.8.8.8");
    }

    [Test]
    public async Task Apply_ShouldCompensateInMemoryWhenPersistenceFails()
    {
        var config = ConfigWithDns();
        var saves = 0;
        var service = new DnsSettingsRepairService(_ =>
        {
            saves++;
            return Task.FromResult(saves == 1 ? -1 : 0);
        });
        var plan = service.Prepare(config, Cloudflare(), "2026-09-23");

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
        await config.SimpleDNSItem.RemoteDNS.Should().BeEqualTo("https://old.example/dns-query");
        await config.SimpleDNSItem.BootstrapDNS.Should().BeEqualTo("192.0.2.53");
        await saves.Should().BeEqualTo(2);
    }

    [Test]
    public async Task Apply_ShouldCompensateWhenPersistenceThrows()
    {
        var config = ConfigWithDns();
        var saves = 0;
        var service = new DnsSettingsRepairService(_ =>
        {
            saves++;
            if (saves == 1)
            {
                throw new IOException("simulated apply persistence exception");
            }
            return Task.FromResult(0);
        });
        var plan = service.Prepare(config, Cloudflare(), "2026-09-23");

        var threw = false;
        try
        {
            await service.ApplyAsync(config, plan);
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.InnerException is IOException;
        }

        await threw.Should().BeTrue();
        await config.SimpleDNSItem.RemoteDNS.Should().BeEqualTo("https://old.example/dns-query");
        await config.SimpleDNSItem.BootstrapDNS.Should().BeEqualTo("192.0.2.53");
        await saves.Should().BeEqualTo(2);
    }

    [Test]
    public async Task Rollback_ShouldCompensateWhenPersistenceThrows()
    {
        var config = ConfigWithDns();
        var applyService = new DnsSettingsRepairService(_ => Task.FromResult(0));
        var plan = applyService.Prepare(config, Cloudflare(), "2026-09-23");
        var receipt = await applyService.ApplyAsync(config, plan);

        var saves = 0;
        var service = new DnsSettingsRepairService(_ =>
        {
            saves++;
            if (saves == 1)
            {
                throw new IOException("simulated rollback persistence exception");
            }
            return Task.FromResult(0);
        });

        var threw = false;
        try
        {
            await service.RollbackAsync(config, receipt);
        }
        catch (InvalidOperationException ex)
        {
            threw = ex.InnerException is IOException;
        }

        await threw.Should().BeTrue();
        await config.SimpleDNSItem.RemoteDNS.Should().BeEqualTo("https://cloudflare-dns.com/dns-query");
        await config.SimpleDNSItem.BootstrapDNS.Should().BeEqualTo("1.1.1.1");
        await saves.Should().BeEqualTo(2);
    }

    [Test]
    public async Task Apply_ShouldReportUncertainDurableStateWhenCompensationPersistenceAlsoFails()
    {
        var config = ConfigWithDns();
        var saves = 0;
        var service = new DnsSettingsRepairService(_ =>
        {
            saves++;
            return Task.FromResult(-1);
        });
        var plan = service.Prepare(config, Cloudflare(), "2026-09-23");

        var message = string.Empty;
        try
        {
            await service.ApplyAsync(config, plan);
        }
        catch (InvalidOperationException ex)
        {
            message = ex.Message;
        }

        await message.Should().Contain("durable state is uncertain");
        await config.SimpleDNSItem.RemoteDNS.Should().BeEqualTo("https://old.example/dns-query");
        await config.SimpleDNSItem.BootstrapDNS.Should().BeEqualTo("192.0.2.53");
        await saves.Should().BeEqualTo(2);
    }

    [Test]
    public async Task Rollback_ShouldReportUncertainDurableStateWhenRollbackAndCompensationPersistenceFail()
    {
        var config = ConfigWithDns();
        var applyService = new DnsSettingsRepairService(_ => Task.FromResult(0));
        var plan = applyService.Prepare(config, Cloudflare(), "2026-09-23");
        var receipt = await applyService.ApplyAsync(config, plan);

        var saves = 0;
        var failingService = new DnsSettingsRepairService(_ =>
        {
            saves++;
            return Task.FromResult(-1);
        });

        var message = string.Empty;
        try
        {
            await failingService.RollbackAsync(config, receipt);
        }
        catch (InvalidOperationException ex)
        {
            message = ex.Message;
        }

        await message.Should().Contain("durable state is uncertain");
        await config.SimpleDNSItem.RemoteDNS.Should().BeEqualTo("https://cloudflare-dns.com/dns-query");
        await config.SimpleDNSItem.BootstrapDNS.Should().BeEqualTo("1.1.1.1");
        await saves.Should().BeEqualTo(2);
    }

    private static Config ConfigWithDns()
        => new()
        {
            SimpleDNSItem = new SimpleDNSItem
            {
                DirectDNS = "9.9.9.9",
                RemoteDNS = "https://old.example/dns-query",
                BootstrapDNS = "192.0.2.53",
                ParallelQuery = true,
                ServeStale = true,
                Hosts = "localhost 127.0.0.1",
            },
        };

    private static DnsResolverRecommendation Cloudflare()
        => new()
        {
            CatalogId = "cloudflare-standard",
            Provider = "Cloudflare",
            Name = "Cloudflare 1.1.1.1",
            IPv4 = ["1.1.1.1", "1.0.0.1"],
            IPv6 = ["2606:4700:4700::1111"],
            DotServerName = "one.one.one.one",
            DotPort = 853,
            DohUrl = "https://cloudflare-dns.com/dns-query",
            Policy = "neutral",
            ReferenceEligible = true,
        };
}
