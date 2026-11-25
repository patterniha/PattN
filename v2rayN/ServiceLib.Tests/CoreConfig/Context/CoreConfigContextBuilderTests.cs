namespace ServiceLib.Tests.CoreConfig.Context;

public class CoreConfigContextBuilderTests
{
    [Test]
    public async Task ResolveNodeAsync_DirectCycleDependency_ShouldFailWithCycleError()
    {
        var config = CoreConfigTestFactory.CreateConfig();
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var groupAId = NewId("group-a");
        var groupBId = NewId("group-b");
        var groupA = CoreConfigTestFactory.CreatePolicyGroupNode(ECoreType.Xray, groupAId, "group-a", [groupBId]);
        var groupB = CoreConfigTestFactory.CreatePolicyGroupNode(ECoreType.Xray, groupBId, "group-b", [groupAId]);

        await UpsertProfilesAsync(groupA, groupB);

        var context = CoreConfigTestFactory.CreateContext(config, groupA, ECoreType.Xray);
        context.AllProxiesMap.Clear();

        var (_, validatorResult) = await CoreConfigContextBuilder.ResolveNodeAsync(context, groupA, false);

        await validatorResult.Success.Should().BeFalse();
        await validatorResult.Errors.Should().Contain(ContainsCycleDependencyMessage);
        await context.AllProxiesMap.Should().NotContainKey(groupA.IndexId);
        await context.AllProxiesMap.Should().NotContainKey(groupB.IndexId);
    }

    [Test]
    public async Task ResolveNodeAsync_IndirectCycleDependency_ShouldFailWithCycleError()
    {
        var config = CoreConfigTestFactory.CreateConfig();
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var groupAId = NewId("group-a");
        var groupBId = NewId("group-b");
        var groupCId = NewId("group-c");
        var groupA = CoreConfigTestFactory.CreatePolicyGroupNode(ECoreType.Xray, groupAId, "group-a", [groupBId]);
        var groupB = CoreConfigTestFactory.CreatePolicyGroupNode(ECoreType.Xray, groupBId, "group-b", [groupCId]);
        var groupC = CoreConfigTestFactory.CreatePolicyGroupNode(ECoreType.Xray, groupCId, "group-c", [groupAId]);

        await UpsertProfilesAsync(groupA, groupB, groupC);

        var context = CoreConfigTestFactory.CreateContext(config, groupA, ECoreType.Xray);
        context.AllProxiesMap.Clear();

        var (_, validatorResult) = await CoreConfigContextBuilder.ResolveNodeAsync(context, groupA, false);

        await validatorResult.Success.Should().BeFalse();
        await validatorResult.Errors.Should().Contain(ContainsCycleDependencyMessage);
        await context.AllProxiesMap.Should().NotContainKey(groupA.IndexId);
        await context.AllProxiesMap.Should().NotContainKey(groupB.IndexId);
        await context.AllProxiesMap.Should().NotContainKey(groupC.IndexId);
    }

    [Test]
    public async Task ResolveNodeAsync_CycleWithValidBranch_ShouldSkipCycleAndKeepValidChild()
    {
        var config = CoreConfigTestFactory.CreateConfig();
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var groupAId = NewId("group-a");
        var groupBId = NewId("group-b");
        var leafId = NewId("leaf");
        var groupA = CoreConfigTestFactory.CreatePolicyGroupNode(ECoreType.Xray, groupAId, "group-a", [groupBId, leafId]);
        var groupB = CoreConfigTestFactory.CreatePolicyGroupNode(ECoreType.Xray, groupBId, "group-b", [groupAId]);
        var leaf = CoreConfigTestFactory.CreateSocksNode(ECoreType.Xray, leafId, "leaf");

        await UpsertProfilesAsync(groupA, groupB, leaf);

        var context = CoreConfigTestFactory.CreateContext(config, groupA, ECoreType.Xray);
        context.AllProxiesMap.Clear();

        var (_, validatorResult) = await CoreConfigContextBuilder.ResolveNodeAsync(context, groupA, false);

        await validatorResult.Success.Should().BeTrue();
        await validatorResult.Errors.Should().BeEmpty();
        await validatorResult.Warnings.Should().Contain(ContainsCycleDependencyMessage);

        await context.AllProxiesMap.Should().ContainKey(leaf.IndexId);
        await context.AllProxiesMap.Should().ContainKey(groupA.IndexId);
        await context.AllProxiesMap.Should().NotContainKey(groupB.IndexId);
        await groupA.GetProtocolExtra().ChildItems.Should().BeEqualTo(leaf.IndexId);
    }

    [Test]
    [Arguments("""{"tag": "ech-out", "protocol": "vless", "settings": {"vnext": [{"address": "ech.example", "port": 443, "users": []}]}}""")]
    [Arguments("""{"tag": "ech-out", "protocol": "socks", "settings": {"servers": [{"address": "ech.example", "port": 1080}]}}""")]
    [Arguments("""{"tag": "ech-out", "protocol": "trojan", "settings": {"address": "ech.example", "port": 443, "password": "x"}}""")]
    [Arguments("""{"tag": "ech-out", "protocol": "wireguard", "settings": {"address": ["172.16.0.2/32"], "peers": [{"endpoint": "ech.example:2408"}, {"endpoint": "[2606:4700::1]:2408"}]}}""")]
    public async Task ResolveNodeAsync_EchOutboundServerDomain_ShouldBeProtected(string echOutbound)
    {
        // PattN: the ECH config query goes through the ECH outbound, so the domain of its server has to
        // resolve directly, like the node's own address.
        var config = CoreConfigTestFactory.CreateConfig();
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewId("ech"), "ech");
        node.StreamSecurity = Global.StreamSecurity;
        node.EchConfigList = "cloudflare-ech.com+https://1.1.1.1/dns-query";
        node.EchOutbound = echOutbound;
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);

        var (_, validatorResult) = await CoreConfigContextBuilder.ResolveNodeAsync(context, node, false);

        await validatorResult.Success.Should().BeTrue();
        await context.ProtectDomainList.Should().BeEquivalentTo(["example.com", "cloudflare-ech.com", "ech.example"]);
    }

    [Test]
    [Arguments("cloudflare-ech.com+https://dns.example/dns-query", "example.com,cloudflare-ech.com,dns.example")]
    [Arguments("cloudflare-ech.com+h2c://dns.example/dns-query", "example.com,cloudflare-ech.com,dns.example")]
    [Arguments("cloudflare-ech.com+udp://dns.example:53", "example.com,cloudflare-ech.com,dns.example")]
    [Arguments("https://dns.example/dns-query", "example.com,dns.example")]
    [Arguments("cloudflare-ech.com+https://1.1.1.1/dns-query", "example.com,cloudflare-ech.com")]
    [Arguments("cloudflare-ech.com+https://[2606:4700:4700::1111]/dns-query", "example.com,cloudflare-ech.com")]
    public async Task ResolveNodeAsync_EchDnsServerDomain_ShouldBeProtected(string echConfigList, string protectedDomains)
    {
        // PattN: Xray resolves the domain of the DNS server that it sends the ECH config query to, so that
        // domain has to resolve directly, like the node's own address. An IP needs no DNS.
        var config = CoreConfigTestFactory.CreateConfig();
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewId("ech-dns"), "ech-dns");
        node.StreamSecurity = Global.StreamSecurity;
        node.EchConfigList = echConfigList;
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);

        var (_, validatorResult) = await CoreConfigContextBuilder.ResolveNodeAsync(context, node, false);

        await validatorResult.Success.Should().BeTrue();
        await context.ProtectDomainList.Should().BeEquivalentTo(protectedDomains.Split(','));
    }

    [Test]
    public async Task ResolveNodeAsync_EchDnsServerDomain_ShouldBeLeftToXray()
    {
        // PattN: sing-box never dials the DNS server of echConfigList; it queries the name before the "+"
        // through its own DNS, so only that name is protected.
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.sing_box);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = CoreConfigTestFactory.CreateVmessNode(ECoreType.sing_box, NewId("ech-dns"), "ech-dns");
        node.StreamSecurity = Global.StreamSecurity;
        node.EchConfigList = "cloudflare-ech.com+https://dns.example/dns-query";
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.sing_box);

        var (_, validatorResult) = await CoreConfigContextBuilder.ResolveNodeAsync(context, node, false);

        await validatorResult.Success.Should().BeTrue();
        await context.ProtectDomainList.Should().BeEquivalentTo(["example.com", "cloudflare-ech.com"]);
    }

    private static string NewId(string prefix)
    {
        return $"{prefix}-{Guid.NewGuid():N}";
    }

    private static bool ContainsCycleDependencyMessage(string message)
    {
        return message.Contains("cycle dependency", StringComparison.OrdinalIgnoreCase)
               || message.Contains("循环依赖", StringComparison.Ordinal)
               || message.Contains("循環依賴", StringComparison.Ordinal)
               || message.Contains("циклическую зависимость", StringComparison.OrdinalIgnoreCase);
    }

    private static async Task UpsertProfilesAsync(params ProfileItem[] profiles)
    {
        TestDatabase.Initialize();
        foreach (var profile in profiles)
        {
            await SQLiteHelper.Instance.ReplaceAsync(profile);
        }
    }
}
