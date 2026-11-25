using ServiceLib.Tests.CoreConfig;

namespace ServiceLib.Tests.Manager;

// PattN: a profile looked up by its name, as the exit-node of an Aether profile names one (PattNG ByName): every
// profile with the name is found, so that none and several can be told apart. The names are unique to each test, as
// the test database holds other tests' profiles too. Not beside other tests, whose transactions share the connection.
[NotInParallel]
public class AppManagerProfileNameTests
{
    private static async Task Add(Config config, string remarks, string subId)
    {
        var profile = CoreConfigTestFactory.CreateSocksNode(ECoreType.Xray, string.Empty, remarks);
        profile.Subid = subId;
        await ConfigDbHandler.AddServerCommon(profile);
    }

    [Test]
    public async Task EveryProfileWithTheNameIsFoundWithoutTheSpacesAroundIt()
    {
        var config = CoreConfigTestFactory.CreateConfig();
        CoreConfigTestFactory.BindAppManagerConfig(config);
        SQLiteHelper.Instance.CreateTable<ProfileItem>();
        var name = $"exit-{Guid.NewGuid():N}";
        var subId = $"sub-{Guid.NewGuid():N}";
        await Add(config, name, subId);
        await Add(config, $" {name}\t", subId);
        await Add(config, $"{name}-2", subId);
        await Add(config, name.ToUpperInvariant(), subId);
        await Add(config, $"x{name}", subId);

        var found = await ConfigDbQuery.GetProfileItemsViaRemarksAsync($"  {name} ");

        await found.Count.Should().BeEqualTo(2);
        await found.All(profile => profile.Remarks.Trim() == name).Should().BeTrue();
        await (await ConfigDbQuery.GetProfileItemsViaRemarksAsync($"{name}-2")).Count.Should().BeEqualTo(1);
        await (await ConfigDbQuery.GetProfileItemsViaRemarksAsync($"none-{name}")).Count.Should().BeEqualTo(0);
        await (await ConfigDbQuery.GetProfileItemsViaRemarksAsync("  ")).Count.Should().BeEqualTo(0);
        await (await ConfigDbQuery.GetProfileItemsViaRemarksAsync(null)).Count.Should().BeEqualTo(0);
    }
}
