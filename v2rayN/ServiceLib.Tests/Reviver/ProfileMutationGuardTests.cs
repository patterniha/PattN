using ServiceLib.Reviver.Normalization;

namespace ServiceLib.Tests.Reviver;

public class ProfileMutationGuardTests
{
    [Test]
    public async Task ChangesOnly_ShouldDetectNestedTransportMutationThroughSerializedExtra()
    {
        var original = new ProfileItem { ConfigType = EConfigType.VLESS, Address = "a.example", Port = 443, Password = Guid.NewGuid().ToString() };
        original.SetTransportExtra(new TransportExtraItem { Host = "host.example", Path = "/a" });
        var candidate = JsonUtils.DeepCopy(original)!;
        candidate.Address = "203.0.113.1";

        await ProfileMutationGuard.ChangesOnly(original, candidate, nameof(ProfileItem.Address)).Should().BeTrue();

        candidate.SetTransportExtra(candidate.GetTransportExtra() with { Path = "/changed" });
        await ProfileMutationGuard.ChangesOnly(original, candidate, nameof(ProfileItem.Address)).Should().BeFalse();
        await ProfileMutationGuard.ChangedFields(original, candidate).Contains(nameof(ProfileItem.TransportExtra)).Should().BeTrue();
    }
}
