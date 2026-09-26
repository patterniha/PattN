using ServiceLib.Reviver.Normalization;

namespace ServiceLib.Tests.Reviver;

public class GoldenProfileCorpusTests
{
    [Test]
    public async Task ModernProfiles_ShouldNormalizeWithoutLosingSemanticFields()
    {
        var normalizer = new ProfileNormalizer();
        var invariants = new ProfileInvariantRegistry();

        foreach (var (_, source, _) in GoldenProfileCorpus.ModernProfiles())
        {
            var beforeProtocol = source.ProtoExtra;
            var beforeTransport = source.TransportExtra;
            var normalized = normalizer.Normalize(source);

            // Canonicalization must never mutate its source snapshot.
            await source.ProtoExtra.Should().BeEqualTo(beforeProtocol);
            await source.TransportExtra.Should().BeEqualTo(beforeTransport);

            var violations = invariants.Validate(normalized);
            await violations.Should().BeEmpty();
        }
    }

    [Test]
    public async Task EndpointRepair_ShouldPreserveEveryNonEndpointSemanticField_InGoldenCorpus()
    {
        foreach (var (_, source, _) in GoldenProfileCorpus.ModernProfiles())
        {
            var candidate = JsonUtils.DeepCopy(source)!;
            candidate.Address = "198.51.100.77";

            var changed = ProfileMutationGuard.ChangedFields(source, candidate);
            await changed.Should().BeEquivalentTo([nameof(ProfileItem.Address)]);
            await ProfileMutationGuard.ChangesOnly(source, candidate, nameof(ProfileItem.Address)).Should().BeTrue();

            await candidate.Port.Should().BeEqualTo(source.Port);
            await candidate.Password.Should().BeEqualTo(source.Password);
            await candidate.Network.Should().BeEqualTo(source.Network);
            await candidate.StreamSecurity.Should().BeEqualTo(source.StreamSecurity);
            await candidate.Sni.Should().BeEqualTo(source.Sni);
            await candidate.Fingerprint.Should().BeEqualTo(source.Fingerprint);
            await candidate.PublicKey.Should().BeEqualTo(source.PublicKey);
            await candidate.ShortId.Should().BeEqualTo(source.ShortId);
            await candidate.SpiderX.Should().BeEqualTo(source.SpiderX);
            await candidate.ProtoExtra.Should().BeEqualTo(source.ProtoExtra);
            await candidate.TransportExtra.Should().BeEqualTo(source.TransportExtra);
        }
    }

    [Test]
    public async Task LogicalIdentity_ShouldFollowTlsSniBeforeTransportHostOrPhysicalEndpoint()
    {
        foreach (var (_, profile, expected) in GoldenProfileCorpus.ModernProfiles())
        {
            var identity = ProfileIdentityResolver.ResolveServerName(profile);
            await identity.Should().BeEqualTo(expected);
        }
    }

    [Test]
    public async Task WebSocketMetadata_ShouldRemainLossConscious()
    {
        var (_, profile, _) = GoldenProfileCorpus.ModernProfiles().Single(x => x.Name == "vless-ws-tls-early-data");
        var path = profile.GetTransportExtra().Path;

        await TransportPathParameters.Get(path, "ed").Should().BeEqualTo("2560");
        await TransportPathParameters.Get(path, "eh").Should().BeEqualTo("Sec-WebSocket-Protocol");
        await TransportPathParameters.Remove(path, "ed", "eh").Should().BeEqualTo("/Path2WS?foo=a%2Bb");
    }

    [Test]
    public async Task XhttpFixture_ShouldValidateKnownRanges_AndPreserveUnknownExtension()
    {
        var (_, profile, _) = GoldenProfileCorpus.ModernProfiles().Single(x => x.Name == "vless-reality-xhttp");
        var violations = new ProfileInvariantRegistry().Validate(profile);
        await violations.Should().BeEmpty();
        await profile.GetTransportExtra().XhttpExtra.Should().Contain("futureExtension");
    }
}
