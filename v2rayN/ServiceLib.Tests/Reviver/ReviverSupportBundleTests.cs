using ServiceLib.Models.Entities;
using ServiceLib.Reviver.Models;
using ServiceLib.Reviver.Support;

namespace ServiceLib.Tests.Reviver;

public class ReviverSupportBundleTests
{
    [Test]
    public async Task Bundle_ShouldPreserveDiagnosticShapeWithoutLeakingProfileSecrets()
    {
        const string host = "private-front.example";
        const string ip = "203.0.113.77";
        const string password = "0b6d9d5e-21e6-4aa2-9f2f-a13de5ac45b8";
        const string publicKey = "VERY-PRIVATE-REALITY-PUBLIC-KEY";
        const string path = "/private/customer/path?token=super-secret";

        var profile = new ProfileItem
        {
            ConfigType = EConfigType.VLESS,
            CoreType = ECoreType.Xray,
            ConfigVersion = 4,
            IndexId = "profile-private-id",
            Subid = "subscription-private-id",
            IsSub = true,
            Remarks = "customer private remarks",
            Address = host,
            Port = 443,
            Password = password,
            Username = "private-user",
            Network = "ws",
            StreamSecurity = "tls",
            Sni = host,
            PublicKey = publicKey,
            ShortId = "private-short-id",
            Fingerprint = "fingerprint-secret.example",
            Alpn = "h2",
        };
        profile.SetTransportExtra(new TransportExtraItem
        {
            Host = host,
            Path = path,
            GrpcAuthority = host,
            GrpcServiceName = "private-grpc-service",
        });

        var session = new RepairSession { Original = ProfileSnapshot.Capture(profile) };
        var candidate = new RepairCandidate
        {
            SessionId = session.Id,
            Profile = profile,
            FailureClassAddressed = ERepairFailureClass.NetworkUnreachable,
            State = ERepairCandidateState.RuntimeValidated,
            Mutations =
            [
                new RepairMutation
                {
                    Kind = ERepairMutationKind.ReplaceEndpoint,
                    Field = "Address",
                    From = host,
                    To = ip,
                    Reason = "observed endpoint replacement",
                    Confidence = ERepairConfidence.EvidenceBacked,
                },
            ],
            Evidence =
            [
                new RepairEvidence
                {
                    Kind = "endpoint.probe",
                    Summary = "raw summary contains " + host,
                    Source = "https://" + host + "/api?token=secret",
                    Data = new Dictionary<string, string>
                    {
                        ["address"] = ip,
                        ["latencyMs"] = "12.5",
                        ["status"] = "secret.example/private",
                        ["opaque"] = "another-private-value",
                        ["customer-secret-key.example"] = "1",
                    },
                },
            ],
            Validation = new RepairValidationEvidence { Attempts = 3, Successes = 3, MedianLatencyMs = 12.5 },
        };

        var result = new RepairRunResult
        {
            Session = session,
            Diagnosis = new RepairDiagnosis
            {
                FailureClass = ERepairFailureClass.NetworkUnreachable,
                ResolvedAddresses = [ip],
                Evidence = candidate.Evidence,
            },
            PlannedCandidates = [candidate],
            ValidatedCandidates = [candidate],
            RecommendedCandidate = candidate,
        };

        var builder = new ReviverSupportBundleBuilder(Enumerable.Range(1, 32).Select(x => (byte)x).ToArray());
        var bundle = builder.Build(result);
        var json = builder.Serialize(result);

        await bundle.Profile.AddressToken.Should().BeEqualTo(bundle.Profile.SniToken);
        await bundle.Profile.AddressToken.Should().BeEqualTo(bundle.Profile.HttpHostToken);
        await bundle.Candidates[0].Mutations[0].From.Should().BeEqualTo(bundle.Profile.AddressToken);
        await bundle.Candidates[0].Mutations[0].To.Should().BeEqualTo(bundle.ResolvedAddressTokens[0]);
        await bundle.Evidence[0].Data["latencyMs"].Should().BeEqualTo("12.5");

        foreach (var secret in new[]
                 {
                     host, ip, password, publicKey, path, "profile-private-id", "subscription-private-id",
                     "customer private remarks", "private-user", "private-grpc-service",
                     "another-private-value", "token=secret", "fingerprint-secret.example",
                     "secret.example/private", "customer-secret-key.example",
                 })
        {
            await json.Contains(secret, StringComparison.Ordinal).Should().BeFalse();
        }

        await json.Contains("NetworkUnreachable", StringComparison.Ordinal).Should().BeTrue();
        await json.Contains("ReplaceEndpoint", StringComparison.Ordinal).Should().BeTrue();
        await json.Contains("tok:", StringComparison.Ordinal).Should().BeTrue();
    }

    [Test]
    public async Task Export_ShouldWriteOnlyRedactedBundle()
    {
        var profile = new ProfileItem
        {
            ConfigType = EConfigType.VMess,
            Address = "secret.example",
            Port = 443,
            Password = "93011d5e-80fd-4626-a0ed-3f329d2bf6d6",
            Network = "tcp",
            StreamSecurity = "tls",
            Remarks = "do-not-export",
        };
        var session = new RepairSession { Original = ProfileSnapshot.Capture(profile) };
        var result = new RepairRunResult
        {
            Session = session,
            Diagnosis = new RepairDiagnosis { FailureClass = ERepairFailureClass.ConnectionTimeout },
        };

        var root = Path.Combine(Path.GetTempPath(), "pattn-support-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var path = Path.Combine(root, "support.json");
            await new ReviverSupportBundleBuilder(new byte[32]).ExportAsync(path, result);
            var json = await File.ReadAllTextAsync(path);

            await json.Contains("secret.example", StringComparison.Ordinal).Should().BeFalse();
            await json.Contains(profile.Password, StringComparison.Ordinal).Should().BeFalse();
            await json.Contains(profile.Remarks, StringComparison.Ordinal).Should().BeFalse();
            await json.Contains("ConnectionTimeout", StringComparison.Ordinal).Should().BeTrue();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
