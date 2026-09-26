using ServiceLib.Discovery.Protocol;

namespace ServiceLib.Tests.Reviver;

public partial class DiscoveryRpcModelTests
{
    [Test]
    public async Task Request_ShouldSerializeToEngineContract()
    {
        var request = new DiscoveryRpcRequest
        {
            Id = "abc",
            Method = "targets.inspect",
            Params = new { targets = new[] { "10.0.0.0/8" } },
        };
        var json = JsonSerializer.Serialize(request);
        await json.Contains("\"v\":1").Should().BeTrue();
        await json.Contains("\"id\":\"abc\"").Should().BeTrue();
        await json.Contains("\"method\":\"targets.inspect\"").Should().BeTrue();
    }

    [Test]
    public async Task TargetInspection_ShouldKeepAddressCountAsArbitraryPrecisionText()
    {
        var parsed = JsonSerializer.Deserialize<DiscoveryTargetInspection>("""{"ranges":["2001:db8::/64"],"invalid":[],"addressCount":"18446744073709551616"}""");
        await parsed.Should().NotBeNull();
        await parsed!.AddressCount.Should().BeEqualTo("18446744073709551616");
    }

    [Test]
    public async Task TcpStreamDtos_ShouldPreserveArbitraryPrecisionCountsAndResultEvidence()
    {
        var started = JsonSerializer.Deserialize<DiscoveryTcpScanStarted>(
            """{"scanId":"s","addressCount":"18446744073709551616","endpointCount":"36893488147419103232","invalid":[]}""");
        var result = JsonSerializer.Deserialize<DiscoveryTcpScanResult>(
            """{"address":"203.0.113.10","port":443,"latencyMs":12.5}""");

        await started.Should().NotBeNull();
        await started!.AddressCount.Should().BeEqualTo("18446744073709551616");
        await started.EndpointCount.Should().BeEqualTo("36893488147419103232");
        await result.Should().NotBeNull();
        await result!.Address.Should().BeEqualTo("203.0.113.10");
        await result.LatencyMs.Should().BeEqualTo(12.5);
    }

    [Test]
    public async Task EndpointProbeRequest_ShouldSerializePhysicalAndLogicalTargetsSeparately()
    {
        var request = new DiscoveryEndpointProbeRequest
        {
            Addresses = ["203.0.113.10"],
            Port = 443,
            ServerName = "logical.example",
            HttpHost = "logical.example",
            Scheme = "https",
            Attempts = 3,
            MinSuccesses = 2,
        };
        var json = JsonSerializer.Serialize(request);
        await json.Contains("\"addresses\":[\"203.0.113.10\"]").Should().BeTrue();
        await json.Contains("\"serverName\":\"logical.example\"").Should().BeTrue();
        await json.Contains("\"httpHost\":\"logical.example\"").Should().BeTrue();
    }
}

public partial class DiscoveryRpcModelTests
{
    [Test]
    public async Task TargetNormalizeRequest_ShouldKeepSourceSemanticsSeparateFromRanges()
    {
        var request = new DiscoveryTargetNormalizeRequest
        {
            Source = new DiscoveryTargetSourceMetadata
            {
                Id = "iran-geo",
                Kind = "country",
                Scope = "country-geolocation",
                ScopeValue = "IR",
                Version = "2026-09",
            },
            Targets = ["192.0.2.0/25", "192.0.2.128/25"],
            IPv4 = true,
            IPv6 = false,
        };

        var json = JsonSerializer.Serialize(request);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;

        await root.GetProperty("source").GetProperty("scope").GetString().Should().BeEqualTo("country-geolocation");
        await root.GetProperty("source").GetProperty("scopeValue").GetString().Should().BeEqualTo("IR");
        await root.GetProperty("targets").GetArrayLength().Should().BeEqualTo(2);
        await root.GetProperty("ipv4").GetBoolean().Should().BeTrue();
        await root.GetProperty("ipv6").GetBoolean().Should().BeFalse();
    }
}

public partial class DiscoveryRpcModelTests
{
    [Test]
    public async Task ResolverDiscoveryDtos_ShouldKeepCheapDiscoveryEvidenceSeparateFromQualification()
    {
        var result = JsonSerializer.Deserialize<DiscoveryResolverResult>(
            """{"address":"203.0.113.53","port":53,"latencyMs":18.25,"rcode":0,"recursionAvailable":true,"truncated":false,"answerIps":["93.184.216.34"]}""");

        await result.Should().NotBeNull();
        await result!.Address.Should().BeEqualTo("203.0.113.53");
        await result.RecursionAvailable.Should().BeTrue();
        await result.RCode.Should().BeEqualTo(0);
        await result.AnswerIps.Count.Should().BeEqualTo(1);
    }
}

public partial class DiscoveryRpcModelTests
{
    [Test]
    public async Task ResolverQualificationDto_ShouldKeepObservationAndVerdictEvidence()
    {
        var result = JsonSerializer.Deserialize<DiscoveryResolverQualification>(
            """{"address":"203.0.113.53","port":53,"domain":"example.com","udp":{"transport":"udp","responded":true,"latencyMs":10.5,"rcode":0,"recursionAvailable":true,"authoritative":false,"truncated":false,"answerIps":["93.184.216.34"]},"tcp":{"transport":"tcp","responded":true,"latencyMs":15.0,"rcode":0,"recursionAvailable":true,"authoritative":false,"truncated":false,"answerIps":["93.184.216.34"]},"responded":true,"recursionAvailable":true,"preferredTransport":"udp","transportAgreement":true,"privateAnswerObserved":false,"referenceCompared":true,"referenceDivergence":false,"hijackChecked":true,"hijackDetected":false,"status":"usable"}""");

        await result.Should().NotBeNull();
        await result!.Status.Should().BeEqualTo("usable");
        await result.TransportAgreement.Should().BeTrue();
        await result.ReferenceCompared.Should().BeTrue();
        await result.ReferenceDivergence.Should().BeFalse();
        await result.HijackDetected.Should().BeFalse();
        await result.Udp.Should().NotBeNull();
        await result.Tcp.Should().NotBeNull();
    }
}
