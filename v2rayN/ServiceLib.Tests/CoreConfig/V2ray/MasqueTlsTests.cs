namespace ServiceLib.Tests.CoreConfig.V2ray;

/// <summary>
/// PattN: a MASQUE outbound's TLS settings as the fork core uses them (PattNG CoreOutboundBuilder.toOutboundMasque): over
/// HTTP/3 no fingerprint and no cipherSuites, over HTTP/2 both; curvePreferences, session resumption and ECH either way.
/// </summary>
public class MasqueTlsTests
{
    private const string Suites = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
    private const string EchConfigList = "public.example.com+https://1.1.1.1/dns-query";

    private static TlsSettings4Ray TlsOf(string? alpn)
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = new ProfileItem
        {
            IndexId = "node-masque-1",
            ConfigType = EConfigType.MASQUE,
            CoreType = ECoreType.Xray,
            Remarks = "masque",
            Address = "example.com",
            Port = 443,
            Username = "user",
            Password = "pass",
            StreamSecurity = Global.StreamSecurity,
            Alpn = alpn!,
            Fingerprint = "unsafe",
            CipherSuites = Suites,
            CurvePreferences = "X25519",
            EnableSessionResumption = true,
            EchConfigList = EchConfigList,
            Subid = string.Empty,
        };
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();
        if (!result.Success)
        {
            throw new InvalidOperationException("config generation failed: " + result.Msg);
        }
        var generated = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
        return generated.outbounds.Single(outbound => outbound.protocol == "masque").streamSettings!.tlsSettings!;
    }

    [Test]
    [Arguments("h3")]
    [Arguments("h3,h2")]
    [Arguments(null)]
    public async Task OverHttp3_ShouldWriteNeitherTheFingerprintNorCipherSuites(string? alpn)
    {
        var tls = TlsOf(alpn);

        await tls.fingerprint.Should().BeNull();
        await tls.cipherSuites.Should().BeNull();
        await string.Join(",", tls.curvePreferences ?? []).Should().BeEqualTo("X25519");
        await tls.enableSessionResumption.Should().BeEqualTo(true);
        await tls.echConfigList.Should().BeEqualTo(EchConfigList);
    }

    [Test]
    [Arguments("h2")]
    [Arguments("h2,http/1.1")]
    public async Task OverHttp2_ShouldWriteTheFingerprintAndCipherSuites(string alpn)
    {
        var tls = TlsOf(alpn);

        await tls.fingerprint.Should().BeEqualTo("unsafe");
        await tls.cipherSuites.Should().BeEqualTo(Suites);
        await string.Join(",", tls.curvePreferences ?? []).Should().BeEqualTo("X25519");
        await tls.enableSessionResumption.Should().BeEqualTo(true);
        await tls.echConfigList.Should().BeEqualTo(EchConfigList);
    }
}
