namespace ServiceLib.Tests.Reviver;

/// <summary>
/// PattN-native semantic fixtures distilled from representative Xray example configurations.
/// These deliberately model only the outbound properties Reviver is allowed to reason about;
/// they are not copies of Xray JSON and therefore remain stable if Xray's surrounding schema changes.
/// </summary>
internal static class GoldenProfileCorpus
{
    public static IEnumerable<(string Name, ProfileItem Profile, string LogicalHost)> ModernProfiles()
    {
        yield return ("vless-reality-vision", RealityVision(), "www.example.com");
        yield return ("vless-reality-grpc", RealityGrpc(), "www.yahoo.com");
        yield return ("vless-reality-xhttp", RealityXhttp(), "front.example.com");
        yield return ("vless-ws-tls-early-data", WebSocketTlsEarlyData(), "ws.example.com");
        yield return ("hysteria2", Hysteria2(), "hy2.example.com");
    }

    // Distilled from Xray-examples/VLESS-TCP-XTLS-Vision-REALITY/config_client.jsonc.
    private static ProfileItem RealityVision()
    {
        var profile = BaseVless("origin.example.com", nameof(ETransport.raw), Global.StreamSecurityReality);
        profile.Sni = "www.example.com";
        profile.Fingerprint = "chrome";
        profile.PublicKey = "reality-public-key";
        profile.ShortId = "d49d578f280fd83a";
        profile.SpiderX = "/dns-query/";
        profile.SetProtocolExtra(new ProtocolExtraItem
        {
            Flow = "xtls-rprx-vision",
            VlessEncryption = Global.None,
        });
        return profile;
    }

    // Distilled from Xray-examples/VLESS-gRPC-REALITY/config_client.jsonc.
    private static ProfileItem RealityGrpc()
    {
        var profile = BaseVless("1.2.3.4", nameof(ETransport.grpc), Global.StreamSecurityReality);
        profile.Sni = "www.yahoo.com";
        profile.Fingerprint = "chrome";
        profile.PublicKey = "OBR2JYROQB8odK5glVW_KLnsWl3UZ-voyGq_9ihQgTI";
        profile.ShortId = "d49d578f280fd83a";
        profile.SpiderX = string.Empty;
        profile.SetProtocolExtra(new ProtocolExtraItem { Flow = string.Empty, VlessEncryption = Global.None });
        profile.SetTransportExtra(new TransportExtraItem
        {
            GrpcServiceName = "edge-service",
            GrpcAuthority = "grpc.example.com",
            GrpcMode = "gun",
        });
        return profile;
    }

    // Distilled from Xray-examples/VLESS-XHTTP-Reality/minimal-steal_others/client.jsonc.
    private static ProfileItem RealityXhttp()
    {
        var profile = BaseVless("edge.example.com", nameof(ETransport.xhttp), Global.StreamSecurityReality);
        profile.Sni = "front.example.com";
        profile.Fingerprint = "chrome";
        profile.PublicKey = "xhttp-public-key";
        profile.ShortId = "a1b2c3d4";
        profile.SpiderX = "/somepath";
        profile.SetProtocolExtra(new ProtocolExtraItem { Flow = string.Empty, VlessEncryption = Global.None });
        profile.SetTransportExtra(new TransportExtraItem
        {
            Host = "front.example.com",
            Path = "/yourpath",
            XhttpMode = "auto",
            XhttpExtra = """{"xPaddingBytes":"100-1000","xmux":{"maxConcurrency":"4-16"},"futureExtension":{"keep":true}}""",
        });
        return profile;
    }

    // Distilled from Xray-examples/VLESS-WSS-Nginx/client.jsonc.
    private static ProfileItem WebSocketTlsEarlyData()
    {
        var profile = BaseVless("203.0.113.20", nameof(ETransport.ws), Global.StreamSecurity);
        profile.Sni = "ws.example.com";
        profile.Fingerprint = "chrome";
        profile.SetProtocolExtra(new ProtocolExtraItem { Flow = string.Empty, VlessEncryption = Global.None });
        profile.SetTransportExtra(new TransportExtraItem
        {
            Host = "ws.example.com",
            Path = "/Path2WS?foo=a%2Bb&ed=2560&eh=Sec-WebSocket-Protocol",
        });
        return profile;
    }

    // Distilled from Xray-examples/Hysteria2/client.jsonc into PattN's Hysteria2 model.
    private static ProfileItem Hysteria2()
    {
        var profile = new ProfileItem
        {
            ConfigType = EConfigType.Hysteria2,
            CoreType = ECoreType.Xray,
            Address = "hy2.example.com",
            Port = 11451,
            Password = "114514",
            Network = string.Empty,
            StreamSecurity = Global.StreamSecurity,
            Sni = "hy2.example.com",
            Remarks = "golden-hysteria2",
        };
        profile.SetProtocolExtra(new ProtocolExtraItem
        {
            SalamanderPass = "114514",
            UpMbps = 30,
            DownMbps = 100,
        });
        profile.SetTransportExtra(new TransportExtraItem());
        return profile;
    }

    private static ProfileItem BaseVless(string address, string network, string security)
    {
        var profile = new ProfileItem
        {
            ConfigType = EConfigType.VLESS,
            CoreType = ECoreType.Xray,
            Address = address,
            Port = 443,
            Password = "11111111-1111-4111-8111-111111111111",
            Network = network,
            StreamSecurity = security,
            Remarks = "golden-vless",
        };
        profile.SetProtocolExtra(new ProtocolExtraItem { Flow = string.Empty, VlessEncryption = Global.None });
        profile.SetTransportExtra(new TransportExtraItem());
        return profile;
    }
}
