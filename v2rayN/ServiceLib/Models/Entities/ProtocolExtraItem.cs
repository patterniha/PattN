namespace ServiceLib.Models.Entities;

public record ProtocolExtraItem
{
    public bool? Uot { get; init; }
    public string? CongestionControl { get; init; }

    // http outbound
    public string? HttpHeaders { get; init; }

    // vmess
    public string? AlterId { get; init; }
    public string? VmessSecurity { get; init; }

    // vless
    public string? Flow { get; init; }
    public string? VlessEncryption { get; init; }
    //public string? VisionSeed { get; init; }

    // shadowsocks
    //public string? PluginArgs { get; init; }
    public string? SsMethod { get; init; }

    // wireguard
    public string? WgPublicKey { get; init; }
    public string? WgPresharedKey { get; init; }
    public string? WgInterfaceAddress { get; init; }
    public string? WgReserved { get; init; }
    public int? WgMtu { get; init; }
    public string? WgDns { get; init; }

    // hysteria2
    public string? SalamanderPass { get; init; }
    public int? UpMbps { get; init; }
    public int? DownMbps { get; init; }
    public string? Ports { get; init; }
    public string? HopInterval { get; init; }
    // realm://<token>@<rendezvous-host>[:port]/<realm-name>?stun=<stun-host>[:port]&stun=<stun-host>[:port]...
    // example:
    // realm://public@realm.hy2.io/57f9be7c-2810-4f5b-8cb9-260bc84d6c90?stun=example.stun:3478&stun=example2.stun:3478
    public string? Hy2RealmUrl { get; init; }
    public string? GeckoMinPacketSize { get; init; }
    public string? GeckoMaxPacketSize { get; init; }

    // naiveproxy
    public int? InsecureConcurrency { get; init; }
    public bool? NaiveQuic { get; init; }

    // MASQUE
    public string? MasquePath { get; init; }
    public string? MasqueHeaders { get; init; }
    public string? WarpPublicKey { get; init; }
    public string? WarpPrivateKey { get; init; }
    public string? WarpAddress { get; init; }

    // group profile
    public string? GroupType { get; init; }
    public string? ChildItems { get; init; }
    public string? SubChildItems { get; init; }
    public string? Filter { get; init; }
    public EMultipleLoad? MultipleLoad { get; init; }

    // custom outbound
    public bool? IsSingboxEndpoint { get; init; }

    // PattN: aether (PattNG's aether* fields). Null always means the default, so a profile stores only what
    // differs from the defaults and follows a default that changes later.
    public string? AetherProtocol { get; init; }
    public string? AetherTransport { get; init; }
    public string? AetherMasqueSni { get; init; }
    public string? AetherScanMode { get; init; }
    public string? AetherObfuscation { get; init; }
    public string? AetherFingerprint { get; init; }
    public string? AetherIpVersion { get; init; }
    public string? AetherWiwOuter { get; init; }
    public string? AetherWiwInner { get; init; }
    public bool? AetherFragment { get; init; }
    public string? AetherFragmentSize { get; init; }
    public string? AetherFragmentDelay { get; init; }
    public bool? AetherEch { get; init; }
    public string? AetherEchDns { get; init; }
    public string? AetherEchDomain { get; init; }
    public string? AetherDns { get; init; }
    public string? AetherExitLoc { get; init; }
    public string? AetherExitNode { get; init; }
    public string? AetherPsiphon { get; init; }
    public string? AetherPsiphonMode { get; init; }
    public string? AetherPsiphonCdnIps { get; init; }
    public string? AetherPsiphonCdnSni { get; init; }
    public string? AetherPsiphonCdnSets { get; init; }
    public string? AetherPsiphonRegion { get; init; }
    public bool? AetherPsiphonBundledList { get; init; }
    public string? AetherTor { get; init; }
    public string? AetherTorBridges { get; init; }
    public string? AetherTorBridgeLines { get; init; }
    public string? AetherTorRelays { get; init; }
    public string? AetherCommand { get; init; }
}
