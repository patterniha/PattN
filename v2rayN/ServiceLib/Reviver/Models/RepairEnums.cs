namespace ServiceLib.Reviver.Models;

public enum ERepairFailureClass
{
    Unknown = 0,
    ParseInvalid,
    ProfileSemanticallyInvalid,
    CoreUnsupported,
    CoreConfigurationInvalid,
    CoreStartupFailure,
    DnsResolutionFailure,
    NoUsableAddressFamily,
    NetworkUnreachable,
    ConnectionRefused,
    ConnectionTimeout,
    TlsHandshakeFailure,
    TlsIdentityFailure,
    RealityHandshakeFailure,
    AlpnMismatch,
    TransportHandshakeFailure,
    WebSocketFailure,
    GrpcFailure,
    XhttpFailure,
    AuthenticationFailure,
    ProtocolFailure,
    ProxyEstablishedButNoEgress,
    DnsThroughTunnelFailure,
    UdpUnavailable,
    ApplicationProbeFailure,
    PerformanceDegraded,
    IntermittentFailure,
}

public enum ERepairMutationKind
{
    Canonicalize = 0,
    ReplaceEndpoint,
    ReplacePort,
    PreferAddressFamily,
    ChangeCore,
    RefreshResolvedAddress,
    ChangeFingerprint,
    ChangeAlpn,
    ApplyNetworkAdaptation,
}

public enum ERepairConfidence
{
    Equivalent = 0,
    LowRisk,
    EvidenceBacked,
    Speculative,
}

public enum ERepairCandidateState
{
    Planned = 0,
    Rejected,
    StaticValidated,
    RuntimeValidated,
    Failed,
    Promoted,
}
