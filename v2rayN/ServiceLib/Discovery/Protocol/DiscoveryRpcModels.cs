namespace ServiceLib.Discovery.Protocol;

public sealed record DiscoveryRpcRequest
{
    [JsonPropertyName("v")]
    public int Version { get; init; } = 1;

    [JsonPropertyName("id")]
    public required string Id { get; init; }

    [JsonPropertyName("method")]
    public required string Method { get; init; }

    [JsonPropertyName("params")]
    public object? Params { get; init; }
}

public sealed record DiscoveryRpcError
{
    [JsonPropertyName("code")]
    public string Code { get; init; } = string.Empty;

    [JsonPropertyName("message")]
    public string Message { get; init; } = string.Empty;
}

public sealed record DiscoveryRpcResponse
{
    [JsonPropertyName("v")]
    public int Version { get; init; }

    [JsonPropertyName("id")]
    public string Id { get; init; } = string.Empty;

    [JsonPropertyName("event")]
    public string Event { get; init; } = string.Empty;

    [JsonPropertyName("data")]
    public JsonElement Data { get; init; }

    [JsonPropertyName("error")]
    public DiscoveryRpcError? Error { get; init; }
}

public sealed record DiscoveryEngineVersion
{
    [JsonPropertyName("engine")]
    public string Engine { get; init; } = string.Empty;

    [JsonPropertyName("version")]
    public string Version { get; init; } = string.Empty;
}

public sealed record DiscoveryCapabilities
{
    [JsonPropertyName("protocolVersion")]
    public int ProtocolVersion { get; init; }

    [JsonPropertyName("methods")]
    public IReadOnlyList<string> Methods { get; init; } = [];

    [JsonPropertyName("nativeScanner")]
    public bool NativeScanner { get; init; }
}

public sealed record DiscoveryTargetInspection
{
    [JsonPropertyName("ranges")]
    public IReadOnlyList<string> Ranges { get; init; } = [];

    [JsonPropertyName("invalid")]
    public IReadOnlyList<string> Invalid { get; init; } = [];

    // String by design: IPv6 target sets such as /64 exceed UInt64 in the general case.
    [JsonPropertyName("addressCount")]
    public string AddressCount { get; init; } = "0";
}

public sealed class DiscoveryRpcException(string code, string message) : Exception($"{code}: {message}")
{
    public string Code { get; } = code;
}

public sealed record DiscoveryEndpointProbeRequest
{
    [JsonPropertyName("addresses")]
    public IReadOnlyList<string> Addresses { get; init; } = [];

    [JsonPropertyName("port")]
    public int Port { get; init; }

    [JsonPropertyName("serverName")]
    public string? ServerName { get; init; }

    [JsonPropertyName("httpHost")]
    public string? HttpHost { get; init; }

    [JsonPropertyName("scheme")]
    public string Scheme { get; init; } = "https";

    [JsonPropertyName("path")]
    public string Path { get; init; } = "/";

    [JsonPropertyName("method")]
    public string Method { get; init; } = "HEAD";

    [JsonPropertyName("timeoutMs")]
    public int TimeoutMs { get; init; } = 5000;

    [JsonPropertyName("attempts")]
    public int Attempts { get; init; } = 3;

    [JsonPropertyName("minSuccesses")]
    public int MinSuccesses { get; init; } = 2;

    [JsonPropertyName("insecureSkipVerify")]
    public bool InsecureSkipVerify { get; init; }
}

public sealed record DiscoveryEdgeObservation
{
    [JsonPropertyName("provider")]
    public string Provider { get; init; } = string.Empty;

    [JsonPropertyName("pop")]
    public string Pop { get; init; } = string.Empty;

    [JsonPropertyName("evidence")]
    public string Evidence { get; init; } = string.Empty;
}

public sealed record DiscoveryEndpointProbeResult
{
    [JsonPropertyName("address")]
    public string Address { get; init; } = string.Empty;

    [JsonPropertyName("port")]
    public int Port { get; init; }

    [JsonPropertyName("statusCode")]
    public int StatusCode { get; init; }

    [JsonPropertyName("attempts")]
    public int Attempts { get; init; }

    [JsonPropertyName("successes")]
    public int Successes { get; init; }

    [JsonPropertyName("consecutiveSuccesses")]
    public int ConsecutiveSuccesses { get; init; }

    [JsonPropertyName("reliability")]
    public double Reliability { get; init; }

    [JsonPropertyName("medianLatencyMs")]
    public double MedianLatencyMs { get; init; }

    [JsonPropertyName("qualified")]
    public bool Qualified { get; init; }

    [JsonPropertyName("edge")]
    public DiscoveryEdgeObservation Edge { get; init; } = new();

    [JsonPropertyName("errors")]
    public IReadOnlyList<string> Errors { get; init; } = [];
}

public sealed record DiscoveryEndpointProbeResponse
{
    [JsonPropertyName("results")]
    public IReadOnlyList<DiscoveryEndpointProbeResult> Results { get; init; } = [];

    [JsonPropertyName("invalid")]
    public IReadOnlyList<string> Invalid { get; init; } = [];
}

public sealed record DiscoveryTcpScanRequest
{
    [JsonPropertyName("targets")]
    public IReadOnlyList<string> Targets { get; init; } = [];

    [JsonPropertyName("ports")]
    public IReadOnlyList<int> Ports { get; init; } = [];

    [JsonPropertyName("timeoutMs")]
    public int TimeoutMs { get; init; } = 1500;

    [JsonPropertyName("concurrency")]
    public int Concurrency { get; init; } = 256;

    [JsonPropertyName("maxTargets")]
    public long MaxTargets { get; init; } = 100_000;
}

public sealed record DiscoveryTcpScanStarted
{
    [JsonPropertyName("scanId")]
    public string ScanId { get; init; } = string.Empty;

    [JsonPropertyName("addressCount")]
    public string AddressCount { get; init; } = "0";

    [JsonPropertyName("endpointCount")]
    public string EndpointCount { get; init; } = "0";

    [JsonPropertyName("invalid")]
    public IReadOnlyList<string> Invalid { get; init; } = [];
}

public sealed record DiscoveryTcpScanResult
{
    [JsonPropertyName("address")]
    public string Address { get; init; } = string.Empty;

    [JsonPropertyName("port")]
    public int Port { get; init; }

    [JsonPropertyName("latencyMs")]
    public double LatencyMs { get; init; }
}

public sealed record DiscoveryTcpScanProgress
{
    [JsonPropertyName("addressesDispatched")]
    public long AddressesDispatched { get; init; }

    [JsonPropertyName("endpointsProcessed")]
    public long EndpointsProcessed { get; init; }

    [JsonPropertyName("openEndpoints")]
    public long OpenEndpoints { get; init; }
}

public sealed record DiscoveryTcpScanSummary
{
    [JsonPropertyName("scanId")]
    public string ScanId { get; init; } = string.Empty;

    [JsonPropertyName("addressesDispatched")]
    public long AddressesDispatched { get; init; }

    [JsonPropertyName("endpointsProcessed")]
    public long EndpointsProcessed { get; init; }

    [JsonPropertyName("openEndpoints")]
    public long OpenEndpoints { get; init; }
}

public sealed record DiscoveryTcpScanEvent
{
    public required string Event { get; init; }
    public DiscoveryTcpScanStarted? Started { get; init; }
    public DiscoveryTcpScanResult? Result { get; init; }
    public DiscoveryTcpScanProgress? Progress { get; init; }
    public DiscoveryTcpScanSummary? Summary { get; init; }
}

public sealed record DiscoveryScanControl
{
    [JsonPropertyName("scanId")]
    public string ScanId { get; init; } = string.Empty;

    [JsonPropertyName("state")]
    public string State { get; init; } = string.Empty;
}

public sealed record DiscoveryTargetSourceMetadata
{
    [JsonPropertyName("id")]
    public string Id { get; init; } = string.Empty;

    [JsonPropertyName("kind")]
    public string Kind { get; init; } = "user";

    [JsonPropertyName("scope")]
    public string Scope { get; init; } = "unspecified";

    [JsonPropertyName("scopeValue")]
    public string ScopeValue { get; init; } = string.Empty;

    [JsonPropertyName("version")]
    public string Version { get; init; } = string.Empty;

    [JsonPropertyName("updatedAt")]
    public DateTimeOffset? UpdatedAt { get; init; }

    [JsonPropertyName("attributes")]
    public IReadOnlyDictionary<string, string> Attributes { get; init; } = new Dictionary<string, string>();
}

public sealed record DiscoveryTargetNormalizeRequest
{
    [JsonPropertyName("source")]
    public required DiscoveryTargetSourceMetadata Source { get; init; }

    [JsonPropertyName("targets")]
    public IReadOnlyList<string> Targets { get; init; } = [];

    [JsonPropertyName("ipv4")]
    public bool? IPv4 { get; init; }

    [JsonPropertyName("ipv6")]
    public bool? IPv6 { get; init; }
}

public sealed record DiscoveryTargetNormalizeResponse
{
    [JsonPropertyName("source")]
    public DiscoveryTargetSourceMetadata Source { get; init; } = new();

    [JsonPropertyName("ranges")]
    public IReadOnlyList<string> Ranges { get; init; } = [];

    [JsonPropertyName("invalid")]
    public IReadOnlyList<string> Invalid { get; init; } = [];

    [JsonPropertyName("addressCount")]
    public string AddressCount { get; init; } = "0";
}

public sealed record DiscoveryResolverRequest
{
    [JsonPropertyName("targets")]
    public IReadOnlyList<string> Targets { get; init; } = [];

    [JsonPropertyName("port")]
    public int Port { get; init; } = 53;

    [JsonPropertyName("domain")]
    public string Domain { get; init; } = "example.com";

    [JsonPropertyName("timeoutMs")]
    public int TimeoutMs { get; init; } = 1200;

    [JsonPropertyName("concurrency")]
    public int Concurrency { get; init; } = 128;

    [JsonPropertyName("maxTargets")]
    public long MaxTargets { get; init; } = 100_000;
}

public sealed record DiscoveryResolverStarted
{
    [JsonPropertyName("scanId")]
    public string ScanId { get; init; } = string.Empty;

    [JsonPropertyName("addressCount")]
    public string AddressCount { get; init; } = "0";

    [JsonPropertyName("invalid")]
    public IReadOnlyList<string> Invalid { get; init; } = [];

    [JsonPropertyName("port")]
    public int Port { get; init; }

    [JsonPropertyName("domain")]
    public string Domain { get; init; } = string.Empty;
}

public sealed record DiscoveryResolverResult
{
    [JsonPropertyName("address")]
    public string Address { get; init; } = string.Empty;

    [JsonPropertyName("port")]
    public int Port { get; init; }

    [JsonPropertyName("latencyMs")]
    public double LatencyMs { get; init; }

    [JsonPropertyName("rcode")]
    public int RCode { get; init; }

    [JsonPropertyName("recursionAvailable")]
    public bool RecursionAvailable { get; init; }

    [JsonPropertyName("truncated")]
    public bool Truncated { get; init; }

    [JsonPropertyName("answerIps")]
    public IReadOnlyList<string> AnswerIps { get; init; } = [];
}

public sealed record DiscoveryResolverProgress
{
    [JsonPropertyName("addressesDispatched")]
    public long AddressesDispatched { get; init; }

    [JsonPropertyName("addressesProcessed")]
    public long AddressesProcessed { get; init; }

    [JsonPropertyName("candidates")]
    public long Candidates { get; init; }
}

public sealed record DiscoveryResolverSummary
{
    [JsonPropertyName("scanId")]
    public string ScanId { get; init; } = string.Empty;

    [JsonPropertyName("addressesDispatched")]
    public long AddressesDispatched { get; init; }

    [JsonPropertyName("addressesProcessed")]
    public long AddressesProcessed { get; init; }

    [JsonPropertyName("candidates")]
    public long Candidates { get; init; }
}

public sealed record DiscoveryResolverEvent
{
    public required string Event { get; init; }
    public DiscoveryResolverStarted? Started { get; init; }
    public DiscoveryResolverResult? Result { get; init; }
    public DiscoveryResolverProgress? Progress { get; init; }
    public DiscoveryResolverSummary? Summary { get; init; }
}

public sealed record DiscoveryResolverQualificationRequest
{
    [JsonPropertyName("address")]
    public string Address { get; init; } = string.Empty;

    [JsonPropertyName("port")]
    public int Port { get; init; } = 53;

    [JsonPropertyName("domain")]
    public string Domain { get; init; } = "example.com";

    [JsonPropertyName("timeoutMs")]
    public int TimeoutMs { get; init; } = 2000;

    [JsonPropertyName("depthAttempts")]
    public int DepthAttempts { get; init; } = 3;

    [JsonPropertyName("depthMinSuccesses")]
    public int DepthMinSuccesses { get; init; } = 2;

    [JsonPropertyName("referenceAnswers")]
    public IReadOnlyList<string> ReferenceAnswers { get; init; } = [];

    [JsonPropertyName("checkUdp")]
    public bool CheckUdp { get; init; } = true;

    [JsonPropertyName("checkTcp")]
    public bool CheckTcp { get; init; } = true;

    [JsonPropertyName("checkHijack")]
    public bool CheckHijack { get; init; } = true;

    [JsonPropertyName("checkDnssec")]
    public bool CheckDnssec { get; init; }

    [JsonPropertyName("checkDepth")]
    public bool CheckDepth { get; init; }

    [JsonPropertyName("serverName")]
    public string ServerName { get; init; } = string.Empty;

    [JsonPropertyName("dotPort")]
    public int DotPort { get; init; } = 853;

    [JsonPropertyName("dohUrl")]
    public string DohUrl { get; init; } = string.Empty;
}

public sealed record DiscoveryDnsTransportEvidence
{
    [JsonPropertyName("transport")]
    public string Transport { get; init; } = string.Empty;

    [JsonPropertyName("responded")]
    public bool Responded { get; init; }

    [JsonPropertyName("latencyMs")]
    public double LatencyMs { get; init; }

    [JsonPropertyName("rcode")]
    public int RCode { get; init; }

    [JsonPropertyName("recursionAvailable")]
    public bool RecursionAvailable { get; init; }

    [JsonPropertyName("authoritative")]
    public bool Authoritative { get; init; }

    [JsonPropertyName("truncated")]
    public bool Truncated { get; init; }

    [JsonPropertyName("answerIps")]
    public IReadOnlyList<string> AnswerIps { get; init; } = [];

    [JsonPropertyName("error")]
    public string Error { get; init; } = string.Empty;
}

public sealed record DiscoveryResolverQualification
{
    [JsonPropertyName("address")]
    public string Address { get; init; } = string.Empty;

    [JsonPropertyName("port")]
    public int Port { get; init; }

    [JsonPropertyName("domain")]
    public string Domain { get; init; } = string.Empty;

    [JsonPropertyName("udp")]
    public DiscoveryDnsTransportEvidence? Udp { get; init; }

    [JsonPropertyName("tcp")]
    public DiscoveryDnsTransportEvidence? Tcp { get; init; }

    [JsonPropertyName("responded")]
    public bool Responded { get; init; }

    [JsonPropertyName("recursionAvailable")]
    public bool RecursionAvailable { get; init; }

    [JsonPropertyName("preferredTransport")]
    public string PreferredTransport { get; init; } = string.Empty;

    [JsonPropertyName("transportAgreement")]
    public bool? TransportAgreement { get; init; }

    [JsonPropertyName("privateAnswerObserved")]
    public bool PrivateAnswerObserved { get; init; }

    [JsonPropertyName("referenceCompared")]
    public bool ReferenceCompared { get; init; }

    [JsonPropertyName("referenceDivergence")]
    public bool ReferenceDivergence { get; init; }

    [JsonPropertyName("dnssecReferenceCompared")]
    public bool DnssecReferenceCompared { get; init; }

    [JsonPropertyName("dnssecReferenceDivergence")]
    public bool DnssecReferenceDivergence { get; init; }

    [JsonPropertyName("dnssecReferenceStatus")]
    public string DnssecReferenceStatus { get; init; } = string.Empty;

    [JsonPropertyName("hijackChecked")]
    public bool HijackChecked { get; init; }

    [JsonPropertyName("hijackDetected")]
    public bool HijackDetected { get; init; }

    [JsonPropertyName("hijackEvidence")]
    public DiscoveryDnsTransportEvidence? HijackEvidence { get; init; }

    [JsonPropertyName("depth")]
    public DiscoveryResolverProfileResult? Depth { get; init; }

    [JsonPropertyName("status")]
    public string Status { get; init; } = string.Empty;
}


public sealed record DiscoveryDeepDnsRequest
{
    [JsonPropertyName("domain")]
    public string Domain { get; init; } = string.Empty;

    [JsonPropertyName("queryType")]
    public int QueryType { get; init; } = 1;

    [JsonPropertyName("timeoutMs")]
    public int TimeoutMs { get; init; } = 2000;

    [JsonPropertyName("maxHops")]
    public int MaxHops { get; init; } = 32;

    [JsonPropertyName("maxNsDepth")]
    public int MaxNsDepth { get; init; } = 4;

    [JsonPropertyName("rootServers")]
    public IReadOnlyList<string> RootServers { get; init; } = [];
}

public sealed record DiscoveryDnsRecord
{
    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("type")]
    public int Type { get; init; }

    [JsonPropertyName("ttl")]
    public long Ttl { get; init; }

    [JsonPropertyName("address")]
    public string Address { get; init; } = string.Empty;

    [JsonPropertyName("target")]
    public string Target { get; init; } = string.Empty;
}

public sealed record DiscoveryDnsAuthorityEndpoint
{
    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("addresses")]
    public IReadOnlyList<string> Addresses { get; init; } = [];

    [JsonPropertyName("error")]
    public string Error { get; init; } = string.Empty;
}

public sealed record DiscoveryDnsAliasStep
{
    [JsonPropertyName("queryName")]
    public string QueryName { get; init; } = string.Empty;

    [JsonPropertyName("owner")]
    public string Owner { get; init; } = string.Empty;

    [JsonPropertyName("target")]
    public string Target { get; init; } = string.Empty;

    [JsonPropertyName("resultName")]
    public string ResultName { get; init; } = string.Empty;

    [JsonPropertyName("type")]
    public int Type { get; init; }

    [JsonPropertyName("synthesized")]
    public bool Synthesized { get; init; }

    [JsonPropertyName("authoritativeZone")]
    public string AuthoritativeZone { get; init; } = string.Empty;
}

public sealed record DiscoveryDnsTraceHop
{
    [JsonPropertyName("nameServer")]
    public string NameServer { get; init; } = string.Empty;

    [JsonPropertyName("queryName")]
    public string QueryName { get; init; } = string.Empty;

    [JsonPropertyName("queryType")]
    public int QueryType { get; init; }

    [JsonPropertyName("transport")]
    public string Transport { get; init; } = string.Empty;

    [JsonPropertyName("latencyMs")]
    public double LatencyMs { get; init; }

    [JsonPropertyName("rcode")]
    public int RCode { get; init; }

    [JsonPropertyName("authoritative")]
    public bool Authoritative { get; init; }

    [JsonPropertyName("truncated")]
    public bool Truncated { get; init; }

    [JsonPropertyName("answers")]
    public IReadOnlyList<DiscoveryDnsRecord> Answers { get; init; } = [];

    [JsonPropertyName("authorities")]
    public IReadOnlyList<DiscoveryDnsRecord> Authorities { get; init; } = [];

    [JsonPropertyName("additionals")]
    public IReadOnlyList<DiscoveryDnsRecord> Additionals { get; init; } = [];
}

public sealed record DiscoveryDnsTraceResult
{
    [JsonPropertyName("domain")]
    public string Domain { get; init; } = string.Empty;

    [JsonPropertyName("queryType")]
    public int QueryType { get; init; }

    [JsonPropertyName("hops")]
    public IReadOnlyList<DiscoveryDnsTraceHop> Hops { get; init; } = [];

    [JsonPropertyName("delegation")]
    public IReadOnlyList<DiscoveryDnsAuthorityEndpoint> Delegation { get; init; } = [];

    [JsonPropertyName("aliasChain")]
    public IReadOnlyList<DiscoveryDnsAliasStep> AliasChain { get; init; } = [];

    [JsonPropertyName("finalAnswers")]
    public IReadOnlyList<DiscoveryDnsRecord> FinalAnswers { get; init; } = [];

    [JsonPropertyName("complete")]
    public bool Complete { get; init; }

    [JsonPropertyName("terminalRcode")]
    public int TerminalRCode { get; init; }

    [JsonPropertyName("terminalZone")]
    public string TerminalZone { get; init; } = string.Empty;

    [JsonPropertyName("errorCode")]
    public string ErrorCode { get; init; } = string.Empty;

    [JsonPropertyName("error")]
    public string Error { get; init; } = string.Empty;
}

public sealed record DiscoveryDnsAuthorityObservation
{
    [JsonPropertyName("authority")]
    public string Authority { get; init; } = string.Empty;

    [JsonPropertyName("address")]
    public string Address { get; init; } = string.Empty;

    [JsonPropertyName("transport")]
    public string Transport { get; init; } = string.Empty;

    [JsonPropertyName("latencyMs")]
    public double LatencyMs { get; init; }

    [JsonPropertyName("rcode")]
    public int RCode { get; init; }

    [JsonPropertyName("authoritative")]
    public bool Authoritative { get; init; }

    [JsonPropertyName("truncated")]
    public bool Truncated { get; init; }

    [JsonPropertyName("signature")]
    public string Signature { get; init; } = string.Empty;

    [JsonPropertyName("answers")]
    public IReadOnlyList<DiscoveryDnsRecord> Answers { get; init; } = [];

    [JsonPropertyName("error")]
    public string Error { get; init; } = string.Empty;
}

public sealed record DiscoveryDnsAgreementGroup
{
    [JsonPropertyName("signature")]
    public string Signature { get; init; } = string.Empty;

    [JsonPropertyName("count")]
    public int Count { get; init; }

    [JsonPropertyName("endpoints")]
    public IReadOnlyList<string> Endpoints { get; init; } = [];
}

public sealed record DiscoveryDnsAuthorityComparison
{
    [JsonPropertyName("domain")]
    public string Domain { get; init; } = string.Empty;

    [JsonPropertyName("queryType")]
    public int QueryType { get; init; }

    [JsonPropertyName("delegation")]
    public IReadOnlyList<DiscoveryDnsAuthorityEndpoint> Delegation { get; init; } = [];

    [JsonPropertyName("observations")]
    public IReadOnlyList<DiscoveryDnsAuthorityObservation> Observations { get; init; } = [];

    [JsonPropertyName("groups")]
    public IReadOnlyList<DiscoveryDnsAgreementGroup> Groups { get; init; } = [];

    [JsonPropertyName("responding")]
    public int Responding { get; init; }

    [JsonPropertyName("unanimous")]
    public bool Unanimous { get; init; }

    [JsonPropertyName("divergent")]
    public bool Divergent { get; init; }

    [JsonPropertyName("majorityCount")]
    public int MajorityCount { get; init; }

    [JsonPropertyName("majoritySignature")]
    public string MajoritySignature { get; init; } = string.Empty;

    [JsonPropertyName("errorCode")]
    public string ErrorCode { get; init; } = string.Empty;

    [JsonPropertyName("error")]
    public string Error { get; init; } = string.Empty;
}


public sealed record DiscoveryDnsResolverEndpoint
{
    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("address")]
    public string Address { get; init; } = string.Empty;

    [JsonPropertyName("port")]
    public int Port { get; init; } = 53;

    [JsonPropertyName("catalogId")]
    public string CatalogId { get; init; } = string.Empty;

    [JsonPropertyName("policy")]
    public string Policy { get; init; } = string.Empty;

    [JsonPropertyName("serverName")]
    public string ServerName { get; init; } = string.Empty;

    [JsonPropertyName("dotPort")]
    public int DotPort { get; init; } = 853;

    [JsonPropertyName("dohUrl")]
    public string DohUrl { get; init; } = string.Empty;
}

public sealed record DiscoveryDnsConsensusRequest
{
    [JsonPropertyName("domain")]
    public string Domain { get; init; } = string.Empty;

    [JsonPropertyName("queryType")]
    public int QueryType { get; init; } = 1;

    [JsonPropertyName("timeoutMs")]
    public int TimeoutMs { get; init; } = 2000;

    [JsonPropertyName("depthAttempts")]
    public int DepthAttempts { get; init; } = 3;

    [JsonPropertyName("depthMinSuccesses")]
    public int DepthMinSuccesses { get; init; } = 2;

    [JsonPropertyName("maxHops")]
    public int MaxHops { get; init; } = 32;

    [JsonPropertyName("maxNsDepth")]
    public int MaxNsDepth { get; init; } = 4;

    [JsonPropertyName("rootServers")]
    public IReadOnlyList<string> RootServers { get; init; } = [];

    [JsonPropertyName("useDefaultTrustedResolvers")]
    public bool UseDefaultTrustedResolvers { get; init; } = true;

    [JsonPropertyName("trustedResolvers")]
    public IReadOnlyList<DiscoveryDnsResolverEndpoint> TrustedResolvers { get; init; } = [];

    [JsonPropertyName("candidateResolvers")]
    public IReadOnlyList<DiscoveryDnsResolverEndpoint> CandidateResolvers { get; init; } = [];

    [JsonPropertyName("checkDnssec")]
    public bool CheckDnssec { get; init; }

    [JsonPropertyName("checkDepth")]
    public bool CheckDepth { get; init; }
}

public sealed record DiscoveryDnsResolverObservation
{
    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("address")]
    public string Address { get; init; } = string.Empty;

    [JsonPropertyName("port")]
    public int Port { get; init; }

    [JsonPropertyName("kind")]
    public string Kind { get; init; } = string.Empty;

    [JsonPropertyName("catalogId")]
    public string CatalogId { get; init; } = string.Empty;

    [JsonPropertyName("policy")]
    public string Policy { get; init; } = string.Empty;

    [JsonPropertyName("referenceEligible")]
    public bool ReferenceEligible { get; init; }

    [JsonPropertyName("transport")]
    public string Transport { get; init; } = string.Empty;

    [JsonPropertyName("latencyMs")]
    public double LatencyMs { get; init; }

    [JsonPropertyName("rcode")]
    public int RCode { get; init; }

    [JsonPropertyName("signature")]
    public string Signature { get; init; } = string.Empty;

    [JsonPropertyName("depth")]
    public DiscoveryResolverProfileResult? Depth { get; init; }

    [JsonPropertyName("error")]
    public string Error { get; init; } = string.Empty;
}

public sealed record DiscoveryDnsConsensusGroup
{
    [JsonPropertyName("signature")]
    public string Signature { get; init; } = string.Empty;

    [JsonPropertyName("count")]
    public int Count { get; init; }

    [JsonPropertyName("authoritativeCount")]
    public int AuthoritativeCount { get; init; }

    [JsonPropertyName("sources")]
    public IReadOnlyList<string> Sources { get; init; } = [];
}

public sealed record DiscoveryDnsConsensus
{
    [JsonPropertyName("evidenceCount")]
    public int EvidenceCount { get; init; }

    [JsonPropertyName("validEvidenceCount")]
    public int ValidEvidenceCount { get; init; }

    [JsonPropertyName("groups")]
    public IReadOnlyList<DiscoveryDnsConsensusGroup> Groups { get; init; } = [];

    [JsonPropertyName("dominantSignature")]
    public string DominantSignature { get; init; } = string.Empty;

    [JsonPropertyName("dominantCount")]
    public int DominantCount { get; init; }

    [JsonPropertyName("unanimous")]
    public bool Unanimous { get; init; }

    [JsonPropertyName("divergent")]
    public bool Divergent { get; init; }
}

public sealed record DiscoveryDnsCandidateAssessment
{
    [JsonPropertyName("source")]
    public string Source { get; init; } = string.Empty;

    [JsonPropertyName("signature")]
    public string Signature { get; init; } = string.Empty;

    [JsonPropertyName("authorityReference")]
    public string AuthorityReference { get; init; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; init; } = string.Empty;

    [JsonPropertyName("dnssecStatus")]
    public string DnssecStatus { get; init; } = string.Empty;

    [JsonPropertyName("error")]
    public string Error { get; init; } = string.Empty;
}

public sealed record DiscoveryDnsConsensusComparison
{
    [JsonPropertyName("domain")]
    public string Domain { get; init; } = string.Empty;

    [JsonPropertyName("queryType")]
    public int QueryType { get; init; }

    [JsonPropertyName("authority")]
    public DiscoveryDnsAuthorityComparison Authority { get; init; } = new();

    [JsonPropertyName("resolvers")]
    public IReadOnlyList<DiscoveryDnsResolverObservation> Resolvers { get; init; } = [];

    [JsonPropertyName("consensus")]
    public DiscoveryDnsConsensus Consensus { get; init; } = new();

    [JsonPropertyName("referenceConsensus")]
    public DiscoveryDnsConsensus ReferenceConsensus { get; init; } = new();

    [JsonPropertyName("authorityReferenceSignature")]
    public string AuthorityReferenceSignature { get; init; } = string.Empty;

    [JsonPropertyName("authorityReferenceDefinitive")]
    public bool AuthorityReferenceDefinitive { get; init; }

    [JsonPropertyName("dnssecReference")]
    public DiscoveryDnssecDomainValidation? DnssecReference { get; init; }

    [JsonPropertyName("dnssecReferenceSignature")]
    public string DnssecReferenceSignature { get; init; } = string.Empty;

    [JsonPropertyName("dnssecReferenceDefinitive")]
    public bool DnssecReferenceDefinitive { get; init; }

    [JsonPropertyName("candidates")]
    public IReadOnlyList<DiscoveryDnsCandidateAssessment> Candidates { get; init; } = [];
}

public sealed record DiscoveryDnssecDs
{
    [JsonPropertyName("keyTag")]
    public int KeyTag { get; init; }

    [JsonPropertyName("algorithm")]
    public int Algorithm { get; init; }

    [JsonPropertyName("digestType")]
    public int DigestType { get; init; }

    [JsonPropertyName("digest")]
    public string Digest { get; init; } = string.Empty;
}

public sealed record DiscoveryDnssecDnskey
{
    [JsonPropertyName("flags")]
    public int Flags { get; init; }

    [JsonPropertyName("protocol")]
    public int Protocol { get; init; }

    [JsonPropertyName("algorithm")]
    public int Algorithm { get; init; }

    [JsonPropertyName("publicKey")]
    public string PublicKey { get; init; } = string.Empty;

    [JsonPropertyName("keyTag")]
    public int KeyTag { get; init; }
}

public sealed record DiscoveryDnssecMatch
{
    [JsonPropertyName("ds")]
    public DiscoveryDnssecDs Ds { get; init; } = new();

    [JsonPropertyName("dnskey")]
    public DiscoveryDnssecDnskey Dnskey { get; init; } = new();
}

public sealed record DiscoveryDnssecDelegationValidation
{
    [JsonPropertyName("zone")]
    public string Zone { get; init; } = string.Empty;

    [JsonPropertyName("dsCount")]
    public int DsCount { get; init; }

    [JsonPropertyName("dnskeyCount")]
    public int DnskeyCount { get; init; }

    [JsonPropertyName("supportedDsCount")]
    public int SupportedDsCount { get; init; }

    [JsonPropertyName("matches")]
    public IReadOnlyList<DiscoveryDnssecMatch> Matches { get; init; } = [];

    [JsonPropertyName("unsupportedDigestTypes")]
    public IReadOnlyList<int> UnsupportedDigestTypes { get; init; } = [];

    [JsonPropertyName("status")]
    public string Status { get; init; } = string.Empty;
}

public sealed record DiscoveryDnssecSignatureValidation
{
    [JsonPropertyName("typeCovered")]
    public int TypeCovered { get; init; }

    [JsonPropertyName("algorithm")]
    public int Algorithm { get; init; }

    [JsonPropertyName("keyTag")]
    public int KeyTag { get; init; }

    [JsonPropertyName("signerName")]
    public string SignerName { get; init; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; init; } = string.Empty;

    [JsonPropertyName("error")]
    public string Error { get; init; } = string.Empty;
}

public sealed record DiscoveryDnssecInspection
{
    [JsonPropertyName("zone")]
    public string Zone { get; init; } = string.Empty;

    [JsonPropertyName("ds")]
    public DiscoveryDnsTraceResult Ds { get; init; } = new();

    [JsonPropertyName("dnskey")]
    public DiscoveryDnsTraceResult Dnskey { get; init; } = new();

    [JsonPropertyName("validation")]
    public DiscoveryDnssecDelegationValidation Validation { get; init; } = new();

    [JsonPropertyName("dnskeySignatures")]
    public IReadOnlyList<DiscoveryDnssecSignatureValidation> DnskeySignatures { get; init; } = [];

    [JsonPropertyName("dnskeyAuthenticated")]
    public bool DnskeyAuthenticated { get; init; }

    [JsonPropertyName("authenticationStatus")]
    public string AuthenticationStatus { get; init; } = string.Empty;
}


public sealed record DiscoveryDnssecDenialEvidence
{
    [JsonPropertyName("mechanism")]
    public string Mechanism { get; init; } = string.Empty;

    [JsonPropertyName("owner")]
    public string Owner { get; init; } = string.Empty;

    [JsonPropertyName("next")]
    public string Next { get; init; } = string.Empty;

    [JsonPropertyName("queryName")]
    public string QueryName { get; init; } = string.Empty;

    [JsonPropertyName("queryType")]
    public int QueryType { get; init; }

    [JsonPropertyName("exactName")]
    public bool ExactName { get; init; }

    [JsonPropertyName("nameCovered")]
    public bool NameCovered { get; init; }

    [JsonPropertyName("typeAbsent")]
    public bool TypeAbsent { get; init; }

    [JsonPropertyName("cnameAbsent")]
    public bool CnameAbsent { get; init; }

    [JsonPropertyName("optOut")]
    public bool OptOut { get; init; }

    [JsonPropertyName("status")]
    public string Status { get; init; } = string.Empty;
}

public sealed record DiscoveryDnssecDenialValidation
{
    [JsonPropertyName("evidence")]
    public DiscoveryDnssecDenialEvidence Evidence { get; init; } = new();

    [JsonPropertyName("signatures")]
    public IReadOnlyList<DiscoveryDnssecSignatureValidation> Signatures { get; init; } = [];

    [JsonPropertyName("authenticated")]
    public bool Authenticated { get; init; }
}

public sealed record DiscoveryDnssecAliasValidation
{
    [JsonPropertyName("step")]
    public DiscoveryDnsAliasStep Step { get; init; } = new();

    [JsonPropertyName("signerZone")]
    public string SignerZone { get; init; } = string.Empty;

    [JsonPropertyName("chain")]
    public DiscoveryDnssecChainResult? Chain { get; init; }

    [JsonPropertyName("signatures")]
    public IReadOnlyList<DiscoveryDnssecSignatureValidation> Signatures { get; init; } = [];

    [JsonPropertyName("authenticated")]
    public bool Authenticated { get; init; }

    [JsonPropertyName("status")]
    public string Status { get; init; } = string.Empty;
}

public sealed record DiscoveryDnssecDomainValidation
{
    [JsonPropertyName("domain")]
    public string Domain { get; init; } = string.Empty;

    [JsonPropertyName("queryType")]
    public int QueryType { get; init; }

    [JsonPropertyName("rcode")]
    public int RCode { get; init; }

    [JsonPropertyName("trace")]
    public DiscoveryDnsTraceResult Trace { get; init; } = new();

    [JsonPropertyName("signerZone")]
    public string SignerZone { get; init; } = string.Empty;

    [JsonPropertyName("signerInspection")]
    public DiscoveryDnssecInspection? SignerInspection { get; init; }

    [JsonPropertyName("chain")]
    public DiscoveryDnssecChainResult? Chain { get; init; }

    [JsonPropertyName("rrsetSignatures")]
    public IReadOnlyList<DiscoveryDnssecSignatureValidation> RrsetSignatures { get; init; } = [];

    [JsonPropertyName("aliasValidations")]
    public IReadOnlyList<DiscoveryDnssecAliasValidation> AliasValidations { get; init; } = [];

    [JsonPropertyName("aliasChainAuthenticated")]
    public bool AliasChainAuthenticated { get; init; }

    [JsonPropertyName("denial")]
    public IReadOnlyList<DiscoveryDnssecDenialValidation> Denial { get; init; } = [];

    [JsonPropertyName("denialProof")]
    public DiscoveryDnssecDenialProof? DenialProof { get; init; }

    [JsonPropertyName("answerAuthenticated")]
    public bool AnswerAuthenticated { get; init; }

    [JsonPropertyName("denialAuthenticated")]
    public bool DenialAuthenticated { get; init; }

    [JsonPropertyName("trustScope")]
    public string TrustScope { get; init; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; init; } = string.Empty;
}


public sealed record DiscoveryDnsTrustAnchorAudit
{
    [JsonPropertyName("version")]
    public string Version { get; init; } = string.Empty;

    [JsonPropertyName("sourceUrl")]
    public string SourceUrl { get; init; } = string.Empty;

    [JsonPropertyName("sourceUpdatedDate")]
    public string SourceUpdatedDate { get; init; } = string.Empty;

    [JsonPropertyName("verifiedDate")]
    public string VerifiedDate { get; init; } = string.Empty;

    [JsonPropertyName("rolloverDate")]
    public string RolloverDate { get; init; } = string.Empty;

    [JsonPropertyName("ageDays")]
    public int AgeDays { get; init; }

    [JsonPropertyName("maxAgeDays")]
    public int MaxAgeDays { get; init; }

    [JsonPropertyName("daysUntilRollover")]
    public int DaysUntilRollover { get; init; }

    [JsonPropertyName("rolloverReviewRequired")]
    public bool RolloverReviewRequired { get; init; }

    [JsonPropertyName("stale")]
    public bool Stale { get; init; }

    [JsonPropertyName("valid")]
    public bool Valid { get; init; }

    [JsonPropertyName("reviewRequired")]
    public bool ReviewRequired { get; init; }

    [JsonPropertyName("status")]
    public string Status { get; init; } = string.Empty;

    [JsonPropertyName("keyTags")]
    public IReadOnlyList<int> KeyTags { get; init; } = [];

    [JsonPropertyName("errors")]
    public IReadOnlyList<string> Errors { get; init; } = [];
}

public sealed record DiscoveryDnssecTrustAnchor
{
    [JsonPropertyName("zone")]
    public string Zone { get; init; } = string.Empty;

    [JsonPropertyName("keyTag")]
    public int KeyTag { get; init; }

    [JsonPropertyName("algorithm")]
    public int Algorithm { get; init; }

    [JsonPropertyName("digestType")]
    public int DigestType { get; init; }

    [JsonPropertyName("digest")]
    public string Digest { get; init; } = string.Empty;

    [JsonPropertyName("source")]
    public string Source { get; init; } = string.Empty;
}

public sealed record DiscoveryDnssecChainStep
{
    [JsonPropertyName("zone")]
    public string Zone { get; init; } = string.Empty;

    [JsonPropertyName("parent")]
    public string Parent { get; init; } = string.Empty;

    [JsonPropertyName("ds")]
    public DiscoveryDnsTraceResult? Ds { get; init; }

    [JsonPropertyName("dnskey")]
    public DiscoveryDnsTraceResult Dnskey { get; init; } = new();

    [JsonPropertyName("dsValidation")]
    public DiscoveryDnssecDelegationValidation? DsValidation { get; init; }

    [JsonPropertyName("dsSignatures")]
    public IReadOnlyList<DiscoveryDnssecSignatureValidation> DsSignatures { get; init; } = [];

    [JsonPropertyName("dsAbsenceProof")]
    public DiscoveryDnssecDenialProof? DsAbsenceProof { get; init; }

    [JsonPropertyName("dnskeySignatures")]
    public IReadOnlyList<DiscoveryDnssecSignatureValidation> DnskeySignatures { get; init; } = [];

    [JsonPropertyName("delegationAuthenticated")]
    public bool DelegationAuthenticated { get; init; }

    [JsonPropertyName("insecureDelegation")]
    public bool InsecureDelegation { get; init; }

    [JsonPropertyName("authenticated")]
    public bool Authenticated { get; init; }

    [JsonPropertyName("status")]
    public string Status { get; init; } = string.Empty;

    [JsonPropertyName("trustedKeyCount")]
    public int TrustedKeyCount { get; init; }
}

public sealed record DiscoveryDnssecChainResult
{
    [JsonPropertyName("targetZone")]
    public string TargetZone { get; init; } = string.Empty;

    [JsonPropertyName("trustAnchors")]
    public IReadOnlyList<DiscoveryDnssecTrustAnchor> TrustAnchors { get; init; } = [];

    [JsonPropertyName("steps")]
    public IReadOnlyList<DiscoveryDnssecChainStep> Steps { get; init; } = [];

    [JsonPropertyName("rootAuthenticated")]
    public bool RootAuthenticated { get; init; }

    [JsonPropertyName("chainAuthenticated")]
    public bool ChainAuthenticated { get; init; }

    [JsonPropertyName("insecureDelegation")]
    public bool InsecureDelegation { get; init; }

    [JsonPropertyName("authenticatedZone")]
    public string AuthenticatedZone { get; init; } = string.Empty;

    [JsonPropertyName("insecureZone")]
    public string InsecureZone { get; init; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; init; } = string.Empty;

    [JsonPropertyName("errorCode")]
    public string ErrorCode { get; init; } = string.Empty;

    [JsonPropertyName("error")]
    public string Error { get; init; } = string.Empty;
}


public sealed record DiscoveryResolverProfileRequest
{
    [JsonPropertyName("address")]
    public string Address { get; init; } = string.Empty;

    [JsonPropertyName("port")]
    public int Port { get; init; } = 53;

    [JsonPropertyName("domain")]
    public string Domain { get; init; } = "example.com";

    [JsonPropertyName("timeoutMs")]
    public int TimeoutMs { get; init; } = 2000;

    [JsonPropertyName("attempts")]
    public int Attempts { get; init; } = 3;

    [JsonPropertyName("minSuccesses")]
    public int MinSuccesses { get; init; } = 2;

    [JsonPropertyName("serverName")]
    public string ServerName { get; init; } = string.Empty;

    [JsonPropertyName("dotPort")]
    public int DotPort { get; init; } = 853;

    [JsonPropertyName("dohUrl")]
    public string DohUrl { get; init; } = string.Empty;

    [JsonPropertyName("checkUdp")]
    public bool CheckUdp { get; init; } = true;

    [JsonPropertyName("checkTcp")]
    public bool CheckTcp { get; init; } = true;

    [JsonPropertyName("checkEdns")]
    public bool CheckEdns { get; init; } = true;

    [JsonPropertyName("checkTxt")]
    public bool CheckTxt { get; init; } = true;

    [JsonPropertyName("checkDot")]
    public bool CheckDot { get; init; }

    [JsonPropertyName("checkDoh")]
    public bool CheckDoh { get; init; }
}

public sealed record DiscoveryResolverProfileAttempt
{
    [JsonPropertyName("responded")]
    public bool Responded { get; init; }

    [JsonPropertyName("latencyMs")]
    public double LatencyMs { get; init; }

    [JsonPropertyName("rcode")]
    public int RCode { get; init; }

    [JsonPropertyName("recursionAvailable")]
    public bool RecursionAvailable { get; init; }

    [JsonPropertyName("truncated")]
    public bool Truncated { get; init; }

    [JsonPropertyName("ednsObserved")]
    public bool EdnsObserved { get; init; }

    [JsonPropertyName("answerCount")]
    public int AnswerCount { get; init; }

    [JsonPropertyName("answerSignature")]
    public string AnswerSignature { get; init; } = string.Empty;

    [JsonPropertyName("txt")]
    public IReadOnlyList<string> Txt { get; init; } = [];

    [JsonPropertyName("tlsVersion")]
    public string TlsVersion { get; init; } = string.Empty;

    [JsonPropertyName("alpn")]
    public string Alpn { get; init; } = string.Empty;

    [JsonPropertyName("tlsServerName")]
    public string TlsServerName { get; init; } = string.Empty;

    [JsonPropertyName("tlsVerified")]
    public bool TlsVerified { get; init; }

    [JsonPropertyName("httpStatus")]
    public int HttpStatus { get; init; }

    [JsonPropertyName("httpVersion")]
    public string HttpVersion { get; init; } = string.Empty;

    [JsonPropertyName("contentType")]
    public string ContentType { get; init; } = string.Empty;

    [JsonPropertyName("error")]
    public string Error { get; init; } = string.Empty;
}

public sealed record DiscoveryResolverProfileProbe
{
    [JsonPropertyName("transport")]
    public string Transport { get; init; } = string.Empty;

    [JsonPropertyName("attempted")]
    public bool Attempted { get; init; }

    [JsonPropertyName("responded")]
    public bool Responded { get; init; }

    [JsonPropertyName("attempts")]
    public int Attempts { get; init; }

    [JsonPropertyName("successes")]
    public int Successes { get; init; }

    [JsonPropertyName("quorumMet")]
    public bool QuorumMet { get; init; }

    [JsonPropertyName("reliability")]
    public double Reliability { get; init; }

    [JsonPropertyName("medianLatencyMs")]
    public double MedianLatencyMs { get; init; }

    [JsonPropertyName("latencyMs")]
    public double LatencyMs { get; init; }

    [JsonPropertyName("rcode")]
    public int RCode { get; init; }

    [JsonPropertyName("recursionAvailable")]
    public bool RecursionAvailable { get; init; }

    [JsonPropertyName("truncated")]
    public bool Truncated { get; init; }

    [JsonPropertyName("ednsObserved")]
    public bool EdnsObserved { get; init; }

    [JsonPropertyName("answerCount")]
    public int AnswerCount { get; init; }

    [JsonPropertyName("answerSignature")]
    public string AnswerSignature { get; init; } = string.Empty;

    [JsonPropertyName("txt")]
    public IReadOnlyList<string> Txt { get; init; } = [];

    [JsonPropertyName("tlsVersion")]
    public string TlsVersion { get; init; } = string.Empty;

    [JsonPropertyName("alpn")]
    public string Alpn { get; init; } = string.Empty;

    [JsonPropertyName("tlsServerName")]
    public string TlsServerName { get; init; } = string.Empty;

    [JsonPropertyName("tlsVerified")]
    public bool TlsVerified { get; init; }

    [JsonPropertyName("httpStatus")]
    public int HttpStatus { get; init; }

    [JsonPropertyName("httpVersion")]
    public string HttpVersion { get; init; } = string.Empty;

    [JsonPropertyName("contentType")]
    public string ContentType { get; init; } = string.Empty;

    [JsonPropertyName("error")]
    public string Error { get; init; } = string.Empty;

    [JsonPropertyName("samples")]
    public IReadOnlyList<DiscoveryResolverProfileAttempt> Samples { get; init; } = [];
}

public sealed record DiscoveryResolverProfileResult
{
    [JsonPropertyName("address")]
    public string Address { get; init; } = string.Empty;

    [JsonPropertyName("domain")]
    public string Domain { get; init; } = string.Empty;

    [JsonPropertyName("udp")]
    public DiscoveryResolverProfileProbe? Udp { get; init; }

    [JsonPropertyName("tcp")]
    public DiscoveryResolverProfileProbe? Tcp { get; init; }

    [JsonPropertyName("edns512")]
    public DiscoveryResolverProfileProbe? Edns512 { get; init; }

    [JsonPropertyName("edns1232")]
    public DiscoveryResolverProfileProbe? Edns1232 { get; init; }

    [JsonPropertyName("txt")]
    public DiscoveryResolverProfileProbe? Txt { get; init; }

    [JsonPropertyName("dot")]
    public DiscoveryResolverProfileProbe? Dot { get; init; }

    [JsonPropertyName("doh")]
    public DiscoveryResolverProfileProbe? Doh { get; init; }

    [JsonPropertyName("ednsCompatible")]
    public bool EdnsCompatible { get; init; }

    [JsonPropertyName("ednsDowngrade")]
    public bool EdnsDowngrade { get; init; }

    [JsonPropertyName("udpAndTcpAgree")]
    public bool? UdpAndTcpAgree { get; init; }

    [JsonPropertyName("classicEncryptedAgree")]
    public bool? ClassicEncryptedAgree { get; init; }

    [JsonPropertyName("encryptedDnsAvailable")]
    public bool EncryptedDnsAvailable { get; init; }

    [JsonPropertyName("interceptionSuspected")]
    public bool InterceptionSuspected { get; init; }

    [JsonPropertyName("interceptionReasons")]
    public IReadOnlyList<string> InterceptionReasons { get; init; } = [];

    [JsonPropertyName("quorumTransportCount")]
    public int QuorumTransportCount { get; init; }

    [JsonPropertyName("reliabilityFloor")]
    public double ReliabilityFloor { get; init; }

    [JsonPropertyName("quality")]
    public string Quality { get; init; } = string.Empty;

    [JsonPropertyName("qualityReasons")]
    public IReadOnlyList<string> QualityReasons { get; init; } = [];

    [JsonPropertyName("status")]
    public string Status { get; init; } = string.Empty;
}

public sealed record DiscoveryDnssecDenialProof
{
    [JsonPropertyName("mechanism")]
    public string Mechanism { get; init; } = string.Empty;

    [JsonPropertyName("queryName")]
    public string QueryName { get; init; } = string.Empty;

    [JsonPropertyName("queryType")]
    public int QueryType { get; init; }

    [JsonPropertyName("rcode")]
    public int RCode { get; init; }

    [JsonPropertyName("closestEncloser")]
    public string ClosestEncloser { get; init; } = string.Empty;

    [JsonPropertyName("nextCloser")]
    public string NextCloser { get; init; } = string.Empty;

    [JsonPropertyName("wildcardName")]
    public string WildcardName { get; init; } = string.Empty;

    [JsonPropertyName("closestEncloserProven")]
    public bool ClosestEncloserProven { get; init; }

    [JsonPropertyName("nextCloserProven")]
    public bool NextCloserProven { get; init; }

    [JsonPropertyName("wildcardNonexistenceProven")]
    public bool WildcardNonexistenceProven { get; init; }

    [JsonPropertyName("exactNameProven")]
    public bool ExactNameProven { get; init; }

    [JsonPropertyName("typeAbsent")]
    public bool TypeAbsent { get; init; }

    [JsonPropertyName("cnameAbsent")]
    public bool CnameAbsent { get; init; }

    [JsonPropertyName("optOut")]
    public bool OptOut { get; init; }

    [JsonPropertyName("insecureDelegation")]
    public bool InsecureDelegation { get; init; }

    [JsonPropertyName("complete")]
    public bool Complete { get; init; }

    [JsonPropertyName("status")]
    public string Status { get; init; } = string.Empty;
}


public sealed record DiscoveryResolverCatalogIdentity
{
    [JsonPropertyName("id")]
    public string Id { get; init; } = string.Empty;

    [JsonPropertyName("provider")]
    public string Provider { get; init; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("ipv4")]
    public IReadOnlyList<string> IPv4 { get; init; } = [];

    [JsonPropertyName("ipv6")]
    public IReadOnlyList<string> IPv6 { get; init; } = [];

    [JsonPropertyName("port")]
    public int Port { get; init; } = 53;

    [JsonPropertyName("dotServerName")]
    public string DotServerName { get; init; } = string.Empty;

    [JsonPropertyName("dotPort")]
    public int DotPort { get; init; } = 853;

    [JsonPropertyName("dohUrl")]
    public string DohUrl { get; init; } = string.Empty;

    [JsonPropertyName("dnssecValidating")]
    public bool DnssecValidating { get; init; }

    [JsonPropertyName("policy")]
    public string Policy { get; init; } = string.Empty;

    [JsonPropertyName("referenceEligible")]
    public bool ReferenceEligible { get; init; }

    [JsonPropertyName("sourceUrls")]
    public IReadOnlyList<string> SourceUrls { get; init; } = [];

    [JsonPropertyName("verifiedDate")]
    public string VerifiedDate { get; init; } = string.Empty;
}

public sealed record DiscoveryResolverCatalog
{
    [JsonPropertyName("version")]
    public string Version { get; init; } = string.Empty;

    [JsonPropertyName("resolvers")]
    public IReadOnlyList<DiscoveryResolverCatalogIdentity> Resolvers { get; init; } = [];

    [JsonPropertyName("referenceEligible")]
    public IReadOnlyList<DiscoveryResolverCatalogIdentity> ReferenceEligible { get; init; } = [];
}


public sealed record DiscoveryDnsRepairFamilyResult
{
    [JsonPropertyName("family")]
    public string Family { get; init; } = string.Empty;

    [JsonPropertyName("queryType")]
    public int QueryType { get; init; }

    [JsonPropertyName("trace")]
    public DiscoveryDnsTraceResult Trace { get; init; } = new();

    [JsonPropertyName("dnssec")]
    public DiscoveryDnssecDomainValidation? Dnssec { get; init; }

    [JsonPropertyName("dnssecAuthenticated")]
    public bool DnssecAuthenticated { get; init; }

    [JsonPropertyName("dnssecStatus")]
    public string DnssecStatus { get; init; } = string.Empty;

    [JsonPropertyName("fallbackUsed")]
    public bool FallbackUsed { get; init; }

    [JsonPropertyName("error")]
    public string Error { get; init; } = string.Empty;
}

public sealed record DiscoveryDnsRepairInspection
{
    [JsonPropertyName("domain")]
    public string Domain { get; init; } = string.Empty;

    [JsonPropertyName("ipv4")]
    public DiscoveryDnsRepairFamilyResult IPv4 { get; init; } = new();

    [JsonPropertyName("ipv6")]
    public DiscoveryDnsRepairFamilyResult IPv6 { get; init; } = new();

    [JsonPropertyName("resolverCatalogVersion")]
    public string ResolverCatalogVersion { get; init; } = string.Empty;

    [JsonPropertyName("resolverRecommendations")]
    public IReadOnlyList<DiscoveryResolverCatalogIdentity> ResolverRecommendations { get; init; } = [];
}


public sealed record DiscoveryResolverCatalogAuditEntry
{
    [JsonPropertyName("id")]
    public string Id { get; init; } = string.Empty;

    [JsonPropertyName("verifiedDate")]
    public string VerifiedDate { get; init; } = string.Empty;

    [JsonPropertyName("ageDays")]
    public int AgeDays { get; init; }

    [JsonPropertyName("stale")]
    public bool Stale { get; init; }
}

public sealed record DiscoveryResolverCatalogAudit
{
    [JsonPropertyName("version")]
    public string Version { get; init; } = string.Empty;

    [JsonPropertyName("valid")]
    public bool Valid { get; init; }

    [JsonPropertyName("error")]
    public string Error { get; init; } = string.Empty;

    [JsonPropertyName("maxAgeDays")]
    public int MaxAgeDays { get; init; }

    [JsonPropertyName("staleCount")]
    public int StaleCount { get; init; }

    [JsonPropertyName("entries")]
    public IReadOnlyList<DiscoveryResolverCatalogAuditEntry> Entries { get; init; } = [];
}
