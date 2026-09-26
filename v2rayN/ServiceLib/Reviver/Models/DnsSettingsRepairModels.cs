namespace ServiceLib.Reviver.Models;

public sealed record DnsSettingsRepairPlan
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public required string ResolverCatalogId { get; init; }
    public required string ResolverName { get; init; }
    public required string ResolverPolicy { get; init; }
    public required bool ResolverReferenceEligible { get; init; }
    public required string CatalogVersion { get; init; }
    public required SimpleDNSItem Before { get; init; }
    public required SimpleDNSItem After { get; init; }
    public required string BeforeFingerprint { get; init; }
    public required string AfterFingerprint { get; init; }
    public IReadOnlyList<string> Changes { get; init; } = [];
}

public sealed record DnsSettingsRepairReceipt
{
    public required string PlanId { get; init; }
    public required string ResolverCatalogId { get; init; }
    public required string CatalogVersion { get; init; }
    public required SimpleDNSItem Before { get; init; }
    public required SimpleDNSItem Applied { get; init; }
    public required string AppliedFingerprint { get; init; }
    public DateTimeOffset AppliedAt { get; init; } = DateTimeOffset.UtcNow;
}
