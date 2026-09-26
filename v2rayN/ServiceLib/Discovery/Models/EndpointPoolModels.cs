namespace ServiceLib.Discovery.Models;

public sealed record EndpointPoolQuery
{
    public const int MaximumItems = 2000;

    public string? LogicalHost { get; init; }
    public bool IncludeDisabled { get; init; } = true;
    public long? DisabledUnpinnedBeforeUnixMs { get; init; }
    public bool OldestFirst { get; init; }
    public int MaxItems { get; init; } = 200;
}

public sealed record EndpointPoolUpdate
{
    public required string Id { get; init; }
    public bool? Enabled { get; init; }
    public bool? Pinned { get; init; }
    public string? Label { get; init; }
}
