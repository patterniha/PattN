namespace ServiceLib.Discovery.Models;

public sealed record EndpointPoolQuery
{
    public string? LogicalHost { get; init; }
    public bool IncludeDisabled { get; init; } = true;
    public int MaxItems { get; init; } = 200;
}

public sealed record EndpointPoolUpdate
{
    public required string Id { get; init; }
    public bool? Enabled { get; init; }
    public bool? Pinned { get; init; }
    public string? Label { get; init; }
}
