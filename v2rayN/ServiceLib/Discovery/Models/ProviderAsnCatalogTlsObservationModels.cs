namespace ServiceLib.Discovery.Models;

/// <summary>
/// Certificate/key evidence observed through an ordinary HTTPS connection. This is display-only evidence:
/// observing a key never adds it to the trusted pin set and never changes remote source configuration.
/// </summary>
public sealed record ProviderAsnCatalogTlsObservation
{
    public required string RequestedUri { get; init; }
    public required string FinalUri { get; init; }
    public int HttpStatusCode { get; init; }
    public required string Host { get; init; }
    public required string SpkiSha256 { get; init; }
    public string Subject { get; init; } = string.Empty;
    public string Issuer { get; init; } = string.Empty;
    public DateTimeOffset NotBefore { get; init; }
    public DateTimeOffset NotAfter { get; init; }
    public DateTimeOffset ObservedAt { get; init; }
}

public sealed record ProviderAsnCatalogTlsPinSetDiff
{
    public IReadOnlyList<string> Existing { get; init; } = [];
    public IReadOnlyList<string> Proposed { get; init; } = [];
    public IReadOnlyList<string> Added { get; init; } = [];
    public IReadOnlyList<string> Removed { get; init; } = [];
    public IReadOnlyList<string> Unchanged { get; init; } = [];

    public bool Changed => Added.Count > 0 || Removed.Count > 0;
}
