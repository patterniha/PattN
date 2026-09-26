using ServiceLib.Discovery.Protocol;

namespace ServiceLib.Discovery.Services;

public interface IDnsResolverTelemetryProbe : IAsyncDisposable
{
    Task<DiscoveryResolverCatalog> GetCatalogAsync(CancellationToken cancellationToken = default);
    Task<DiscoveryResolverCatalogAudit> AuditCatalogAsync(int maxAgeDays, CancellationToken cancellationToken = default);
    Task<DiscoveryResolverProfileResult> ProfileAsync(
        DiscoveryResolverProfileRequest request,
        CancellationToken cancellationToken = default);
}

public sealed class DiscoveryResolverTelemetryProbe : IDnsResolverTelemetryProbe
{
    private readonly DiscoveryEngineService _engine = new();

    public Task<DiscoveryResolverCatalog> GetCatalogAsync(CancellationToken cancellationToken = default)
        => _engine.GetResolverCatalogAsync(cancellationToken);

    public Task<DiscoveryResolverCatalogAudit> AuditCatalogAsync(
        int maxAgeDays,
        CancellationToken cancellationToken = default)
        => _engine.AuditResolverCatalogAsync(maxAgeDays, cancellationToken);

    public Task<DiscoveryResolverProfileResult> ProfileAsync(
        DiscoveryResolverProfileRequest request,
        CancellationToken cancellationToken = default)
        => _engine.ProfileResolverAsync(request, cancellationToken);

    public ValueTask DisposeAsync() => _engine.DisposeAsync();
}
