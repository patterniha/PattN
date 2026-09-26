using ServiceLib.Reviver.Models;

namespace ServiceLib.Reviver.Services;

public interface IDnsRepairEvidenceProvider
{
    Task<DnsRepairObservation> InspectAsync(
        string host,
        CancellationToken cancellationToken = default);
}
