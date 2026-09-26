using ServiceLib.Reviver.Models;

namespace ServiceLib.Reviver.Services;

public interface IRepairBaselineDiagnostic
{
    Task<RepairDiagnosis> DiagnoseAsync(RepairSession session, CancellationToken cancellationToken = default);
}
