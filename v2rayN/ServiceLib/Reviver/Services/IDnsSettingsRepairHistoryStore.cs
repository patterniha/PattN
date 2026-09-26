using ServiceLib.Reviver.Models;

namespace ServiceLib.Reviver.Services;

public interface IDnsSettingsRepairHistoryStore
{
    Task RecordAppliedAsync(
        DnsSettingsRepairReceipt receipt,
        CancellationToken cancellationToken = default);

    Task RecordRolledBackAsync(
        DnsSettingsRepairReceipt receipt,
        CancellationToken cancellationToken = default);

    Task<DnsSettingsRepairReceipt?> GetLatestActiveAsync(
        CancellationToken cancellationToken = default);
}
