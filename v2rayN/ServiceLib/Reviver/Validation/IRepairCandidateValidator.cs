using ServiceLib.Reviver.Models;

namespace ServiceLib.Reviver.Validation;

public interface IRepairCandidateValidator
{
    Task<RepairValidationEvidence> ValidateAsync(
        RepairCandidate candidate,
        CancellationToken cancellationToken = default);
}
