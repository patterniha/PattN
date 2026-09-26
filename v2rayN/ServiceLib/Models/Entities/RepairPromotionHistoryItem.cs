namespace ServiceLib.Models.Entities;

[Serializable]
public class RepairPromotionHistoryItem
{
    [PrimaryKey]
    public string Id { get; set; } = string.Empty;

    public string EventKind { get; set; } = string.Empty;
    public string SessionId { get; set; } = string.Empty;
    public string CandidateId { get; set; } = string.Empty;
    public string OriginalProfileId { get; set; } = string.Empty;
    public string PromotedProfileId { get; set; } = string.Empty;
    public string PreviousDefaultProfileId { get; set; } = string.Empty;
    public bool BecameDefault { get; set; }
    public double? Score { get; set; }
    public string OutcomeVerdict { get; set; } = string.Empty;
    public string MutationsJson { get; set; } = string.Empty;
    public string BaselineValidationJson { get; set; } = string.Empty;
    public string CandidateValidationJson { get; set; } = string.Empty;
    public string OutcomeComparisonJson { get; set; } = string.Empty;
    public long ObservedAtUnixMs { get; set; }
}
