namespace ServiceLib.Models.Entities;

[Serializable]
public class DnsRepairHistoryItem
{
    [PrimaryKey]
    public string Id { get; set; } = string.Empty;

    public string Host { get; set; } = string.Empty;
    public string ProfileId { get; set; } = string.Empty;
    public string SessionId { get; set; } = string.Empty;
    public string CandidateId { get; set; } = string.Empty;
    public string EventKind { get; set; } = string.Empty;
    public string TargetStrategy { get; set; } = string.Empty;
    public string FamilyPreference { get; set; } = string.Empty;
    public string CandidateState { get; set; } = string.Empty;
    public string CatalogVersion { get; set; } = string.Empty;
    public int Attempts { get; set; }
    public int Successes { get; set; }
    public int ConsecutiveSuccesses { get; set; }
    public double? LossRate { get; set; }
    public double? MedianLatencyMs { get; set; }
    public bool RuntimeQuorumMet { get; set; }
    public long ObservedAtUnixMs { get; set; }
    public string EvidenceJson { get; set; } = string.Empty;
}
