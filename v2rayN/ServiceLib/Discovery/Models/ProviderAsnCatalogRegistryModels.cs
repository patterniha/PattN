namespace ServiceLib.Discovery.Models;

public sealed record ProviderAsnCatalogRegistrationOptions
{
    public string? DisplayName { get; init; }
    public bool Enabled { get; init; } = true;
    public bool RequireFreshMetadata { get; init; }
    public ProviderAsnCatalogAuditPolicy AuditPolicy { get; init; } = new();
}

public sealed record ProviderAsnCatalogUnregisterOptions
{
    /// <summary>
    /// Irreversibly discards the registry's persisted revision ledger. The catalog file itself is never deleted.
    /// </summary>
    public bool DiscardRevisionHistory { get; init; }
}

public sealed record ProviderAsnCatalogUnregisterReceipt
{
    public required string RegistryId { get; init; }
    public required string FilePath { get; init; }
    public string CatalogId { get; init; } = string.Empty;
    public DateTimeOffset UnregisteredAt { get; init; }
    public bool RevisionHistoryDiscarded { get; init; }
    public int RevisionCount { get; init; }
}

public sealed record ProviderAsnCatalogRegistryView
{
    public required string Id { get; init; }
    public required string FilePath { get; init; }
    public string DisplayName { get; init; } = string.Empty;
    public bool Enabled { get; init; }

    public string CatalogId { get; init; } = string.Empty;
    public string CatalogVersion { get; init; } = string.Empty;
    public string CatalogSource { get; init; } = string.Empty;
    public string Sha256 { get; init; } = string.Empty;
    public DateTimeOffset? CatalogUpdatedAt { get; init; }

    public DateTimeOffset RegisteredAt { get; init; }
    public DateTimeOffset UpdatedAt { get; init; }
    public DateTimeOffset? UnregisteredAt { get; init; }
    public bool Registered => UnregisteredAt is null;
    public DateTimeOffset? LastAuditedAt { get; init; }
    public ProviderAsnCatalogAudit? LastAudit { get; init; }
    public string ActiveRevisionId { get; init; } = string.Empty;
}

public sealed record ProviderAsnCatalogRevisionView
{
    public required string Id { get; init; }
    public required string RegistryId { get; init; }
    public string PlanId { get; init; } = string.Empty;
    public string DestinationPath { get; init; } = string.Empty;
    public string BeforeSha256 { get; init; } = string.Empty;
    public string AfterSha256 { get; init; } = string.Empty;
    public string BeforeCatalogVersion { get; init; } = string.Empty;
    public string AfterCatalogVersion { get; init; } = string.Empty;
    public DateTimeOffset AppliedAt { get; init; }
    public DateTimeOffset? RolledBackAt { get; init; }
    public bool RollbackForced { get; init; }
    public bool Active { get; init; }
    public ProviderAsnCatalogAudit? AppliedAudit { get; init; }
    public ProviderAsnCatalogDiff? Diff { get; init; }
}

public sealed record ProviderAsnCatalogRegistryQuery
{
    public bool IncludeDisabled { get; init; } = true;
    public bool IncludeUnregistered { get; init; }
    public int MaxItems { get; init; } = 200;
}

public sealed record ProviderAsnCatalogRevisionQuery
{
    public string? RegistryId { get; init; }
    public bool IncludeRolledBack { get; init; } = true;
    public int MaxItems { get; init; } = 200;
}
