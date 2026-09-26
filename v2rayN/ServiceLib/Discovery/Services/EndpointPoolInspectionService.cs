using ServiceLib.Discovery.Models;

namespace ServiceLib.Discovery.Services;

public sealed class EndpointPoolInspectionService(
    IEndpointPoolAdminStore admin,
    IEndpointHistoryQueryService history)
{
    public async Task<IReadOnlyList<EndpointPoolInspectionRow>> InspectAsync(
        EndpointPoolInspectionQuery? query = null,
        CancellationToken cancellationToken = default)
    {
        query ??= new EndpointPoolInspectionQuery();
        Validate(query);
        cancellationToken.ThrowIfCancellationRequested();

        var rows = await admin.ListAsync(
            new EndpointPoolQuery
            {
                LogicalHost = query.LogicalHost,
                IncludeDisabled = query.IncludeDisabled,
                MaxItems = query.MaxItems,
            },
            cancellationToken);

        var result = new List<EndpointPoolInspectionRow>(rows.Count);
        foreach (var row in rows)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var detail = await history.GetAsync(
                new DiscoveryCandidateRequest
                {
                    OriginalAddress = row.LogicalHost,
                    OriginalPort = row.Port,
                    LogicalHost = row.LogicalHost,
                    HttpHost = row.HttpHost.NullIfEmpty() ?? row.LogicalHost,
                    Network = row.Network,
                    StreamSecurity = row.StreamSecurity,
                },
                row.Address,
                query.HistoryAge,
                query.HistoryPoints,
                cancellationToken);

            result.Add(new EndpointPoolInspectionRow
            {
                Id = row.Id,
                LogicalHost = row.LogicalHost,
                HttpHost = row.HttpHost,
                Port = row.Port,
                Network = row.Network,
                StreamSecurity = row.StreamSecurity,
                Address = row.Address,
                Label = row.Label,
                Enabled = row.Enabled,
                Pinned = row.Pinned,
                Provider = row.Provider,
                Asn = row.Asn,
                Pop = row.Pop,
                CreatedAt = DateTimeOffset.FromUnixTimeMilliseconds(row.CreatedAtUnixMs),
                UpdatedAt = DateTimeOffset.FromUnixTimeMilliseconds(row.UpdatedAtUnixMs),
                History = detail.Summary,
                LatestObservation = detail.Points.FirstOrDefault(),
                HistoricallyGood = detail.Summary?.IsHistoricallyGood(query.HistoryPolicy) == true,
            });
        }

        return result;
    }

    private static void Validate(EndpointPoolInspectionQuery query)
    {
        if (query.MaxItems is < 1 or > 250)
        {
            throw new ArgumentOutOfRangeException(nameof(query.MaxItems), "Endpoint pool inspection is limited to 1..250 rows per request.");
        }
        if (query.HistoryPoints is < 1 or > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(query.HistoryPoints), "Endpoint pool inspection history is limited to 1..100 points per row.");
        }
        if (query.HistoryAge <= TimeSpan.Zero || query.HistoryAge > TimeSpan.FromDays(365))
        {
            throw new ArgumentOutOfRangeException(nameof(query.HistoryAge), "Endpoint pool inspection history age must be greater than zero and no more than 365 days.");
        }
        ArgumentNullException.ThrowIfNull(query.HistoryPolicy);
    }
}
