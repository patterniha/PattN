namespace ServiceLib.Discovery.Models;

public sealed record MaintenancePayloadEstimate
{
    public long TotalBytes { get; init; }
    public IReadOnlyDictionary<string, long> BytesByCategory { get; init; } =
        new Dictionary<string, long>(StringComparer.Ordinal);

    public string HumanReadable
        => FormatBytes(TotalBytes);

    public static string FormatBytes(long value)
    {
        value = Math.Max(0, value);
        string[] units = ["B", "KB", "MB", "GB"];
        var size = (double)value;
        var unit = 0;
        while (size >= 1024d && unit < units.Length - 1)
        {
            size /= 1024d;
            unit++;
        }
        return $"{size:0.##} {units[unit]}";
    }
}
