namespace ServiceLib.Discovery.Models;

public static class EndpointPoolPolicy
{
    public const int MaxLabelLength = 160;

    public static string NormalizeLabel(string? label)
    {
        label = label?.Trim() ?? string.Empty;
        if (label.Length > MaxLabelLength)
        {
            throw new ArgumentOutOfRangeException(nameof(label), $"Endpoint pool labels may not exceed {MaxLabelLength} characters.");
        }
        return label;
    }
}
