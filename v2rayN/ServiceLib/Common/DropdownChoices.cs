namespace ServiceLib.Common;

// PattN: fork-only file.

/// <summary>
/// PattN: the choices a fixed dropdown of the server editor offers (alpn, curvePreferences) for a profile whose value is
/// none of them, as a share link can carry any: that value after them, so that the box shows what the profile holds, and
/// saving keeps it, rather than looking empty; picking a choice replaces it. PattNG's dropdown fields show any value.
/// </summary>
public static class DropdownChoices
{
    /// <summary>
    /// <paramref name="choices" />, with <paramref name="value" /> after them when it is not empty and none of them,
    /// compared as written; the choices alone otherwise. The list given is left as it is.
    /// </summary>
    public static List<string> With(IReadOnlyList<string> choices, string? value)
    {
        var list = choices.ToList();
        if (!string.IsNullOrEmpty(value) && !list.Contains(value, StringComparer.Ordinal))
        {
            list.Add(value);
        }
        return list;
    }
}
