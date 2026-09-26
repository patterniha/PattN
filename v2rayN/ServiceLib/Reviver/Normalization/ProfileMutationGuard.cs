namespace ServiceLib.Reviver.Normalization;

/// <summary>
/// Detects top-level ProfileItem semantic changes. ProtocolExtra/TransportExtra are serialized fields on the
/// profile, so any nested change is visible as a change to those properties.
/// </summary>
public static class ProfileMutationGuard
{
    private static readonly PropertyInfo[] ComparableProperties = typeof(ProfileItem)
        .GetProperties(BindingFlags.Instance | BindingFlags.Public)
        .Where(x => x.CanRead && x.GetIndexParameters().Length == 0)
        .ToArray();

    public static IReadOnlyList<string> ChangedFields(ProfileItem original, ProfileItem candidate)
    {
        ArgumentNullException.ThrowIfNull(original);
        ArgumentNullException.ThrowIfNull(candidate);

        var changed = new List<string>();
        foreach (var property in ComparableProperties)
        {
            var left = property.GetValue(original);
            var right = property.GetValue(candidate);
            if (!Equals(left, right))
            {
                changed.Add(property.Name);
            }
        }
        return changed;
    }

    public static bool ChangesOnly(ProfileItem original, ProfileItem candidate, params string[] allowedFields)
    {
        var allowed = allowedFields.ToHashSet(StringComparer.Ordinal);
        return ChangedFields(original, candidate).All(allowed.Contains);
    }
}
