namespace ServiceLib.Reviver.Models;

/// <summary>
/// Immutable-by-convention deep snapshot of a PattN profile at the start of a repair session.
/// Every repair candidate is cloned from this snapshot; the original ProfileItem is never mutated.
/// </summary>
public sealed class ProfileSnapshot
{
    private readonly ProfileItem _profile;

    private ProfileSnapshot(ProfileItem profile)
    {
        _profile = profile;
    }

    public string IndexId => _profile.IndexId;
    public EConfigType ConfigType => _profile.ConfigType;
    public string Remarks => _profile.Remarks;

    public static ProfileSnapshot Capture(ProfileItem profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        return new ProfileSnapshot(JsonUtils.DeepCopy(profile)
            ?? throw new InvalidOperationException("Could not snapshot profile."));
    }

    public ProfileItem CreateWorkingCopy()
    {
        return JsonUtils.DeepCopy(_profile)
            ?? throw new InvalidOperationException("Could not clone profile snapshot.");
    }
}
