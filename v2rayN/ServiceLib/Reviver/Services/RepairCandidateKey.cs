namespace ServiceLib.Reviver.Services;

internal static class RepairCandidateKey
{
    public static string Create(ProfileItem profile)
    {
        // The repair search never mutates the candidate during key generation. Full canonical JSON is deliberate:
        // two strategies that produce exactly the same ProfileItem collapse to one validation candidate.
        return JsonUtils.Serialize(profile, false);
    }
}
