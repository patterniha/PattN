using System.Reflection;
using System.Text.Json;
using ServiceLib;
using ServiceLib.Enums;
using ServiceLib.Helper;
using ServiceLib.Manager;
using ServiceLib.Models.Configs;
using ServiceLib.Models.Entities;
using ServiceLib.Resx;
using v2rayN.WebAPI.Contracts;
using v2rayN.WebAPI.Services;

namespace v2rayN.WebAPI.Tests;

// PattN (N1, PattNG SubEditViewModel): the API refuses the subscription the desktop's subscription editor refuses, one
// whose previous or next profile is a name no profile has, or several have, with code subscription_chain_profile_invalid
// and the editor's words as the detail of its data, as the other refusals carry them; a name that finds its one profile,
// the spaces around it aside, and a blank name, which chains nothing, are saved.
[NotInParallel]
public class SubscriptionNameRefusalTests
{
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    private sealed record Names(string Suffix, ProfileItem Found, string Shared, string Missing)
    {
        public string Subscription => $"sub-{Suffix}";
    }

    /// <summary>
    /// Runs <paramref name="body" /> with a profile named <c>found-…</c>, two named <c>shared-…</c> (one with a space after
    /// it) and none named <c>missing-…</c>, then removes them and every subscription the body saved.
    /// </summary>
    private static async Task WithProfilesAsync(Func<Names, V2rayRuntime, Task> body)
    {
        var previousLocalData = Environment.GetEnvironmentVariable(Global.LocalAppData);
        var state = ConfigState.Instance;
        var configField = typeof(ConfigState).GetField("_current", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new MissingFieldException(typeof(ConfigState).FullName, "_current");
        var previousConfig = configField.GetValue(state);
        var suffix = Guid.NewGuid().ToString("N");
        var shared = $"shared-{suffix}";
        var profiles = new[]
        {
            new ProfileItem { IndexId = $"found-{suffix}", ConfigType = EConfigType.VLESS, CoreType = ECoreType.Xray, Remarks = $"found-{suffix}" },
            new ProfileItem { IndexId = $"twin-a-{suffix}", ConfigType = EConfigType.VLESS, CoreType = ECoreType.Xray, Remarks = shared },
            new ProfileItem { IndexId = $"twin-b-{suffix}", ConfigType = EConfigType.Trojan, CoreType = ECoreType.Xray, Remarks = $"{shared} " },
        };
        var names = new Names(suffix, profiles[0], shared, $"missing-{suffix}");
        try
        {
            Environment.SetEnvironmentVariable(Global.LocalAppData, "0");
            configField.SetValue(state, new Config { SubIndexId = string.Empty });
            SQLiteHelper.Instance.CreateTable<ProfileItem>();
            SQLiteHelper.Instance.CreateTable<SubItem>();
            foreach (var profile in profiles)
            {
                await SQLiteHelper.Instance.ReplaceAsync(profile);
            }
            await body(names, new V2rayRuntime(null!, null!, null!, null!, null!));
        }
        finally
        {
            try
            {
                foreach (var profile in profiles)
                {
                    await SQLiteHelper.Instance.DeleteAsync(profile);
                }
                foreach (var saved in await SavedAsync(names))
                {
                    await SQLiteHelper.Instance.DeleteAsync(saved);
                }
            }
            finally
            {
                configField.SetValue(state, previousConfig);
                Environment.SetEnvironmentVariable(Global.LocalAppData, previousLocalData);
            }
        }
    }

    private static async Task<List<SubItem>> SavedAsync(Names names) =>
        (await ConfigDbQuery.SubItems() ?? []).Where(item => item.Remarks == names.Subscription).ToList();

    private static SubscriptionInput Input(Names names, string? prevProfile = null, string? nextProfile = null) =>
        new(names.Subscription, string.Empty, MoreUrl: string.Empty, Enabled: false, AutoUpdateInterval: 0,
            PrevProfile: prevProfile, NextProfile: nextProfile);

    /// <summary>The words of the refusal <paramref name="result" />, as its reply carries them.</summary>
    private static async Task<string?> DetailOf(SubscriptionMutationResult result)
    {
        await result.Success.Should().BeFalse();
        await result.Code.Should().BeEqualTo("subscription_chain_profile_invalid");
        await result.MessageKey.Should().BeEqualTo(ApiMessageKeys.CommonInvalidInput);
        await result.Data.Should().BeNull();
        var reply = JsonSerializer.SerializeToElement(result, WebJson);
        await reply.GetProperty("success").GetBoolean().Should().BeFalse();
        await reply.GetProperty("code").GetString().Should().BeEqualTo("subscription_chain_profile_invalid");
        await reply.GetProperty("messageKey").GetString().Should().BeEqualTo(ApiMessageKeys.CommonInvalidInput);
        await reply.TryGetProperty("detail", out _).Should().BeFalse();
        var detail = reply.GetProperty("data").GetProperty("detail").GetString();
        await detail.Should().BeEqualTo(result.Detail);
        return detail;
    }

    [Test]
    public async Task ANameNoProfileHasIsRefusedAndNothingIsSaved()
    {
        await WithProfilesAsync(async (names, runtime) =>
        {
            var added = await runtime.AddSubscriptionAsync(Input(names, prevProfile: $" {names.Missing} "));

            await (await DetailOf(added)).Should().BeEqualTo(string.Format(ResUI.MsgRoutingRuleTargetNotFound, names.Missing));
            await (await SavedAsync(names)).Should().BeEmpty();
            await (await V2rayRuntime.SubscriptionNamesRefusalAsync(new SubItem { NextProfile = names.Missing }))!.Detail
                .Should().BeEqualTo(string.Format(ResUI.MsgRoutingRuleTargetNotFound, names.Missing));
        });
    }

    [Test]
    public async Task ANameSeveralProfilesHaveIsRefusedAndNothingIsSaved()
    {
        await WithProfilesAsync(async (names, runtime) =>
        {
            var added = await runtime.AddSubscriptionAsync(Input(names, nextProfile: names.Shared));

            await (await DetailOf(added)).Should().BeEqualTo(string.Format(ResUI.MsgRoutingRuleTargetDuplicate, names.Shared));
            await (await SavedAsync(names)).Should().BeEmpty();
            await (await V2rayRuntime.SubscriptionNamesRefusalAsync(new SubItem { PrevProfile = $"{names.Shared} " }))!.Detail
                .Should().BeEqualTo(string.Format(ResUI.MsgRoutingRuleTargetDuplicate, names.Shared));
        });
    }

    [Test]
    public async Task AValidNameAndABlankNameAreSaved()
    {
        await WithProfilesAsync(async (names, runtime) =>
        {
            await (await V2rayRuntime.SubscriptionNamesRefusalAsync(new SubItem())).Should().BeNull();
            await (await V2rayRuntime.SubscriptionNamesRefusalAsync(new SubItem { PrevProfile = " ", NextProfile = string.Empty })).Should().BeNull();
            await (await V2rayRuntime.SubscriptionNamesRefusalAsync(new SubItem { PrevProfile = names.Found.Remarks })).Should().BeNull();

            var added = await runtime.AddSubscriptionAsync(Input(names, prevProfile: $"  {names.Found.Remarks} ", nextProfile: "  "));

            await added.Success.Should().BeTrue();
            await added.Code.Should().BeEqualTo("ok");
            await added.Detail.Should().BeNull();
            await added.Data!.PrevProfile.Should().BeEqualTo($"  {names.Found.Remarks} ");
            // A saved subscription still goes out as the reply's data.
            var reply = JsonSerializer.SerializeToElement(added, WebJson);
            await reply.GetProperty("data").GetProperty("id").GetString().Should().BeEqualTo(added.Data.Id);
            await reply.GetProperty("data").GetProperty("prevProfile").GetString().Should().BeEqualTo($"  {names.Found.Remarks} ");
            await reply.GetProperty("data").TryGetProperty("detail", out _).Should().BeFalse();
            await (await SavedAsync(names)).Count.Should().BeEqualTo(1);
        });
    }

    [Test]
    public async Task AnUpdateIsRefusedForAnUnclearNameAndTheStoredSubscriptionStaysAsItWas()
    {
        await WithProfilesAsync(async (names, runtime) =>
        {
            var added = await runtime.AddSubscriptionAsync(Input(names, prevProfile: names.Found.Remarks));
            await added.Success.Should().BeTrue();
            var id = added.Data!.Id;

            var several = await runtime.UpdateSubscriptionAsync(id, Input(names, prevProfile: names.Found.Remarks, nextProfile: $" {names.Shared}"));
            await (await DetailOf(several)).Should().BeEqualTo(string.Format(ResUI.MsgRoutingRuleTargetDuplicate, names.Shared));
            var none = await runtime.UpdateSubscriptionAsync(id, Input(names, prevProfile: names.Missing));
            await (await DetailOf(none)).Should().BeEqualTo(string.Format(ResUI.MsgRoutingRuleTargetNotFound, names.Missing));

            var stored = await ConfigDbQuery.GetSubItem(id);
            await stored!.PrevProfile.Should().BeEqualTo(names.Found.Remarks);
            await stored.NextProfile.Should().BeNull();

            // A request that leaves the names out keeps the stored ones, and they are looked at as the desktop's editor,
            // which shows and saves them, looks at them: after the profile was renamed away, its name finds none.
            names.Found.Remarks = $"renamed-{names.Suffix}";
            await SQLiteHelper.Instance.ReplaceAsync(names.Found);
            var kept = await runtime.UpdateSubscriptionAsync(id, new SubscriptionInput(names.Subscription, string.Empty));
            await (await DetailOf(kept)).Should().BeEqualTo(string.Format(ResUI.MsgRoutingRuleTargetNotFound, $"found-{names.Suffix}"));

            var cleared = await runtime.UpdateSubscriptionAsync(id, Input(names, prevProfile: string.Empty));
            await cleared.Success.Should().BeTrue();
            await (await ConfigDbQuery.GetSubItem(id))!.PrevProfile.Should().BeEqualTo(string.Empty);
        });
    }
}
