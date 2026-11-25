using System.Diagnostics;
using System.Reflection;
using ServiceLib.Common;
using ServiceLib.Enums;
using ServiceLib.Handler.Builder;
using ServiceLib.Helper;
using ServiceLib.Manager;
using ServiceLib.Models.Configs;
using ServiceLib.Models.CoreConfigs;
using ServiceLib.Models.Dto;
using ServiceLib.Models.Entities;
using v2rayN.WebAPI.Contracts;
using v2rayN.WebAPI.Services;

namespace v2rayN.WebAPI.Tests;

// PattN (design 4, W4 and W5; critique 32): a configuration with an Aether profile in it needs the Aether core, which runs
// beside Xray and is tracked by its process id; what the generator refuses for it is refused before the running core
// stops; its exit on its own shows in the runtime state; and what the desktop's editors refuse, the API refuses.
public class AetherRuntimeTests
{
    private static ProfileItem Profile(string id, EConfigType type) => new()
    {
        IndexId = id,
        ConfigType = type,
        CoreType = ECoreType.Xray,
        Remarks = id,
    };

    private static CoreConfigContextBuilderAllResult Built(ProfileItem node, params ProfileItem[] reached)
    {
        var context = new CoreConfigContext
        {
            Node = node,
            RunCoreType = ECoreType.Xray,
            AllProxiesMap = reached.Append(node).ToDictionary(profile => profile.IndexId),
        };
        return new CoreConfigContextBuilderAllResult(new CoreConfigContextBuilderResult(context, NodeValidatorResult.Empty()), null);
    }

    [Test]
    public async Task AnAetherProfileNeedsTheAetherCoreBesideXray()
    {
        var asked = new List<ECoreType>();
        var preflight = CoreLaunchPreflight.Validate(new ProfileItem(), Built(Profile("warp", EConfigType.Aether)), coreType =>
        {
            asked.Add(coreType);
            return null;
        });

        await preflight.Success.Should().BeTrue();
        await asked.SequenceEqual([ECoreType.Xray, ECoreType.aether]).Should().BeTrue();
    }

    [Test]
    public async Task AnAetherProfileAGroupOrRuleReachesNeedsTheAetherCoreToo()
    {
        var built = Built(Profile("group", EConfigType.PolicyGroup), Profile("vless", EConfigType.VLESS), Profile("warp", EConfigType.Aether));

        await CoreLaunchPreflight.NeedsAether(built).Should().BeTrue();
    }

    [Test]
    public async Task AStartWithoutTheAetherCoreKeepsWhatRuns()
    {
        var preflight = CoreLaunchPreflight.Validate(new ProfileItem(), Built(Profile("warp", EConfigType.Aether)), coreType =>
            coreType == ECoreType.aether
                ? OperationView.Fail("core_binary_missing", ApiMessageKeys.CoreBinaryMissing, new { coreType = coreType.ToString() })
                : null);

        await preflight.Success.Should().BeFalse();
        await preflight.Failure!.Code.Should().BeEqualTo("core_binary_missing");
    }

    [Test]
    public async Task AConfigurationWithoutAnAetherProfileDoesNotAskForTheAetherCore()
    {
        var asked = new List<ECoreType>();
        var built = Built(Profile("group", EConfigType.PolicyGroup), Profile("vless", EConfigType.VLESS));

        CoreLaunchPreflight.Validate(new ProfileItem(), built, coreType =>
        {
            asked.Add(coreType);
            return null;
        });

        await CoreLaunchPreflight.NeedsAether(built).Should().BeFalse();
        await asked.SequenceEqual([ECoreType.Xray]).Should().BeTrue();
    }

    // The session's core is tracked by the process id its manager knows: tests run the same program without a
    // configuration file to tell them apart by, so no Aether process is claimed by its program (design 4, W5).
    [Test]
    public async Task TheAetherSessionCoreIsTrackedByItsProcessIdAlone()
    {
        var startInfo = OperatingSystem.IsWindows()
            ? new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "PING.EXE")) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true }
            : new ProcessStartInfo("/bin/sleep") { UseShellExecute = false };
        foreach (var argument in OperatingSystem.IsWindows() ? ["-n", "60", "127.0.0.1"] : new[] { "60" })
        {
            startInfo.ArgumentList.Add(argument);
        }
        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start the test process.");
        try
        {
            var identity = CoreProcessTracker.CaptureProcess(process.Id).Single();
            await identity.ProcessId.Should().BeEqualTo(process.Id);
            await CoreProcessTracker.GetActiveProcesses([identity]).Select(active => active.ProcessId).Should().Contain(process.Id);
            await CoreProcessTracker.CaptureProcess(null).Should().BeEmpty();

            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();

            await CoreProcessTracker.GetActiveProcesses([identity]).Should().BeEmpty();
            await CoreProcessTracker.CaptureProcess(process.Id).Should().BeEmpty();
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
            }
        }
    }

    [Test]
    public async Task ACustomConfigurationNeedsNoAetherCoreWhateverItsRulesReach()
    {
        // A custom configuration runs as written: its generation starts no Aether core, though the builder resolves the
        // routing rules for it as for any main profile.
        var built = Built(Profile("custom", EConfigType.Custom), Profile("warp", EConfigType.Aether));
        var asked = new List<ECoreType>();

        var preflight = CoreLaunchPreflight.Validate(new ProfileItem(), built, coreType =>
        {
            asked.Add(coreType);
            return null;
        });

        await CoreLaunchPreflight.NeedsAether(built).Should().BeFalse();
        await preflight.Success.Should().BeTrue();
        await asked.Contains(ECoreType.aether).Should().BeFalse();
    }

    // Design 2.7.5: what the generator refuses for the Aether core (an exit-node no profile has, two Aether profiles, a
    // port taken) is refused before the running core stops, as on the desktop, and in the generator's words.
    [Test]
    public async Task AStartTheGeneratorRefusesLeavesTheRunningCoreAlone()
    {
        var built = Built(Profile("warp", EConfigType.Aether));
        var generated = new List<string>();
        var refusal = await CoreLaunchPreflight.AetherRefusalAsync(built, context =>
        {
            generated.Add(context.Node.IndexId);
            return Task.FromResult(new RetResult(false, "No profile named \"germany\" was found"));
        });
        await refusal.Should().BeEqualTo("No profile named \"germany\" was found");
        await generated.SequenceEqual(["warp"]).Should().BeTrue();

        var preflight = CoreLaunchPreflight.Validate(new ProfileItem(), built, _ => null);
        var refused = preflight with { Failure = CoreLaunchPreflight.AetherRefused(refusal!) };
        var stopped = false;
        var result = await CoreRestartFlow.ExecuteAsync(
            () => Task.FromResult(refused),
            () =>
            {
                stopped = true;
                return Task.CompletedTask;
            },
            () => { },
            _ => Task.FromResult(OperationView.Ok(ApiMessageKeys.CoreStarted)));

        await stopped.Should().BeFalse();
        await result.Success.Should().BeFalse();
        await result.Code.Should().BeEqualTo("core_config_refused");
        await result.MessageKey.Should().BeEqualTo(ApiMessageKeys.ProfileInvalid);
        await System.Text.Json.JsonSerializer.Serialize(result.Data).Should().Contain("germany");

        // A configuration the generator accepts, or one without an Aether core, is not refused; the latter is not generated.
        await (await CoreLaunchPreflight.AetherRefusalAsync(built, _ => Task.FromResult(new RetResult(true, "ok")))).Should().BeNull();
        var plain = Built(Profile("vless", EConfigType.VLESS));
        await (await CoreLaunchPreflight.AetherRefusalAsync(plain, _ => throw new InvalidOperationException("generated"))).Should().BeNull();
    }

    // Critique 32: an Aether core that exits on its own while a start waits for its listener (at once, on a missing DLL, a
    // refused key or a port taken) fails that start in the core's own words.
    [Test]
    public async Task AnAetherCoresEndDuringAStartIsThatStartsFailure()
    {
        var notice = new AetherCoreStopNotice();
        var starting = CoreRuntimeSnapshot.Stopped with { State = CoreRuntimeState.Starting, ProfileId = "warp" };

        await notice.Apply(() => starting, "The Aether core could not start").Should().BeNull();
        await notice.Take().Should().BeEqualTo("The Aether core could not start");
        await notice.Take().Should().BeNull();

        // What came before the start is no failure of it.
        await notice.Apply(() => starting with { State = CoreRuntimeState.Restarting }, "The Aether core stopped running").Should().BeNull();
        notice.Clear();
        await notice.Take().Should().BeNull();

        // A running core is faulted at once.
        var running = starting with { State = CoreRuntimeState.Running };
        var faulted = notice.Apply(() => running, "The Aether core stopped running");
        await faulted!.State.Should().BeEqualTo(CoreRuntimeState.Faulted);
        await faulted.LastFailure.Should().BeEqualTo("The Aether core stopped running");
        await notice.Take().Should().BeNull();

        // A start that set Running between the two readings, and found nothing to take, gets the words here.
        var readings = new Queue<CoreRuntimeSnapshot>([starting, running]);
        var late = notice.Apply(() => readings.Count > 1 ? readings.Dequeue() : readings.Peek(), "The Aether core stopped running");
        await late!.State.Should().BeEqualTo(CoreRuntimeState.Faulted);
        await notice.Take().Should().BeNull();
    }

    // The desktop's group, chain and subscription editors refuse what an Aether profile cannot be part of; so does the API.
    [Test]
    [NotInParallel]
    public async Task TheApiRefusesTheGroupsChainsAndSubscriptionsTheEditorsRefuse()
    {
        var state = ConfigState.Instance;
        var configField = typeof(ConfigState).GetField("_current", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new MissingFieldException(typeof(ConfigState).FullName, "_current");
        var previousConfig = configField.GetValue(state);
        var suffix = Guid.NewGuid().ToString("N");
        var stored = new List<ProfileItem>();
        try
        {
            configField.SetValue(state, new Config { SubIndexId = string.Empty });
            SQLiteHelper.Instance.CreateTable<ProfileItem>();
            SQLiteHelper.Instance.CreateTable<SubItem>();
            ProfileItem Stored(string name, EConfigType type)
            {
                var profile = new ProfileItem
                {
                    IndexId = $"{name}-{suffix}",
                    ConfigType = type,
                    CoreType = ECoreType.Xray,
                    Remarks = $"{name}-{suffix}",
                    Address = "203.0.113.7",
                    Port = 443,
                };
                stored.Add(profile);
                return profile;
            }
            var warp = Stored("warp", EConfigType.Aether);
            var wg = Stored("wg", EConfigType.Aether);
            var vless = Stored("vless", EConfigType.VLESS);
            foreach (var profile in stored)
            {
                await SQLiteHelper.Instance.ReplaceAsync(profile);
            }
            var runtime = new V2rayRuntime(null!, null!, null!, null!, null!);

            ProfileItem Chain(ECoreType coreType, params ProfileItem[] hops)
            {
                var chain = new ProfileItem { ConfigType = EConfigType.ProxyChain, CoreType = coreType, Remarks = $"chain-{suffix}" };
                chain.SetProtocolExtra(new ProtocolExtraItem { ChildItems = Utils.List2String(hops.Select(hop => hop.IndexId).ToList()) });
                return chain;
            }

            var twoAether = await runtime.SaveProfileAsync(Chain(ECoreType.Xray, warp, vless, wg));
            await twoAether.Success.Should().BeFalse();
            await twoAether.Code.Should().BeEqualTo("profile_group_aether_invalid");
            await System.Text.Json.JsonSerializer.Serialize(twoAether.Data).Should().Contain("detail");
            var singBox = await runtime.SaveProfileAsync(Chain(ECoreType.sing_box, vless, warp));
            await singBox.Code.Should().BeEqualTo("profile_group_aether_invalid");
            await (await ConfigDbQuery.GetProfileItemViaRemarks($"chain-{suffix}")).Should().BeNull();

            var subscription = await runtime.AddSubscriptionAsync(new SubscriptionInput(
                $"sub-{suffix}", string.Empty, MoreUrl: string.Empty, Enabled: false, AutoUpdateInterval: 0,
                PrevProfile: warp.Remarks, NextProfile: wg.Remarks));
            await subscription.Success.Should().BeFalse();
            await subscription.Code.Should().BeEqualTo("subscription_aether_chain_invalid");
        }
        finally
        {
            foreach (var profile in stored)
            {
                await SQLiteHelper.Instance.DeleteAsync(profile);
            }
            configField.SetValue(state, previousConfig);
        }
    }

    [Test]
    public async Task ARunningCoreStoppedForItsAetherCoreIsFaultedInTheCoresWords()
    {
        var running = new CoreRuntimeSnapshot(CoreRuntimeState.Running, "warp", ECoreType.Xray, DateTimeOffset.UtcNow, 10808, 10813, [], [42], null);

        var faulted = V2rayRuntime.AetherStoppedRuntime(running, "The Aether core stopped running");

        await faulted!.State.Should().BeEqualTo(CoreRuntimeState.Faulted);
        await faulted.LastFailure.Should().BeEqualTo("The Aether core stopped running");
        await faulted.ProfileId.Should().BeEqualTo("warp");
        // The monitor may have found the processes gone first; the core's own words say more.
        var found = running with { State = CoreRuntimeState.Faulted, LastFailure = "The tracked Core child process exited unexpectedly." };
        await V2rayRuntime.AetherStoppedRuntime(found, "The Aether core stopped running")!.LastFailure
            .Should().BeEqualTo("The Aether core stopped running");
    }

    [Test]
    public async Task AStartOrAStopOwnsTheRuntimeStateItSets()
    {
        foreach (var state in new[] { CoreRuntimeState.Stopped, CoreRuntimeState.Starting, CoreRuntimeState.Stopping, CoreRuntimeState.Restarting })
        {
            var snapshot = CoreRuntimeSnapshot.Stopped with { State = state };
            await V2rayRuntime.AetherStoppedRuntime(snapshot, "The Aether core stopped running").Should().BeNull();
        }
    }
}
