using ServiceLib.Handler.Builder;
using v2rayN.WebAPI.Contracts;

namespace v2rayN.WebAPI.Services;

internal sealed record CoreLaunchPreflightResult(
    ProfileItem Profile,
    CoreConfigContextBuilderAllResult BuiltContext,
    OperationView? Failure)
{
    public bool Success => Failure is null;
}

internal static class CoreLaunchPreflight
{
    public static async Task<CoreLaunchPreflightResult> BuildAndValidateAsync(
        Config config,
        ProfileItem profile,
        Func<ECoreType, OperationView?> validateCoreBinary)
    {
        var built = await CoreConfigContextBuilder.BuildAll(config, profile);
        return Validate(profile, built, validateCoreBinary);
    }

    internal static CoreLaunchPreflightResult Validate(
        ProfileItem profile,
        CoreConfigContextBuilderAllResult built,
        Func<ECoreType, OperationView?> validateCoreBinary)
    {
        var tunRejection = GetTunLaunchRejection(built);
        if (tunRejection is not null)
        {
            return new CoreLaunchPreflightResult(profile, built, tunRejection);
        }

        if (!built.Success)
        {
            return new CoreLaunchPreflightResult(profile, built,
                OperationView.Fail("profile_validation_failed", ApiMessageKeys.ProfileInvalid));
        }

        var requiredCoreTypes = new[]
            {
                (ECoreType?)built.MainResult.Context.RunCoreType,
                built.PreSocksResult?.Context.RunCoreType,
                // PattN: a configuration with an Aether profile in it runs the Aether core beside Xray (design 4, W4)
                NeedsAether(built) ? ECoreType.aether : null,
            }
            .Where(coreType => coreType.HasValue)
            .Select(coreType => coreType!.Value)
            .Distinct();

        foreach (var coreType in requiredCoreTypes)
        {
            var failure = validateCoreBinary(coreType);
            if (failure is not null)
            {
                return new CoreLaunchPreflightResult(profile, built, failure);
            }
        }

        return new CoreLaunchPreflightResult(profile, built, null);
    }

    /// <summary>
    /// PattN: whether the built main context holds an Aether profile, as its node or among the profiles its groups, chains
    /// and routing rules reach: its configuration then needs the Aether core, whose program must be there. A custom
    /// configuration runs as it is written, and starts no Aether core whatever its routing rules reach.
    /// </summary>
    internal static bool NeedsAether(CoreConfigContextBuilderAllResult built)
    {
        var context = built.MainResult.Context;
        if (context.Node.ConfigType == EConfigType.Custom)
        {
            return false;
        }
        return context.Node.ConfigType == EConfigType.Aether
               || context.AllProxiesMap.Values.Any(profile => profile.ConfigType == EConfigType.Aether);
    }

    /// <summary>
    /// PattN (design 2.7.5): why the configuration of <paramref name="built" />, which needs the Aether core, cannot run,
    /// as the generator <paramref name="generate" /> says it (an exit-node no profile or several have, two Aether profiles,
    /// a port taken, ...); null when it can, or when no Aether core is needed. The generator says so only once it runs,
    /// and a start stops the running core before it generates: this runs it first, so that a refused start leaves the
    /// running core alone, as on the desktop. The configuration is generated again for the start.
    /// </summary>
    internal static async Task<string?> AetherRefusalAsync(
        CoreConfigContextBuilderAllResult built,
        Func<CoreConfigContext, Task<RetResult>> generate)
    {
        if (!NeedsAether(built))
        {
            return null;
        }
        var result = await generate(built.MainResult.Context);
        return result.Success == true ? null : result.Msg;
    }

    /// <summary>PattN: the failure of a start <see cref="AetherRefusalAsync" /> refused with <paramref name="message" />.</summary>
    internal static OperationView AetherRefused(string message) =>
        OperationView.Fail("core_config_refused", ApiMessageKeys.ProfileInvalid, new { detail = message });

    internal static OperationView? GetTunLaunchRejection(CoreConfigContextBuilderAllResult built) =>
        built.MainResult.Context.IsTunEnabled || built.PreSocksResult?.Context.IsTunEnabled == true
            ? OperationView.Fail("tun_not_supported", ApiMessageKeys.CoreTunNotSupported)
            : null;
}

internal static class CoreRestartFlow
{
    public static async Task<OperationView> ExecuteAsync(
        Func<Task<CoreLaunchPreflightResult>> buildAndValidate,
        Func<Task> stopCore,
        Action markCoreStopped,
        Func<CoreLaunchPreflightResult, Task<OperationView>> launch)
    {
        var preflight = await buildAndValidate();
        if (preflight.Failure is { } failure)
        {
            return failure;
        }

        await stopCore();
        markCoreStopped();
        var startResult = await launch(preflight);
        return startResult.Success
            ? OperationView.Ok(ApiMessageKeys.CoreRestarted, startResult.Data)
            : startResult;
    }
}
