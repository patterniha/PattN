namespace ServiceLib.Handler;

/// <summary>
/// Core configuration file processing class
/// </summary>
public static class CoreConfigHandler
{
    private static readonly string _tag = "CoreConfigHandler";

    public static async Task<RetResult> GenerateClientConfig(CoreConfigContext context, string? fileName)
    {
        var config = ConfigTextHandler.Config;
        var result = new RetResult();
        var node = context.Node;

        if (node.ConfigType == EConfigType.Custom)
        {
            result = node.CoreType switch
            {
                ECoreType.mihomo => await new CoreConfigClashService(config, context.IsTunEnabled).GenerateClientCustomConfig(node, fileName),
                _ => await GenerateClientCustomConfig(node, fileName)
            };
        }
        else if (context.RunCoreType == ECoreType.sing_box)
        {
            result = new CoreConfigSingboxService(context).GenerateClientConfigContent();
        }
        else
        {
            result = new CoreConfigV2rayService(context).GenerateClientConfigContent();
        }
        if (result.Success != true)
        {
            return result;
        }
        if (fileName.IsNotEmpty() && result.Data != null)
        {
            await File.WriteAllTextAsync(fileName, result.Data.ToString());
        }

        return result;
    }

    private static async Task<RetResult> GenerateClientCustomConfig(ProfileItem node, string? fileName)
    {
        var ret = new RetResult();
        try
        {
            if (node == null || fileName is null)
            {
                ret.Msg = ResUI.CheckServerSettings;
                return ret;
            }

            if (File.Exists(fileName))
            {
                File.SetAttributes(fileName, FileAttributes.Normal); //If the file has a read-only attribute, direct deletion will fail
                File.Delete(fileName);
            }

            var addressFileName = node.Address;
            if (!File.Exists(addressFileName))
            {
                addressFileName = Utils.GetConfigPath(addressFileName);
            }
            if (!File.Exists(addressFileName))
            {
                var message = $"{ResUI.FailedReadConfiguration}: {addressFileName}";
                Logging.SaveLog($"{_tag}: {message}");
                ret.Msg = message;
                return ret;
            }
            File.Copy(addressFileName, fileName);
            File.SetAttributes(fileName, FileAttributes.Normal); //Copy will keep the attributes of addressFileName, so we need to add write permissions to fileName just in case of addressFileName is a read-only file.

            //check again
            if (!File.Exists(fileName))
            {
                var message = $"{ResUI.FailedReadConfiguration}: {fileName}";
                Logging.SaveLog($"{_tag}: {message}");
                ret.Msg = message;
                return ret;
            }

            ret.Msg = string.Format(ResUI.SuccessfulConfiguration, "");
            ret.Success = true;
            return await Task.FromResult(ret);
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
            ret.Msg = ResUI.FailedGenDefaultConfiguration;
            return ret;
        }
    }

    public static async Task<RetResult> GenerateClientSpeedtestConfig(Config config, string fileName, List<ServerTestItem> selecteds, ECoreType coreType)
    {
        var result = new RetResult();
        var dummyNode = new ProfileItem
        {
            CoreType = coreType
        };
        // PattN: a test drops the routing rules, so their targets never refuse it, nor log that they would (E2)
        var builderResult = await CoreConfigContextBuilder.Build(config, dummyNode, refuseRuleTargets: false);
        var context = builderResult.Context;
        // PattN: the profiles that cannot be resolved, which are left out of the test (N1)
        var unresolved = new HashSet<ServerTestItem>(ReferenceEqualityComparer.Instance);
        foreach (var testItem in selecteds)
        {
            var node = testItem.Profile;
            var (actNode, resolved) = await CoreConfigContextBuilder.ResolveNodeAsync(context, node, true);
            // PattN: a profile that cannot be resolved is not tested, as when upstream finds no outbound of it: a chain its
            // subscription names a hop of that no profile has, or several have, is refused (N1), and the profile, which
            // another one's chain may have put in the context, would otherwise be measured without that hop
            if (!resolved.Success)
            {
                Logging.SaveLog($"Speedtest: '{node.Remarks}' is not tested: {string.Join("; ", resolved.Errors)}");
                testItem.AllowTest = false;
                unresolved.Add(testItem);
                continue;
            }
            if (node.IndexId == actNode.IndexId)
            {
                continue;
            }
            context.ServerTestItemMap[node.IndexId] = actNode.IndexId;
        }
        // PattN
        var testable = unresolved.Count == 0 ? selecteds : selecteds.Where(testItem => !unresolved.Contains(testItem)).ToList();
        if (coreType == ECoreType.sing_box)
        {
            result = new CoreConfigSingboxService(context).GenerateClientSpeedtestConfig(testable);
        }
        else if (coreType == ECoreType.Xray)
        {
            result = new CoreConfigV2rayService(context).GenerateClientSpeedtestConfig(testable);
        }
        if (result.Success != true)
        {
            return result;
        }
        await File.WriteAllTextAsync(fileName, result.Data.ToString());
        return result;
    }

    public static async Task<RetResult> GenerateClientSpeedtestConfig(Config config, CoreConfigContext context, ServerTestItem testItem, string fileName)
    {
        var result = new RetResult();
        var initPort = AppManager.Instance.GetLocalPort(EInboundProtocol.speedtest);
        var port = Utils.GetFreePort(initPort + testItem.QueueNum);
        // PattN: never a port the Aether core may take: the session's or a latency test's core may need it (design 2.12)
        port = AetherPorts.Unreserved(port, AetherPorts.ListenPortOf(config.CoreBasicItem.AetherListenPort));
        testItem.Port = port;

        if (context.RunCoreType == ECoreType.sing_box)
        {
            result = new CoreConfigSingboxService(context).GenerateClientSpeedtestConfig(port);
        }
        else
        {
            result = new CoreConfigV2rayService(context).GenerateClientSpeedtestConfig(port);
        }
        if (result.Success != true)
        {
            return result;
        }

        await File.WriteAllTextAsync(fileName, result.Data.ToString());
        return result;
    }
}
