namespace ServiceLib.Services.CoreConfig;

public partial class CoreConfigV2rayService
{
    private void GenStatistic()
    {
        // Always set policy levels regardless of statistics settings,
        // level 0 covers inbounds (no userLevel), level 1 covers outbounds
        var levelPolicy = new LevelPolicy4Ray
        {
            handshake = 4,
            connIdle = 300,
            uplinkOnly = 0,
            downlinkOnly = 0
        };
        Policy4Ray policyObj = new()
        {
            levels = new Dictionary<string, LevelPolicy4Ray>
            {
                ["0"] = levelPolicy,
                ["1"] = levelPolicy
            }
        };
        _coreConfig.policy = policyObj;

        if (_config.GuiItem.EnableStatistics || _config.GuiItem.DisplayRealTimeSpeed)
        {
            Metrics4Ray metricsObj = new();
            SystemPolicy4Ray policySystemSetting = new();

            _coreConfig.stats = new Stats4Ray();

            metricsObj.listen = $"{Global.Loopback}:{AppManager.Instance.StatePort}";
            _coreConfig.metrics = metricsObj;

            policySystemSetting.statsOutboundDownlink = true;
            policySystemSetting.statsOutboundUplink = true;
            policyObj.system = policySystemSetting;
        }
    }
}
