using System.Reflection;
using ServiceLib.Aether;
using ServiceLib.Enums;
using ServiceLib.Manager;
using ServiceLib.Models.Configs;
using v2rayN.WebAPI.Contracts;
using v2rayN.WebAPI.Services;

namespace v2rayN.WebAPI.Tests;

// PattN (design 2.5.1 and 4, W7): the API does not edit the Aether listen port P, but it refuses to move the mixed port L
// so that one of the local ports of the app, L and the six after it, is P or one of the three ports after it, which the
// Aether core takes; the desktop settings refuse the same. A mixed port left as it is never counts, so a settings file in
// which the two overlap already keeps its other inbound settings editable here.
[NotInParallel]
public class AetherInboundPortTests
{
    private const int L = 10808;
    private const int P = AetherPorts.DefaultListenPort;

    private static Config NewConfig(int localPort = L, int? aetherListenPort = P) => new()
    {
        CoreBasicItem = new CoreBasicItem { AetherListenPort = aetherListenPort },
        Inbound = [new InItem { Protocol = nameof(EInboundProtocol.socks), LocalPort = localPort }],
    };

    private static InboundSettingsInput Inbound(int localPort) => new(
        localPort, false, true, true, ["http", "tls"], false, false, false, string.Empty, string.Empty);

    [Test]
    public async Task AMixedPortWhoseLocalPortsReachTheAetherPortsIsMovedOntoThem()
    {
        var config = NewConfig();
        // L+6 reaching P from below, and L inside P..P+3.
        foreach (var localPort in new[] { P - 6, P - 3, P, P + 3 })
        {
            await V2rayRuntime.MovesMixedPortOntoAetherPorts(config, localPort).Should().BeTrue().Because($"L = {localPort}");
        }
        foreach (var localPort in new[] { P - 7, P + 4, 20000 })
        {
            await V2rayRuntime.MovesMixedPortOntoAetherPorts(config, localPort).Should().BeFalse().Because($"L = {localPort}");
        }
        // The Aether listen port the cores use: the default for a stored value that is no such port.
        await V2rayRuntime.MovesMixedPortOntoAetherPorts(NewConfig(aetherListenPort: 80), P - 3).Should().BeTrue();
        await V2rayRuntime.MovesMixedPortOntoAetherPorts(NewConfig(aetherListenPort: null), P - 3).Should().BeTrue();
        await V2rayRuntime.MovesMixedPortOntoAetherPorts(NewConfig(aetherListenPort: 20808), P - 3).Should().BeFalse();
        await V2rayRuntime.MovesMixedPortOntoAetherPorts(NewConfig(aetherListenPort: 20808), 20808 - 6).Should().BeTrue();
    }

    [Test]
    public async Task AStartupProxyPortOnTheAetherPortsIsToldNotRefused()
    {
        // V2RAYN_WEB_PROXY_PORT writes the mixed port at every start, which W7 never sees; the API cannot move the Aether
        // listen port either. The start goes on, and says why Aether profiles will not start.
        var config = NewConfig();
        var warning = V2rayRuntime.ProxyPortOverrideWarning(config, P - 4);
        await (warning != null).Should().BeTrue();
        await warning!.Should().Contain($"V2RAYN_WEB_PROXY_PORT={P - 4}");
        await warning.Should().Contain($"{P}-{P + 3}");
        // Already in the settings file as well: an override equal to the stored mixed port is told all the same.
        await (V2rayRuntime.ProxyPortOverrideWarning(NewConfig(localPort: P - 4), P - 4) != null).Should().BeTrue();
        foreach (var localPort in new[] { P - 7, P + 4, L })
        {
            await V2rayRuntime.ProxyPortOverrideWarning(config, localPort).Should().BeNull().Because($"L = {localPort}");
        }
        // The Aether listen port the cores use.
        await V2rayRuntime.ProxyPortOverrideWarning(NewConfig(aetherListenPort: 20808), P - 4).Should().BeNull();
        await (V2rayRuntime.ProxyPortOverrideWarning(NewConfig(aetherListenPort: 20808), 20808 - 6) != null).Should().BeTrue();
    }

    [Test]
    public async Task AMixedPortLeftAsItIsIsNeverRefused()
    {
        await V2rayRuntime.MovesMixedPortOntoAetherPorts(NewConfig(localPort: P - 3), P - 3).Should().BeFalse();
        await V2rayRuntime.MovesMixedPortOntoAetherPorts(null, P).Should().BeFalse();
    }

    [Test]
    public async Task TheInboundSettingsRefuseAMixedPortOnTheAetherPortsWithACodeOfTheirOwn()
    {
        var config = NewConfig();
        await WithConfig(config, async () =>
        {
            var runtime = new V2rayRuntime(null!, null!, null!, null!, null!);

            var inbound = await runtime.UpdateInboundSettingsAsync(Inbound(P - 3));
            var all = await runtime.ApplySettingsAsync(new SettingsApplyInput(Inbound(P), null!, null!, null!, [], null, null));

            foreach (var result in new[] { inbound, all })
            {
                await result.Success.Should().BeFalse();
                await result.Code.Should().BeEqualTo("inbound_port_aether_reserved");
                await result.MessageKey.Should().BeEqualTo(ApiMessageKeys.SettingsAetherPortsTaken);
            }
            await ApiMessageKeys.SettingsAetherPortsTaken.Should().BeEqualTo("settings.aetherPortsTaken");
            // Nothing was written.
            await config.Inbound[0].LocalPort.Should().BeEqualTo(L);
            await config.CoreBasicItem.AetherListenPort.Should().BeEqualTo(P);
        });
    }

    private static async Task WithConfig(Config config, Func<Task> run)
    {
        var field = typeof(ConfigState).GetField("_current", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var previous = field.GetValue(ConfigState.Instance);
        field.SetValue(ConfigState.Instance, config);
        try
        {
            await run();
        }
        finally
        {
            field.SetValue(ConfigState.Instance, previous);
        }
    }
}
