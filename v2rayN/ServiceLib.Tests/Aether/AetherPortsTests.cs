namespace ServiceLib.Tests.Aether;

public class AetherPortsTests
{
    // PattNG AetherCoreManagerTest.profile(): an Aether profile with every option the tests do not change set.
    private static ProfileItem Profile(Func<ProtocolExtraItem, ProtocolExtraItem>? copy = null)
    {
        var extra = new ProtocolExtraItem
        {
            AetherProtocol = AetherProtocol.Masque.Type,
            AetherTransport = AetherTransport.Http3.Type,
            AetherScanMode = AetherScanMode.Verified.Type,
            AetherObfuscation = AetherObfuscation.Aggressive.Type,
            AetherIpVersion = AetherIpVersion.Dual.Type,
        };
        var profile = new ProfileItem { ConfigType = EConfigType.Aether, Remarks = "test" };
        profile.SetProtocolExtra(copy == null ? extra : copy(extra));
        return profile;
    }

    // PattN (E1): the default Aether listen port is 10819, so the core takes 10819..10822 unless the setting names another
    // port: in a new settings file (ConfigTextHandler.LoadConfig stores the default where the value is missing) and wherever a
    // stored value is no such port.
    [Test]
    public async Task TheDefaultAetherListenPortIs10819()
    {
        await AetherPorts.DefaultListenPort.Should().BeEqualTo(10819);
        await new CoreBasicItem().AetherListenPort.Should().BeNull();
        await AetherPorts.ListenPortOf(new CoreBasicItem().AetherListenPort).Should().BeEqualTo(10819);
        await AetherPorts.ListenPortOf((string?)null).Should().BeEqualTo(10819);
        await AetherPorts.SecondarySocksPortOf(AetherPorts.ListenPortOf((int?)null)).Should().BeEqualTo(10822);
    }

    // PattN (E1): with the default mixed port the speed tests pick their ports from 10829 on (the mixed port plus 21), above
    // the default Aether ports, so the port pickers that pass over the core's ports (IsReserved) never pass over one of
    // theirs: the speed tests of other profiles take the ports they took before Aether. 10829, the default for a while,
    // lay on the first four of them.
    [Test]
    public async Task WithTheDefaultPortsNoSpeedTestPortIsTheCoresOwn()
    {
        const int mixed = 10808;
        var firstSpeedTestPort = mixed + (int)EInboundProtocol.speedtest;
        await firstSpeedTestPort.Should().BeEqualTo(10829);
        await (AetherPorts.SecondarySocksPortOf(AetherPorts.DefaultListenPort) < firstSpeedTestPort).Should().BeTrue();
        for (var port = firstSpeedTestPort; port < firstSpeedTestPort + 64; port++)
        {
            await AetherPorts.IsReserved(port, AetherPorts.DefaultListenPort).Should().BeFalse().Because($"port {port}");
            await AetherPorts.Unreserved(port, AetherPorts.DefaultListenPort).Should().BeEqualTo(port);
        }
        // Nor is a default Aether port one of the app's own, the mixed port and the six after it.
        await AetherPorts.ListenPortProblem(AetherPorts.DefaultListenPort.ToString(), AetherPorts.LocalPortsOf(mixed)).Should().BeNull();
    }

    [Test]
    public async Task TheAetherListenPortIsAPortAnAppCanListenOnWithThreeMoreAfterIt()
    {
        await AetherPorts.ListenPortOf(" 20808 ").Should().BeEqualTo(20808);
        await AetherPorts.ListenPortOf("1024").Should().BeEqualTo(1024);
        await AetherPorts.ListenPortOf("65532").Should().BeEqualTo(65532);
        foreach (var text in new[] { null, "", "socks", "0", "80", "1023", "65533", "70000", "-1", "10819.5" })
        {
            await AetherPorts.ListenPortOf(text).Should().BeEqualTo(10819);
        }
    }

    [Test]
    public async Task TheAetherListenPortAndTheThreeAfterItStayClearOfTheLocalProxy()
    {
        int[] local = [10808, 10809];
        await AetherPorts.ListenPortProblem("10819", local).Should().BeNull();
        await AetherPorts.ListenPortProblem(" 10810 ", local).Should().BeNull();
        await AetherPorts.ListenPortProblem("10804", local).Should().BeNull();
        foreach (var text in new[] { "10805", "10806", "10808", "10809" })
        {
            await AetherPorts.ListenPortProblem(text, local).Should().BeEqualTo(AetherListenPortProblem.LocalProxy);
        }
        foreach (var text in new[] { "", "socks", "1023", "65533" })
        {
            await AetherPorts.ListenPortProblem(text, local).Should().BeEqualTo(AetherListenPortProblem.NotAPort);
        }
        // A local proxy on a port picked anew at every start is no matter here.
        await AetherPorts.ListenPortProblem("10808", []).Should().BeNull();
    }

    // PattN: the local ports of PattN are L..L+6 (the local proxy on L and the ports after it), not PattNG's two.
    [Test]
    public async Task TheAetherListenPortAndTheThreeAfterItStayClearOfPattNsLocalPorts()
    {
        var local = Enumerable.Range(10808, 7).ToArray();
        // The listen port P and P+1..P+3 against L..L+6, both ways.
        await AetherPorts.ListenPortProblem("10805", local).Should().BeEqualTo(AetherListenPortProblem.LocalProxy);
        await AetherPorts.ListenPortProblem("10811", local).Should().BeEqualTo(AetherListenPortProblem.LocalProxy);
        await AetherPorts.ListenPortProblem("10814", local).Should().BeEqualTo(AetherListenPortProblem.LocalProxy);
        await AetherPorts.ListenPortProblem("10804", local).Should().BeNull();
        await AetherPorts.ListenPortProblem("10815", local).Should().BeNull();
        await AetherPorts.ListenPortProblem("10819", local).Should().BeNull();
    }

    // PattN: the ports the core of the listen port may take, which the speed test's port pickers skip (design 2.5.1).
    [Test]
    public async Task TheListenPortAndTheThreeAfterItAreTheCoresOwn()
    {
        await AetherPorts.IsReserved(10818, 10819).Should().BeFalse();
        await AetherPorts.IsReserved(10819, 10819).Should().BeTrue();
        await AetherPorts.IsReserved(10820, 10819).Should().BeTrue();
        await AetherPorts.IsReserved(10822, 10819).Should().BeTrue();
        await AetherPorts.IsReserved(10823, 10819).Should().BeFalse();
        await AetherPorts.IsReserved(AetherPorts.SecondarySocksPortOf(20808), 20808).Should().BeTrue();
        // No overflow at the ends of int's range.
        await AetherPorts.IsReserved(int.MinValue, int.MaxValue).Should().BeFalse();
        await AetherPorts.IsReserved(int.MaxValue, int.MinValue).Should().BeFalse();
    }

    [Test]
    public async Task AScanBindsNoPortUnlessTorAroundTheTunnelNeedsARealOne()
    {
        const int p = AetherPorts.DefaultListenPort;
        await AetherPorts.ScanPort(Profile(), p).Should().BeEqualTo(0);
        await AetherPorts.ScanPort(Profile(it => it with { AetherPsiphon = "reverse" }), p).Should().BeEqualTo(0);
        await AetherPorts.ScanPort(Profile(it => it with { AetherTor = "chain" }), p).Should().BeEqualTo(0);
        await (AetherPorts.ScanPort(Profile(it => it with { AetherTor = "reverse" }), p) > 0).Should().BeTrue();
    }

    [Test]
    public async Task TheScanPortAndTorsAfterItStayOffThePortsOfTheAetherCore()
    {
        // PattN (design 2.6.5, as for the exit port and the test ports): a session started beside the scan needs P..P+3.
        const int p = AetherPorts.DefaultListenPort;
        var offered = new Queue<int>([p - 1, p + 3, p, 0, 41000]);
        var port = AetherPorts.ScanPort(Profile(it => it with { AetherTor = "reverse" }), p, () => offered.Dequeue());
        // P-1 would put Tor's listener on P, P+3 the scan's own on the secondary-socks port.
        await port.Should().BeEqualTo(41000);
        await offered.Should().BeEmpty();
        // The Aether listen port the settings name, not the default one.
        await AetherPorts.ScanPort(Profile(it => it with { AetherTor = "reverse" }), 20808, () => p).Should().BeEqualTo(p);
        // The last port of all has no port after it for Tor.
        var high = new Queue<int>([65535, 41001]);
        await AetherPorts.ScanPort(Profile(it => it with { AetherTor = "reverse" }), p, () => high.Dequeue()).Should().BeEqualTo(41001);
    }
}
