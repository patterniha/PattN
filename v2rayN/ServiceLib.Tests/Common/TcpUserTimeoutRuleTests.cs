using ServiceLib.Tests.CoreConfig;

namespace ServiceLib.Tests.Common;

/// <summary>
/// PattN (PattNG TcpUserTimeoutRuleTest): where the tcpUserTimeout of a profile counts, which is only where the
/// connection of its outbound is TCP as the fork core dials it, and how a link's or a field's text is read.
/// </summary>
public class TcpUserTimeoutRuleTests
{
    [Test]
    [Arguments(EConfigType.VMess, "raw", "", "")]
    [Arguments(EConfigType.VMess, "", "", "")]
    [Arguments(EConfigType.VLESS, "ws", "tls", "h2")]
    [Arguments(EConfigType.VLESS, "grpc", "tls", "h3")]
    [Arguments(EConfigType.VLESS, "httpupgrade", "tls", "")]
    [Arguments(EConfigType.VLESS, "xhttp", "tls", "h2")]
    [Arguments(EConfigType.VLESS, "xhttp", "tls", "h3,h2")]
    [Arguments(EConfigType.VLESS, "xhttp", "reality", "h3")]
    [Arguments(EConfigType.VLESS, "xhttp", "", "h3")]
    [Arguments(EConfigType.VLESS, "xdrive", "tls", "")]
    [Arguments(EConfigType.Trojan, "raw", "tls", "")]
    [Arguments(EConfigType.Shadowsocks, "raw", "", "")]
    [Arguments(EConfigType.SOCKS, "raw", "", "")]
    [Arguments(EConfigType.HTTP, "ws", "", "")]
    [Arguments(EConfigType.MASQUE, "raw", "tls", "h2")]
    [Arguments(EConfigType.MASQUE, "raw", "tls", "h2,http/1.1")]
    public async Task ATcpConnectionTakesIt(EConfigType type, string network, string security, string alpn)
    {
        // Only XHTTP and xdrive dial QUIC for h3, and only with TLS; REALITY keeps XHTTP on HTTP/2.
        await TcpUserTimeoutRule.Applies(type, network, security, alpn).Should().BeTrue();
    }

    [Test]
    [Arguments(EConfigType.WireGuard, "raw", "", "")]
    [Arguments(EConfigType.Hysteria2, "raw", "tls", "h3")]
    [Arguments(EConfigType.MASQUE, "raw", "tls", "h3")]
    [Arguments(EConfigType.MASQUE, "raw", "tls", "h3,h2")]
    [Arguments(EConfigType.MASQUE, "raw", "tls", "")]
    [Arguments(EConfigType.VLESS, "kcp", "", "")]
    [Arguments(EConfigType.VMess, "kcp", "tls", "h2")]
    [Arguments(EConfigType.VLESS, "xhttp", "tls", "h3")]
    [Arguments(EConfigType.VMess, "xdrive", "tls", "h3")]
    [Arguments(EConfigType.TUIC, "raw", "tls", "")]
    [Arguments(EConfigType.Naive, "raw", "tls", "")]
    [Arguments(EConfigType.Anytls, "raw", "tls", "")]
    [Arguments(EConfigType.Aether, "raw", "", "")]
    public async Task AUdpConnectionOrATypeXrayDoesNotDialDoesNot(EConfigType type, string network, string security, string alpn)
    {
        // An Aether profile goes by its core instead (AetherCore.ConnectsOverTcp).
        await TcpUserTimeoutRule.Applies(type, network, security, alpn).Should().BeFalse();
    }

    [Test]
    public async Task TheValueIsTheProfilesWhereItCountsAndIsAboveZero()
    {
        var vmess = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray);
        vmess.TcpUserTimeout = 10000;
        await TcpUserTimeoutRule.ValueOf(vmess).Should().BeEqualTo(10000);

        vmess.Network = nameof(ETransport.kcp);
        await TcpUserTimeoutRule.ValueOf(vmess).Should().BeNull();
        vmess.Network = nameof(ETransport.raw);
        vmess.TcpUserTimeout = 0;
        await TcpUserTimeoutRule.ValueOf(vmess).Should().BeNull();
        vmess.TcpUserTimeout = -5;
        await TcpUserTimeoutRule.ValueOf(vmess).Should().BeNull();
        vmess.TcpUserTimeout = null;
        await TcpUserTimeoutRule.ValueOf(vmess).Should().BeNull();

        var wireguard = CoreConfigTestFactory.CreateWireguardNode(ECoreType.Xray);
        wireguard.TcpUserTimeout = 10000;
        await TcpUserTimeoutRule.ValueOf(wireguard).Should().BeNull();
    }

    [Test]
    [Arguments("10000", 10000)]
    [Arguments(" 2000 ", 2000)]
    [Arguments("+20", 20)]
    [Arguments("1", 1)]
    [Arguments("2147483647", int.MaxValue)]
    public async Task ParseTakesAWholeNumberAboveZero(string text, int expected)
    {
        await TcpUserTimeoutRule.Parse(text).Should().BeEqualTo(expected);
    }

    [Test]
    [Arguments(null)]
    [Arguments("")]
    [Arguments(" ")]
    [Arguments("0")]
    [Arguments("-5")]
    [Arguments("1.5")]
    [Arguments("2s")]
    [Arguments("1 000")]
    [Arguments("abc")]
    [Arguments("2147483648")]
    public async Task ParseLeavesAnythingElseUnset(string? text)
    {
        await TcpUserTimeoutRule.Parse(text).Should().BeNull();
    }

    [Test]
    public async Task AnAetherCoreConnectsOverTcpThroughTorOrPsiphonOrMasqueOverHttp2()
    {
        static bool Over(AetherProtocol protocol, AetherTransport transport, AetherTor? tor = null, AetherPsiphon? psiphon = null)
        {
            return AetherArguments.ConnectsOverTcp(protocol, transport, tor ?? AetherTor.Off, psiphon ?? AetherPsiphon.Off);
        }

        // WARP alone: only a tunnel over MASQUE that runs over HTTP/2.
        await Over(AetherProtocol.Masque, AetherTransport.Http2).Should().BeTrue();
        await Over(AetherProtocol.Mim, AetherTransport.Http2).Should().BeTrue();
        await Over(AetherProtocol.WgOverMasque, AetherTransport.Http2).Should().BeTrue();
        await Over(AetherProtocol.Masque, AetherTransport.Http3).Should().BeFalse();
        await Over(AetherProtocol.Mim, AetherTransport.Http3).Should().BeFalse();
        // The transport is MASQUE's alone: WireGuard and WARP-in-WARP reach WARP over UDP whatever it says.
        await Over(AetherProtocol.WireGuard, AetherTransport.Http2).Should().BeFalse();
        await Over(AetherProtocol.Gool, AetherTransport.Http2).Should().BeFalse();
        // Tor or Psiphon around the tunnel carry TCP alone, and the core takes HTTP/2 for it.
        await Over(AetherProtocol.Masque, AetherTransport.Http3, AetherTor.Reverse).Should().BeTrue();
        await Over(AetherProtocol.Masque, AetherTransport.Http3, psiphon: AetherPsiphon.Reverse).Should().BeTrue();
        // Inside the tunnel they leave the tunnel's own connection as it is.
        await Over(AetherProtocol.Masque, AetherTransport.Http3, AetherTor.Chain).Should().BeFalse();
        await Over(AetherProtocol.WireGuard, AetherTransport.Http3, psiphon: AetherPsiphon.Chain).Should().BeFalse();
        await Over(AetherProtocol.Masque, AetherTransport.Http2, AetherTor.Chain).Should().BeTrue();
        // Alone they are the whole of it.
        await Over(AetherProtocol.WireGuard, AetherTransport.Http3, AetherTor.Only).Should().BeTrue();
        await Over(AetherProtocol.WireGuard, AetherTransport.Http3, psiphon: AetherPsiphon.Only).Should().BeTrue();
    }

    [Test]
    public async Task TheMasqueTransportOfACommandIsTheLastFlagAsTheCoreReadsIt()
    {
        await AetherArguments.MasqueTransportOf([]).Should().BeEqualTo(AetherTransport.Http3);
        await AetherArguments.MasqueTransportOf(["--h2"]).Should().BeEqualTo(AetherTransport.Http2);
        await AetherArguments.MasqueTransportOf(["--http2"]).Should().BeEqualTo(AetherTransport.Http2);
        await AetherArguments.MasqueTransportOf(["--h2", "--quic"]).Should().BeEqualTo(AetherTransport.Http3);
        await AetherArguments.MasqueTransportOf(["--h3", "--h2"]).Should().BeEqualTo(AetherTransport.Http2);
        await AetherArguments.MasqueTransportOf(["--sni", "h2"]).Should().BeEqualTo(AetherTransport.Http3);
    }

    [Test]
    public async Task AnAetherProfileGoesByTheCommandWrittenByHandInPlaceOfItsSettings()
    {
        var profile = CoreConfigTestFactory.CreateAetherNode("a1", "warp", AetherProtocol.Masque.Type);
        profile.TcpUserTimeout = 10000;
        await AetherCore.ConnectsOverTcp(profile).Should().BeFalse();
        await TcpUserTimeoutRule.ValueOf(profile).Should().BeNull();

        profile.SetProtocolExtra(profile.GetProtocolExtra() with { AetherTransport = AetherTransport.Http2.Type });
        await AetherCore.ConnectsOverTcp(profile).Should().BeTrue();
        await TcpUserTimeoutRule.ValueOf(profile).Should().BeEqualTo(10000);

        // The command runs in place of the settings, as for LeavesThroughWarp.
        profile.SetProtocolExtra(profile.GetProtocolExtra() with { AetherCommand = "aether --protocol masque --h3" });
        await AetherCore.ConnectsOverTcp(profile).Should().BeFalse();
        profile.SetProtocolExtra(profile.GetProtocolExtra() with
        {
            AetherTransport = AetherTransport.Http3.Type,
            AetherCommand = "aether --protocol masque --http2",
        });
        await AetherCore.ConnectsOverTcp(profile).Should().BeTrue();
        profile.SetProtocolExtra(profile.GetProtocolExtra() with { AetherCommand = "aether --wg --tor-only" });
        await AetherCore.ConnectsOverTcp(profile).Should().BeTrue();
        profile.SetProtocolExtra(profile.GetProtocolExtra() with { AetherCommand = "aether --wg" });
        await AetherCore.ConnectsOverTcp(profile).Should().BeFalse();
    }
}
