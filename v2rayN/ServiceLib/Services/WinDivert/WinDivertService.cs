namespace ServiceLib.Services.WinDivert;

/// <summary>
/// Facade of the WinDivert mode.
/// <para>
/// The WinDivert mode diverts the traffic of the whole system to the running core,
/// without requiring a tun adapter (wintun). It is an alternative to the tun mode for
/// systems where the tun device causes problems.
/// </para>
/// </summary>
public class WinDivertService
{
    private const string _tag = "WinDivertService";

    private static readonly Lazy<WinDivertService> _instance = new(() => new());
    public static WinDivertService Instance => _instance.Value;

    private WinDivertEngine? _engine;
    private WinDivertRelay? _relay;
    private WinDivertDnsResolver? _dnsResolver;
    private int _proxyPort;

    public bool IsRunning => _engine?.IsRunning == true;

    public string? LastError { get; private set; }

    /// <summary>
    /// Starts the WinDivert interception.
    /// </summary>
    /// <param name="config">Current configuration.</param>
    /// <returns>True when the interception was started.</returns>
    public bool Start(Config config)
    {
        if (!Utils.IsWindows())
        {
            LastError = "WinDivert is only available on Windows.";
            return false;
        }

        if (!Utils.IsAdministrator())
        {
            LastError = "WinDivert requires administrator rights.";
            return false;
        }

        Stop();

        try
        {
            _proxyPort = AppManager.Instance.GetLocalPort(EInboundProtocol.socks);

            var options = new WinDivertOptions
            {
                EnableDnsHijack = config.WinDivertItem.EnableDnsHijack,
                DropQuic = config.WinDivertItem.DropQuic,
                BypassLan = config.WinDivertItem.BypassLan,
                DnsUrl = config.WinDivertItem.DnsUrl.IsNullOrEmpty() || config.WinDivertItem.DnsUrl.Contains("cloudflare-dns.com")
                    ? "https://1.1.1.1/dns-query"
                    : config.WinDivertItem.DnsUrl,
                ProxyPort = _proxyPort,
            };

            _relay = new WinDivertRelay { ProxyPort = _proxyPort };
            _dnsResolver = new WinDivertDnsResolver(options.DnsUrl);
            _engine = new WinDivertEngine(_relay, _dnsResolver, options);
            _engine.Start();

            LastError = null;
            return true;
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
            LastError = ex.Message;
            Stop();
            return false;
        }
    }

    /// <summary>
    /// Stops the WinDivert interception.
    /// </summary>
    public void Stop()
    {
        try
        {
            _engine?.Dispose();
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
        }
        _engine = null;

        try
        {
            _relay?.Dispose();
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
        }
        _relay = null;

        try
        {
            _dnsResolver?.Dispose();
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
        }
        _dnsResolver = null;
    }

    /// <summary>
    /// Updates the local proxy port, used when the inbound port of the core changed.
    /// </summary>
    public void UpdateProxyPort(int port)
    {
        if (port <= 0 || port == _proxyPort)
        {
            return;
        }

        _proxyPort = port;
        if (_relay != null)
        {
            _relay.ProxyPort = port;
        }
    }
}
