namespace ServiceLib.Manager;

public sealed class CoreInfoManager
{
    private static readonly Lazy<CoreInfoManager> _instance = new(() => new());
    private List<CoreInfo>? _coreInfo;
    public static CoreInfoManager Instance => _instance.Value;

    public CoreInfoManager()
    {
        InitCoreInfo();
    }

    public CoreInfo? GetCoreInfo(ECoreType coreType)
    {
        if (_coreInfo == null)
        {
            InitCoreInfo();
        }
        return _coreInfo?.FirstOrDefault(t => t.CoreType == coreType);
    }

    public List<CoreInfo> GetCoreInfo()
    {
        if (_coreInfo == null)
        {
            InitCoreInfo();
        }
        return _coreInfo ?? [];
    }

    /// <summary>
    /// The file a start of the core of <paramref name="coreInfo" /> runs: for Xray on Windows, its copy, checked against
    /// xray.exe and made equal to it first (<see cref="RunFileOf" />); a start holds <see cref="HoldXrayFilesAsync" /> from
    /// this call until its Xray has started. Empty, with <paramref name="msg" />, when it cannot run.
    /// </summary>
    public string GetCoreExecFile(CoreInfo? coreInfo, out string msg)
    {
        var fileName = FindCoreExe(coreInfo);
        msg = string.Empty;
        if (fileName.IsNullOrEmpty())
        {
            msg = NotFoundMessage(coreInfo);
            Logging.SaveLog(msg);
        }
        else
        {
            fileName = RunFileOf(coreInfo, fileName, out msg);
        }
        return fileName;
    }

    /// <summary>
    /// PattN: the file the core of <paramref name="coreInfo" /> runs from, as a path alone, for a configuration that names
    /// it or a check that it is there: for Xray on Windows its copy, which is neither checked nor made here (a start
    /// does that, <see cref="GetCoreExecFile" />). Empty, with <paramref name="missing" />, when the core is not installed.
    /// </summary>
    public string GetCoreRunPath(CoreInfo? coreInfo, out string missing)
    {
        var fileName = FindCoreExe(coreInfo);
        missing = fileName.IsNullOrEmpty() ? NotFoundMessage(coreInfo) : string.Empty;
        if (fileName.IsNotEmpty() && coreInfo?.CoreType == ECoreType.Xray && Utils.IsWindows())
        {
            fileName = XrayCopyOf(fileName);
        }
        return fileName;
    }

    /// <summary>The program of the core of <paramref name="coreInfo" /> as installed, by its names; empty when there is none.</summary>
    private static string FindCoreExe(CoreInfo? coreInfo)
    {
        foreach (var name in coreInfo?.CoreExes ?? [])
        {
            var vName = Utils.GetBinPath(Utils.GetExeName(name), coreInfo!.CoreType.ToString());
            if (File.Exists(vName))
            {
                return vName;
            }
        }
        return string.Empty;
    }

    private static string NotFoundMessage(CoreInfo? coreInfo)
    {
        return string.Format(ResUI.NotFoundCore, Utils.GetBinPath("", coreInfo?.CoreType.ToString()), coreInfo?.CoreExes?.LastOrDefault(), coreInfo?.Url);
    }

    /// <summary>The name of the copy of xray.exe that Xray runs from on Windows.</summary>
    public const string XrayAliasExeName = "p-xray-p.exe";

    /// <summary>
    /// PattN: the file the core <paramref name="exeFile" /> of <paramref name="coreInfo" /> runs from, whatever it runs
    /// for: a session, a test, a scan, a key run, or a version check. That is the file itself, except for Xray on
    /// Windows, which always runs from its copy p-xray-p.exe beside it, checked against xray.exe and made equal to it
    /// first, and never as xray.exe (<see cref="XrayRunFile" />). Empty, with <paramref name="msg" />, when that copy
    /// cannot be made equal to xray.exe.
    /// </summary>
    public static string RunFileOf(CoreInfo? coreInfo, string exeFile, out string msg)
    {
        msg = string.Empty;
        return coreInfo?.CoreType == ECoreType.Xray && Utils.IsWindows() ? XrayRunFile(exeFile, out msg) : exeFile;
    }

    /// <summary>
    /// PattN: the copy p-xray-p.exe beside <paramref name="xrayExe" /> that Xray runs from on Windows. Windows treats a
    /// process named "xray.exe" as suspicious (XTLS/Xray-core#4427), which breaks HTTP request fragmentation, so Xray never
    /// runs under that name; xray.exe itself is kept, and stays the file updates replace, for third-party tools.
    /// </summary>
    public static string XrayCopyOf(string xrayExe)
    {
        return Path.Combine(Path.GetDirectoryName(xrayExe) ?? string.Empty, XrayAliasExeName);
    }

    /// <summary>
    /// PattN: makes the copy of <paramref name="xrayExe" /> (<see cref="XrayCopyOf" />) equal to it but for its name: where
    /// the copy is missing, or differs, as once an update replaced xray.exe, xray.exe is copied over it. The two are told
    /// equal by their bytes (size, then SHA-256), which says more than their versions do, and asks neither of them: xray.exe
    /// is never run, and its Windows build carries no version that could be read without running it. One check or copy at
    /// a time: Xray processes that start together, as a session and a latency test, wait for each other's copy rather
    /// than fail on it. The copy is left writable, though xray.exe may be read-only, so that the next update can replace
    /// it. False, with <paramref name="msg" />, when the copy cannot be made equal, as while an older one runs.
    /// </summary>
    public static bool SyncXrayCopy(string xrayExe, out string msg)
    {
        msg = string.Empty;
        var copy = XrayCopyOf(xrayExe);
        lock (XrayCopyGate)
        {
            try
            {
                if (!File.Exists(copy) || !IsSameFileContent(xrayExe, copy))
                {
                    if (File.Exists(copy))
                    {
                        File.SetAttributes(copy, FileAttributes.Normal);
                    }
                    File.Copy(xrayExe, copy, true);
                    File.SetAttributes(copy, FileAttributes.Normal);
                }
                return true;
            }
            catch (Exception ex)
            {
                Logging.SaveLog("CoreInfoManager", ex);
                msg = string.Format(ResUI.MsgXrayRunCopyFailed, copy, ex.Message);
                return false;
            }
        }
    }

    private static readonly object XrayCopyGate = new();

    private static readonly SemaphoreSlim XrayFilesGate = new(1, 1);

    /// <summary>
    /// PattN: holds xray.exe and its copy for one user of them at a time until the handle is disposed: an Xray start from
    /// checking the copy until its Xray has started (Windows then keeps the copy that runs from being replaced), a
    /// version check until it has its answer, and an update from checking that no Xray runs from the copy until both files
    /// are new. So no Xray starts from a copy that differs from xray.exe, and an update replaces both or neither.
    /// </summary>
    public static async Task<IDisposable> HoldXrayFilesAsync()
    {
        await XrayFilesGate.WaitAsync().ConfigureAwait(false);
        return new XrayFilesHold();
    }

    private sealed class XrayFilesHold : IDisposable
    {
        private int _released;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _released, 1) == 0)
            {
                XrayFilesGate.Release();
            }
        }
    }

    /// <summary>
    /// PattN: a message when an Xray runs from the copy of <paramref name="xrayExe" /> now, as a speed or latency test that
    /// a core stop does not end, so that the copy cannot be replaced: an update then replaces neither file. Null when none
    /// does, or there is no copy yet. Asked while <see cref="HoldXrayFilesAsync" /> is held, so that none starts meanwhile.
    /// </summary>
    public static string? XrayCopyInUse(string xrayExe)
    {
        var copy = XrayCopyOf(xrayExe);
        if (!File.Exists(copy))
        {
            return null;
        }
        try
        {
            // A file a program runs from can be read, even alone, but not written: Windows refuses that while it runs.
            // Nothing is written here; a read-only copy, which no update could replace either, is made writable first.
            File.SetAttributes(copy, FileAttributes.Normal);
            using var writable = new FileStream(copy, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
            return null;
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }
        catch (IOException)
        {
            return string.Format(ResUI.MsgXrayCopyInUse, copy);
        }
        catch (UnauthorizedAccessException ex)
        {
            return string.Format(ResUI.MsgXrayRunCopyFailed, copy, ex.Message);
        }
    }

    /// <summary>
    /// PattN: the file Xray runs from on Windows: the copy of <paramref name="xrayExe" />, checked against it before every
    /// run and made equal to it where it is missing or differs (<see cref="SyncXrayCopy" />). Empty, with
    /// <paramref name="msg" />, when it cannot be made equal, as while another Xray runs from an older copy: Xray is then
    /// not run at all, neither as xray.exe nor from a copy that differs from it. Copies equal to xray.exe run side by side.
    /// </summary>
    public static string XrayRunFile(string xrayExe, out string msg)
    {
        if (SyncXrayCopy(xrayExe, out msg))
        {
            return XrayCopyOf(xrayExe);
        }
        Logging.SaveLog(msg);
        return string.Empty;
    }

    /// <summary>PattN: xray.exe as installed, in bin/xray, the file updates replace; null when there is none.</summary>
    public string? FindInstalledXray()
    {
        var info = GetCoreInfo(ECoreType.Xray);
        return info?.CoreExes?
            .Select(name => Utils.GetBinPath(Utils.GetExeName(name), info.CoreType.ToString()))
            .FirstOrDefault(File.Exists);
    }

    // Xray builds are reproducible (fixed timestamp) and sizes can repeat across versions, so compare by hash
    private static bool IsSameFileContent(string path1, string path2)
    {
        if (new FileInfo(path1).Length != new FileInfo(path2).Length)
        {
            return false;
        }
        using var stream1 = File.OpenRead(path1);
        using var stream2 = File.OpenRead(path2);
        return SHA256.HashData(stream1).AsSpan().SequenceEqual(SHA256.HashData(stream2));
    }

    public List<ECoreType> GetCheckUpdateCoreTypes()
    {
        var lst = new List<ECoreType>();

        if (RuntimeInformation.ProcessArchitecture != Architecture.X86)
        {
            if (IsCheckUpdateSupported(ECoreType.v2rayN))
            {
                lst.Add(ECoreType.v2rayN);
            }

            if (!(Utils.IsWindows() && Environment.OSVersion.Version.Major < 10))
            {
                lst.Add(ECoreType.Xray);
                lst.Add(ECoreType.mihomo);
                lst.Add(ECoreType.sing_box);

                // PattN: the Aether core, only where patterniha/Aether publishes an archive for this system
                if (IsAetherDownloadable())
                {
                    lst.Add(ECoreType.aether);
                }
            }
        }

        return lst;
    }

    public bool IsCheckUpdateSupported(ECoreType type)
    {
        return type switch
        {
            ECoreType.v2rayN => !Utils.IsPackagedInstall(),
            ECoreType.Xray => true,
            ECoreType.mihomo => true,
            ECoreType.sing_box => true,
            ECoreType.aether => true, // PattN
            _ => false,
        };
    }

    /// <summary>
    /// PattN: whether patterniha/Aether publishes an archive of its core for the running OS and architecture. Where it
    /// publishes none (Linux on RISC-V and LoongArch), the update row of the core is left out rather than failing for
    /// want of a download URL.
    /// </summary>
    public bool IsAetherDownloadable()
    {
        OSPlatform? os = Utils.IsWindows() ? OSPlatform.Windows
            : Utils.IsLinux() ? OSPlatform.Linux
            : Utils.IsMacOS() ? OSPlatform.OSX
            : null;
        return os is { } platform
            && IsAetherDownloadable(GetCoreInfo(ECoreType.aether), platform, RuntimeInformation.ProcessArchitecture, Environment.OSVersion.Version.Build);
    }

    /// <summary>
    /// PattN: whether a system is offered an archive of the Aether core. Windows on ARM gets the x64 core, which only
    /// Windows 11 (build 22000 and later) runs there; Windows 10 on ARM emulates 32-bit x86 programs alone.
    /// </summary>
    public static bool IsAetherDownloadable(CoreInfo? coreInfo, OSPlatform os, Architecture architecture, int windowsBuild)
    {
        if (os == OSPlatform.Windows && architecture == Architecture.Arm64 && windowsBuild < 22000)
        {
            return false;
        }
        return GetDownloadUrl(coreInfo, os, architecture).IsNotEmpty();
    }

    /// <summary>
    /// PattN: the archive of a core for an OS and an architecture, picked as UpdateService.GetUrlFromCore picks it for
    /// the running system (apart from the "-desktop" archive of PattN itself); null where the core has none.
    /// </summary>
    public static string? GetDownloadUrl(CoreInfo? coreInfo, OSPlatform os, Architecture architecture)
    {
        if (os == OSPlatform.Windows)
        {
            return architecture switch
            {
                Architecture.Arm64 => coreInfo?.DownloadUrlWinArm64,
                Architecture.X64 => coreInfo?.DownloadUrlWin64,
                _ => null,
            };
        }
        if (os == OSPlatform.Linux)
        {
            return architecture switch
            {
                Architecture.Arm64 => coreInfo?.DownloadUrlLinuxArm64,
                Architecture.RiscV64 => coreInfo?.DownloadUrlLinuxRiscV64,
                Architecture.LoongArch64 => coreInfo?.DownloadUrlLinuxLoong64,
                Architecture.X64 => coreInfo?.DownloadUrlLinux64,
                _ => null,
            };
        }
        if (os == OSPlatform.OSX)
        {
            return architecture switch
            {
                Architecture.Arm64 => coreInfo?.DownloadUrlOSXArm64,
                Architecture.X64 => coreInfo?.DownloadUrlOSX64,
                _ => null,
            };
        }
        return null;
    }

    public bool GetCheckPreRelease(ECoreType type, bool preRelease)
    {
        return type switch
        {
            ECoreType.v2rayN => preRelease,
            ECoreType.Xray => preRelease,
            _ => false,
        };
    }

    private void InitCoreInfo()
    {
        var urlN = GetCoreUrl(ECoreType.v2rayN);
        var urlXray = GetCoreUrl(ECoreType.Xray);
        var urlMihomo = GetCoreUrl(ECoreType.mihomo);
        var urlSingbox = GetCoreUrl(ECoreType.sing_box);
        var urlAether = GetCoreUrl(ECoreType.aether); // PattN

        _coreInfo =
        [
            new CoreInfo
                {
                    CoreType = ECoreType.v2rayN,
                    Url = GetCoreUrl(ECoreType.v2rayN),
                    ReleaseApiUrl = urlN.Replace(Global.GithubUrl, Global.GithubApiUrl),
                    GitInfoRefsUrl = GetGitInfoRefsUrl(ECoreType.v2rayN),
                    DownloadUrlWin64 = urlN + "/download/{0}/PattN-windows-64.zip",
                    DownloadUrlWinArm64 = urlN + "/download/{0}/PattN-windows-arm64.zip",
                    DownloadUrlLinux64 = urlN + "/download/{0}/PattN-linux-64.zip",
                    DownloadUrlLinuxArm64 = urlN + "/download/{0}/PattN-linux-arm64.zip",
                    DownloadUrlLinuxRiscV64 = urlN + "/download/{0}/PattN-linux-riscv64.zip",
                    DownloadUrlLinuxLoong64 = urlN + "/download/{0}/PattN-linux-loong64.zip",
                    DownloadUrlOSX64 = urlN + "/download/{0}/PattN-macos-64.zip",
                    DownloadUrlOSXArm64 = urlN + "/download/{0}/PattN-macos-arm64.zip",
                },

                new CoreInfo
                {
                    CoreType = ECoreType.v2fly,
                    CoreExes = ["v2ray"],
                    Arguments = "{0}",
                    Url = GetCoreUrl(ECoreType.v2fly),
                    Match = "V2Ray",
                    VersionArg = "-version",
                    Environment = new Dictionary<string, string?>()
                    {
                        { Global.V2RayLocalAsset, Utils.GetBinPath("") },
                    },
                },

                new CoreInfo
                {
                    CoreType = ECoreType.v2fly_v5,
                    CoreExes = ["v2ray"],
                    Arguments = "run -c {0} -format jsonv5",
                    Url = GetCoreUrl(ECoreType.v2fly_v5),
                    Match = "V2Ray",
                    VersionArg = "version",
                    Environment = new Dictionary<string, string?>()
                    {
                        { Global.V2RayLocalAsset, Utils.GetBinPath("") },
                    },
                },

                new CoreInfo
                {
                    CoreType = ECoreType.Xray,
                    CoreExes = ["xray"],
                    Arguments = "run -c {0}",
                    Url = GetCoreUrl(ECoreType.Xray),
                    ReleaseApiUrl = urlXray.Replace(Global.GithubUrl, Global.GithubApiUrl),
                    GitInfoRefsUrl = GetGitInfoRefsUrl(ECoreType.Xray),
                    DownloadUrlWin64 = urlXray + "/download/{0}/Xray-windows-64.zip",
                    DownloadUrlWinArm64 = urlXray + "/download/{0}/Xray-windows-arm64-v8a.zip",
                    DownloadUrlLinux64 = urlXray + "/download/{0}/Xray-linux-64.zip",
                    DownloadUrlLinuxArm64 = urlXray + "/download/{0}/Xray-linux-arm64-v8a.zip",
                    DownloadUrlLinuxRiscV64 = urlXray + "/download/{0}/Xray-linux-riscv64.zip",
                    DownloadUrlLinuxLoong64 = urlXray + "/download/{0}/Xray-linux-loong64.zip",
                    DownloadUrlOSX64 = urlXray + "/download/{0}/Xray-macos-64.zip",
                    DownloadUrlOSXArm64 = urlXray + "/download/{0}/Xray-macos-arm64-v8a.zip",
                    Match = "Xray",
                    VersionArg = "-version",
                    Environment = new Dictionary<string, string?>()
                    {
                        { Global.XrayLocalAsset, Utils.GetBinPath("") },
                        { Global.XrayLocalCert, Utils.GetBinPath("") },
                    },
                },

                new CoreInfo
                {
                    CoreType = ECoreType.mihomo,
                    CoreExes = GetMihomoCoreExes(),
                    Arguments = "-f {0}" + PortableMode(),
                    Url = GetCoreUrl(ECoreType.mihomo),
                    ReleaseApiUrl = urlMihomo.Replace(Global.GithubUrl, Global.GithubApiUrl),
                    GitInfoRefsUrl = GetGitInfoRefsUrl(ECoreType.mihomo),
                    DownloadUrlWin64 = urlMihomo + "/download/{0}/mihomo-windows-amd64-v1-{0}.zip",
                    DownloadUrlWinArm64 = urlMihomo + "/download/{0}/mihomo-windows-arm64-{0}.zip",
                    DownloadUrlLinux64 = urlMihomo + "/download/{0}/mihomo-linux-amd64-v1-{0}.gz",
                    DownloadUrlLinuxArm64 = urlMihomo + "/download/{0}/mihomo-linux-arm64-{0}.gz",
                    DownloadUrlLinuxRiscV64 = urlMihomo + "/download/{0}/mihomo-linux-riscv64-{0}.gz",
                    DownloadUrlLinuxLoong64 = urlMihomo + "/download/{0}/mihomo-linux-loong64-abi2-{0}.gz",
                    DownloadUrlOSX64 = urlMihomo + "/download/{0}/mihomo-darwin-amd64-v1-{0}.gz",
                    DownloadUrlOSXArm64 = urlMihomo + "/download/{0}/mihomo-darwin-arm64-{0}.gz",
                    Match = "Mihomo",
                    VersionArg = "-v",
                },

                new CoreInfo
                {
                    CoreType = ECoreType.hysteria,
                    CoreExes = ["hysteria"],
                    Arguments = "",
                    Url = GetCoreUrl(ECoreType.hysteria),
                },

                new CoreInfo
                {
                    CoreType = ECoreType.naiveproxy,
                    CoreExes = [ "naive", "naiveproxy"],
                    Arguments = "{0}",
                    Url = GetCoreUrl(ECoreType.naiveproxy),
                },

                new CoreInfo
                {
                    CoreType = ECoreType.tuic,
                    CoreExes = ["tuic-client", "tuic"],
                    Arguments = "-c {0}",
                    Url = GetCoreUrl(ECoreType.tuic),
                },

                new CoreInfo
                {
                    CoreType = ECoreType.sing_box,
                    CoreExes = ["sing-box-client", "sing-box"],
                    Arguments = "run -c {0} --disable-color",
                    Url = GetCoreUrl(ECoreType.sing_box),

                    ReleaseApiUrl = urlSingbox.Replace(Global.GithubUrl, Global.GithubApiUrl),
                    GitInfoRefsUrl = GetGitInfoRefsUrl(ECoreType.sing_box),
                    DownloadUrlWin64 = urlSingbox + "/download/{0}/sing-box-{1}-windows-amd64.zip",
                    DownloadUrlWinArm64 = urlSingbox + "/download/{0}/sing-box-{1}-windows-arm64.zip",
                    DownloadUrlLinux64 = urlSingbox + "/download/{0}/sing-box-{1}-linux-amd64.tar.gz",
                    DownloadUrlLinuxArm64 = urlSingbox + "/download/{0}/sing-box-{1}-linux-arm64.tar.gz",
                    DownloadUrlLinuxRiscV64 = urlSingbox + "/download/{0}/sing-box-{1}-linux-riscv64.tar.gz",
                    DownloadUrlLinuxLoong64 = urlSingbox + "/download/{0}/sing-box-{1}-linux-loong64.tar.gz",
                    DownloadUrlOSX64 = urlSingbox + "/download/{0}/sing-box-{1}-darwin-amd64.tar.gz",
                    DownloadUrlOSXArm64 = urlSingbox + "/download/{0}/sing-box-{1}-darwin-arm64.tar.gz",
                    //LockedMaxVersion = new SemanticVersion(1, 14, int.MaxValue),
                    Match = "sing-box",
                    VersionArg = "version",
                },

                new CoreInfo
                {
                    CoreType = ECoreType.juicity,
                    CoreExes = ["juicity-client", "juicity"],
                    Arguments = "run -c {0}",
                    Url = GetCoreUrl(ECoreType.juicity)
                },

                new CoreInfo
                {
                    CoreType = ECoreType.hysteria2,
                    CoreExes = ["hysteria-windows-amd64", "hysteria-linux-amd64", "hysteria"],
                    Arguments = "",
                    Url = GetCoreUrl(ECoreType.hysteria2),
                },

                new CoreInfo
                {
                    CoreType = ECoreType.brook,
                    CoreExes = ["brook_windows_amd64", "brook_linux_amd64", "brook"],
                    Arguments = " {0}",
                    Url = GetCoreUrl(ECoreType.brook),
                    AbsolutePath = true,
                },

                new CoreInfo
                {
                    CoreType = ECoreType.overtls,
                    CoreExes = [ "overtls-bin", "overtls"],
                    Arguments = "-r client -c {0}",
                    Url =  GetCoreUrl(ECoreType.overtls),
                    AbsolutePath = false,
                },

                new CoreInfo
                {
                    CoreType = ECoreType.shadowquic,
                    CoreExes = [ "shadowquic" ],
                    Arguments = "-c {0}",
                    Url =  GetCoreUrl(ECoreType.shadowquic),
                    AbsolutePath = false,
                },

                new CoreInfo
                {
                    CoreType = ECoreType.mieru,
                    CoreExes = [ "mieru" ],
                    Arguments = "run",
                    Url =  GetCoreUrl(ECoreType.mieru),
                    AbsolutePath = false,
                    Environment = new Dictionary<string, string?>()
                    {
                        { "MIERU_CONFIG_JSON_FILE", "{0}" },
                    },
                },

                // PattN: the Aether WARP client (patterniha/Aether). Each release archive holds aether[.exe] and a pt/
                // folder with lyrebird and psiphon-tunnel-core; the updater puts all three side by side in bin/aether
                // (AetherBinaries.Extract), where the core finds both helpers beside itself. The archive names are
                // those of the fork's release.yml.
                new CoreInfo
                {
                    CoreType = ECoreType.aether,
                    CoreExes = [AetherBinaries.CoreName],
                    Arguments = "", // not used: the Aether code builds the argument list of each run itself
                    Url = urlAether,
                    ReleaseApiUrl = urlAether.Replace(Global.GithubUrl, Global.GithubApiUrl),
                    GitInfoRefsUrl = GetGitInfoRefsUrl(ECoreType.aether),
                    DownloadUrlWin64 = urlAether + "/download/{0}/aether-windows-x86_64.zip",
                    // The fork builds no arm64 Windows core; Windows 11 on ARM runs the x64 one.
                    DownloadUrlWinArm64 = urlAether + "/download/{0}/aether-windows-x86_64.zip",
                    // The static musl builds, which run on any distribution, whatever its C library.
                    DownloadUrlLinux64 = urlAether + "/download/{0}/aether-linux-x86_64-musl.tar.gz",
                    DownloadUrlLinuxArm64 = urlAether + "/download/{0}/aether-linux-aarch64-musl.tar.gz",
                    DownloadUrlOSX64 = urlAether + "/download/{0}/aether-macos-x86_64.tar.gz",
                    DownloadUrlOSXArm64 = urlAether + "/download/{0}/aether-macos-arm64.tar.gz",
                    Match = "aether",
                    VersionArg = "--version", // prints "aether 2.3.2"
                },
        ];
    }

    private static string PortableMode()
    {
        return $" -d {Utils.GetBinPath("").AppendQuotes()}";
    }

    private static string GetCoreUrl(ECoreType eCoreType)
    {
        return $"{Global.GithubUrl}/{Global.CoreUrls[eCoreType]}/releases";
    }

    private static string GetGitInfoRefsUrl(ECoreType eCoreType)
    {
        return $"{Global.GithubUrl}/{Global.CoreUrls[eCoreType]}.git/info/refs?service=git-upload-pack";
    }

    private static List<string>? GetMihomoCoreExes()
    {
        var names = new List<string>();

        if (Utils.IsWindows())
        {
            names.Add("mihomo-windows-amd64-v1");
            names.Add("mihomo-windows-amd64-compatible");
            names.Add("mihomo-windows-amd64");
            names.Add("mihomo-windows-arm64");
        }
        else if (Utils.IsLinux())
        {
            names.Add("mihomo-linux-amd64-v1");
            names.Add("mihomo-linux-amd64");
            names.Add("mihomo-linux-arm64");
            names.Add("mihomo-linux-riscv64");
            names.Add("mihomo-linux-loong64-abi2");
        }
        else if (Utils.IsMacOS())
        {
            names.Add("mihomo-darwin-amd64-v1");
            names.Add("mihomo-darwin-amd64");
            names.Add("mihomo-darwin-arm64");
        }

        names.Add("clash");
        names.Add("mihomo");

        return names;
    }
}
