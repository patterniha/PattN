namespace ServiceLib.ViewModels;

public partial class CheckUpdateViewModel : MyReactiveObject
{
    private const string _geo = "GeoFiles";
    private readonly ECoreType _v2rayN = ECoreType.v2rayN;
    private List<CheckUpdateModel> _lstUpdated = [];
    private static readonly string _tag = "CheckUpdateViewModel";

    public EventChannel<RxVoid> ReloadRequested { get; } = new();

    public BulkObservableCollection<CheckUpdateModel> CheckUpdateModels { get; } = [];
    public ReactiveCommand<RxVoid, RxVoid> CheckUpdateCmd { get; }
    public ReactiveCommand<RxVoid, RxVoid> CheckOnlyCmd { get; }

    [Reactive] public partial bool EnableUpdateViaProxy { get; set; }

    public CheckUpdateViewModel()
    {
        _config = AppManager.Instance.Config;

        CheckUpdateCmd = ReactiveCommand.CreateFromTask(CheckUpdate);
        CheckUpdateCmd.ThrownExceptions.Subscribe(ex =>
        {
            Logging.SaveLog(_tag, ex);
            _ = UpdateView(_v2rayN, ex.Message);
        });

        CheckOnlyCmd = ReactiveCommand.CreateFromTask(CheckOnly);
        CheckOnlyCmd.ThrownExceptions.Subscribe(ex =>
        {
            Logging.SaveLog(_tag, ex);
            _ = UpdateView(_v2rayN, ex.Message);
        });

        EnableUpdateViaProxy = _config.CheckUpdateItem.UpdateViaProxy;

        this.WhenAnyValue(x => x.EnableUpdateViaProxy)
            .Subscribe(c => _ = OnUpdateViaProxyChanged());

        AppEvents.HasUpdateNotified
         .AsObservable()
         .ObserveOn(RxSchedulers.MainThreadScheduler)
         .Subscribe(bl => RefreshCheckUpdateItems(bl));

        RefreshCheckUpdateItems(true);
    }

    private void RefreshCheckUpdateItems(bool hasUpdate)
    {
        if (!hasUpdate)
        {
            return;
        }

        var models = CoreInfoManager.Instance.GetCheckUpdateCoreTypes()
                        .Select(t => GetCheckUpdateModel(t))
                        .ToList();

        models.Add(GetGeoFileCheckUpdateModel());
        // PattN: the Psiphon server list of the Aether core, only where an Aether core is offered (critique 28)
        if (models.Any(t => t.CoreType == ECoreType.aether))
        {
            models.Add(GetPsiphonServersCheckUpdateModel());
        }

        CheckUpdateModels.ReplaceRange(models);
    }

    private CheckUpdateModel GetCheckUpdateModel(ECoreType coreType)
    {
        if (coreType == _v2rayN && Utils.IsPackagedInstall())
        {
            return new()
            {
                IsSelected = false,
                IsCheckPreRelease = false,
                ShowCheckPreRelease = false,
                CoreType = coreType,
                IsGeoFile = false,
                Remarks = ResUI.menuCheckUpdate + $" ({ResUI.MsgNotSupport})",
            };
        }

        AppManager.Instance.LastCheckUpdateResults.TryGetValue(coreType, out var lastResult);
        return new()
        {
            IsSelected = _config.CheckUpdateItem.SelectedCoreTypes?.Contains(coreType.ToString()) ?? true,
            IsCheckPreRelease = _config.CheckUpdateItem.CheckPreReleaseCoreTypes?.Contains(coreType.ToString()) ?? false,
            ShowCheckPreRelease = CoreInfoManager.Instance.GetCheckPreRelease(coreType, true),
            CoreType = coreType,
            IsGeoFile = false,
            Remarks = lastResult ?? ResUI.menuCheckUpdate,
        };
    }

    private CheckUpdateModel GetGeoFileCheckUpdateModel()
    {
        return new()
        {
            IsSelected = _config.CheckUpdateItem.SelectedCoreTypes?.Contains(_geo) ?? true,
            IsCheckPreRelease = false,
            ShowCheckPreRelease = false,
            CoreType = null,
            IsGeoFile = true,
            Remarks = ResUI.menuCheckUpdate,
        };
    }

    /// <summary>
    /// PattN (design 3.6): the row of the Psiphon server list, psiphon_servers. It has no core type, as the geo files'
    /// row has none, so its flag tells the two apart. A list of rows saved before it existed leaves it unselected
    /// (critique 26, accepted).
    /// </summary>
    private CheckUpdateModel GetPsiphonServersCheckUpdateModel()
    {
        return new()
        {
            IsSelected = _config.CheckUpdateItem.SelectedCoreTypes?.Contains(CheckUpdateModel.PsiphonServersStorageName) ?? true,
            IsCheckPreRelease = false,
            ShowCheckPreRelease = false,
            CoreType = null,
            IsGeoFile = false,
            IsPsiphonServers = true,
            Remarks = ResUI.menuCheckUpdate,
        };
    }

    private async Task OnUpdateViaProxyChanged()
    {
        if (_config.CheckUpdateItem.UpdateViaProxy == EnableUpdateViaProxy)
        {
            return;
        }
        _config.CheckUpdateItem.UpdateViaProxy = EnableUpdateViaProxy;
        await SaveSelectedCoreTypes();
    }

    private async Task SaveSelectedCoreTypes()
    {
        _config.CheckUpdateItem.SelectedCoreTypes =
            CheckUpdateModels.Where(t => t.IsSelected == true)
                            .Select(t => t.CoreTypeForStorage)
                            .ToList();

        _config.CheckUpdateItem.CheckPreReleaseCoreTypes =
           CheckUpdateModels.Where(t => t.IsCheckPreRelease == true)
                           .Select(t => t.CoreTypeForStorage)
                           .ToList();

        await ConfigHandler.SaveConfig(_config);
    }

    private async Task CheckOnly()
    {
        await Task.Run(CheckOnlyTask);
    }

    private async Task CheckUpdate()
    {
        await Task.Run(CheckUpdateTask);
    }

    private async Task CheckOnlyTask()
    {
        await SaveSelectedCoreTypes();

        for (var k = CheckUpdateModels.Count - 1; k >= 0; k--)
        {
            var item = CheckUpdateModels[k];
            if (item.IsSelected != true)
            {
                continue;
            }

            // PattN: the Psiphon server list is checked only by downloading it, as the geo files are (design 3.6); its
            // row has no core type, which UpdateView takes for the geo files' row
            if (item.IsPsiphonServers)
            {
                await UpdatePsiphonServersView(ResUI.menuCheckOnly + $" ({ResUI.MsgNotSupport})");
                continue;
            }

            await UpdateView(item.CoreType, "...");

            if (item.IsGeoFile || item.CoreType == null)
            {
                await UpdateView(item.CoreType, ResUI.menuCheckOnly + $" ({ResUI.MsgNotSupport})");
                continue;
            }

            if (item.CoreType == null)
            {
                await UpdateView(item.CoreType, ResUI.MsgNotSupport);
                continue;
            }

            using var downloadService = await DownloadService.CreateDownloadServiceWithCheck(EnableUpdateViaProxy);
            var updateService = new UpdateService(downloadService, _config, async (success, msg) => await Task.CompletedTask);
            var result = await updateService.CheckHasUpdateOnly(item.CoreType.Value, item.IsCheckPreRelease);
            if (result.Success && result.Version != null)
            {
                await UpdateView(item.CoreType, string.Format(ResUI.MsgCheckUpdateHasNewVersion, item.CoreType == _v2rayN ? Global.AppName : item.CoreType.ToString(), result.Version));
            }
            else
            {
                await UpdateView(item.CoreType, result.Msg);
            }
        }
    }

    private async Task CheckUpdateTask()
    {
        _lstUpdated.Clear();
        _lstUpdated = CheckUpdateModels
            .Where(x => x.IsSelected == true)
            .Select(x => new CheckUpdateModel()
            {
                CoreType = x.CoreType,
                IsPsiphonServers = x.IsPsiphonServers, // PattN: told apart from the geo files' row, as neither has a core type
                IsGeoFile = x.IsGeoFile
            })
            .ToList();
        await SaveSelectedCoreTypes();

        for (var k = CheckUpdateModels.Count - 1; k >= 0; k--)
        {
            var item = CheckUpdateModels[k];
            if (item.IsSelected != true)
            {
                continue;
            }

            // PattN: the Psiphon server list (design 3.6), on a row of its own: UpdateView takes a row without a core
            // type for the geo files' row
            if (item.IsPsiphonServers)
            {
                await UpdatePsiphonServersView("...");
                await CheckUpdatePsiphonServers();
                continue;
            }

            await UpdateView(item.CoreType, "...");

            if (item.IsGeoFile)
            {
                await CheckUpdateGeo();
            }
            else if (item.CoreType == _v2rayN)
            {
                if (Utils.IsPackagedInstall())
                {
                    await UpdateView(_v2rayN, ResUI.MsgNotSupport);
                    continue;
                }
                await CheckUpdateN(item.IsCheckPreRelease);
            }
            else if (item.CoreType.HasValue)
            {
                await CheckUpdateCore(item, item.IsCheckPreRelease);
            }
        }

        await UpdateFinished();
    }

    // PattN: isPsiphonServers names the Psiphon server list's row, which has no core type, as the geo files' row has none
    private void UpdatedPlusPlus(ECoreType? coreType, string fileName, bool isPsiphonServers = false)
    {
        // PattN: matched by the flag as well, so that neither of the two rows without a core type finishes the other
        var item = RowOf(_lstUpdated, coreType, isPsiphonServers);
        if (item == null)
        {
            return;
        }
        item.IsFinished = true;
        if (!fileName.IsNullOrEmpty())
        {
            item.FileName = fileName;
        }
    }

    /// <summary>
    /// PattN: the row of <paramref name="rows" /> that <paramref name="coreType" /> names, or that of the Psiphon server
    /// list when <paramref name="isPsiphonServers" /> is set; with no core type and without the flag, the geo files' row.
    /// The geo files' row and the Psiphon server list's row both have no core type, so the flag tells them apart.
    /// </summary>
    public static CheckUpdateModel? RowOf(IEnumerable<CheckUpdateModel> rows, ECoreType? coreType, bool isPsiphonServers = false)
    {
        return rows.FirstOrDefault(x => x.CoreType == coreType && x.IsPsiphonServers == isPsiphonServers);
    }

    /// <summary>
    /// PattN (design 2.11, 3.6): downloads the Psiphon server list in place of the one in use, once it is Psiphon's
    /// signed list; no core is stopped for it (critique 16). Its row finishes whatever came of it, as the geo files' does.
    /// </summary>
    private async Task CheckUpdatePsiphonServers()
    {
        async Task _updateUI(bool success, string msg)
        {
            await UpdatePsiphonServersView(msg);
            if (success)
            {
                UpdatedPlusPlus(null, "", isPsiphonServers: true);
            }
        }
        using var downloadService = new DownloadService();
        await new UpdateService(downloadService, _config, _updateUI).UpdatePsiphonServersAsync(EnableUpdateViaProxy)
            .ContinueWith(t =>
            {
                if (t.Exception?.GetBaseException() is { } ex)
                {
                    Logging.SaveLog(_tag, ex);
                    _ = UpdatePsiphonServersView(ex.Message);
                }
                UpdatedPlusPlus(null, "", isPsiphonServers: true);
            });
    }

    private async Task CheckUpdateGeo()
    {
        async Task _updateUI(bool success, string msg)
        {
            await UpdateView(null, msg);
            if (success)
            {
                UpdatedPlusPlus(null, "");
            }
        }
        using var downloadService = await DownloadService.CreateDownloadServiceWithCheck(EnableUpdateViaProxy);
        await new UpdateService(downloadService, _config, _updateUI).UpdateGeoFileAll()
            .ContinueWith(t => UpdatedPlusPlus(null, ""));
    }

    private async Task CheckUpdateN(bool preRelease)
    {
        async Task _updateUI(bool success, string msg)
        {
            await UpdateView(_v2rayN, msg);
            if (success)
            {
                await UpdateView(_v2rayN, ResUI.OperationSuccess);
                UpdatedPlusPlus(_v2rayN, msg);
            }
        }
        using var downloadService = await DownloadService.CreateDownloadServiceWithCheck(EnableUpdateViaProxy);
        await new UpdateService(downloadService, _config, _updateUI).CheckUpdateGuiN(preRelease)
            .ContinueWith(t => UpdatedPlusPlus(_v2rayN, ""));
    }

    private async Task CheckUpdateCore(CheckUpdateModel model, bool preRelease)
    {
        async Task _updateUI(bool success, string msg)
        {
            await UpdateView(model.CoreType, msg);
            if (success)
            {
                await UpdateView(model.CoreType, ResUI.MsgUpdateV2rayCoreSuccessfullyMore);
                UpdatedPlusPlus(model.CoreType, msg);
            }
        }

        if (model.CoreType.HasValue)
        {
            using var downloadService = await DownloadService.CreateDownloadServiceWithCheck(EnableUpdateViaProxy);
            await new UpdateService(downloadService, _config, _updateUI).CheckUpdateCore(model.CoreType.Value, preRelease)
                .ContinueWith(t => UpdatedPlusPlus(model.CoreType, ""));
        }
    }

    private async Task UpdateFinished()
    {
        // PattN: a new Psiphon server list alone stops no core and reloads nothing: the next core start unpacks it (critique 16)
        if (!UpdateRestartsCores(_lstUpdated))
        {
            return;
        }
        if (_lstUpdated.Count > 0 && _lstUpdated.Count(x => x.IsFinished == true) == _lstUpdated.Count)
        {
            await UpdateFinishedSub(false);
            await Task.Delay(2000);
            await UpgradeCore();

            if (_lstUpdated.Any(x => x.CoreType == _v2rayN && x.IsFinished == true))
            {
                await Task.Delay(1000);
                await UpgradeN();
            }
            await Task.Delay(1000);
            await UpdateFinishedSub(true);
        }
    }

    /// <summary>
    /// PattN (critique 16): whether the rows of an update, <paramref name="updated" />, need the cores stopped while files
    /// are replaced and reloaded afterwards: every row does but that of the Psiphon server list, which no running core reads
    /// (the next core start unpacks it, design 2.11).
    /// </summary>
    public static bool UpdateRestartsCores(IEnumerable<CheckUpdateModel> updated)
    {
        return updated.Any(row => !row.IsPsiphonServers);
    }

    private async Task UpdateFinishedSub(bool blReload)
    {
        RxSchedulers.MainThreadScheduler.Schedule(() =>
        {
            _ = UpdateFinishedResult(blReload);
        });
        await Task.CompletedTask;
    }

    public async Task UpdateFinishedResult(bool blReload)
    {
        if (blReload)
        {
            ReloadRequested.Publish();
        }
        else
        {
            await CoreManager.Instance.CoreStop();
        }
    }

    private async Task UpgradeN()
    {
        try
        {
            var fileName = _lstUpdated.FirstOrDefault(x => x.CoreType == _v2rayN)?.FileName;
            if (fileName.IsNullOrEmpty())
            {
                return;
            }
            if (!Utils.UpgradeAppExists(out var upgradeFileName))
            {
                await UpdateView(_v2rayN, ResUI.UpgradeAppNotExistTip);
                NoticeManager.Instance.SendMessageAndEnqueue(ResUI.UpgradeAppNotExistTip);
                Logging.SaveLog("UpgradeApp does not exist");
                return;
            }

            var id = ProcUtils.ProcessStart(upgradeFileName, fileName, Utils.StartupPath());
            if (id > 0)
            {
                await AppManager.Instance.AppExitAsync(true);
            }
        }
        catch (Exception ex)
        {
            await UpdateView(_v2rayN, ex.Message);
        }
    }

    private async Task UpgradeCore()
    {
        // PattN: the stop asked for before the upgrade ends the Aether session before Xray; it is waited for here, so
        // that no core's file is still held when it is replaced
        await CoreManager.Instance.CoreStop();
        // PattN: and every other Aether process, held off until the files are in place: a scan, a key run or a latency
        // test runs a core and an Xray of its own, whose files Windows keeps locked (critique 17)
        await using var aetherHold = await AetherCoreManager.Instance.HoldAsync();
        foreach (var item in _lstUpdated)
        {
            if (item.FileName.IsNullOrEmpty() || item.IsGeoFile)
            {
                continue;
            }
            // PattN: the Psiphon server list is in place as soon as it is downloaded; there is nothing to unpack
            if (item.IsPsiphonServers)
            {
                continue;
            }

            var fileName = item.FileName;
            if (!File.Exists(fileName))
            {
                continue;
            }

            // PattN: the Aether core's archive holds three programs, two of them in a pt/ folder
            if (item.CoreType == ECoreType.aether)
            {
                await UpgradeAetherCore(fileName);
                continue;
            }

            var coreTypeStr = item.CoreType?.ToString() ?? "";
            var toPath = Utils.GetBinPath("", coreTypeStr);

            // PattN: on Windows Xray runs from its copy p-xray-p.exe, which changes with xray.exe: first xray.exe is
            // replaced, then copied over p-xray-p.exe, in one hold in which no Xray starts; and only while no Xray runs from
            // the copy, as a speed or latency test the stop above does not end: otherwise neither file is replaced, and the
            // row says so
            using var xrayFiles = item.CoreType == ECoreType.Xray && Utils.IsWindows()
                ? await CoreInfoManager.HoldXrayFilesAsync()
                : null;
            if (xrayFiles != null
                && CoreInfoManager.XrayCopyInUse(CoreInfoManager.Instance.FindInstalledXray() ?? Path.Combine(toPath, Utils.GetExeName("xray"))) is { } inUse)
            {
                await UpdateView(item.CoreType, inUse);
                File.Delete(fileName);
                continue;
            }

            if (fileName.Contains(".tar.gz"))
            {
                FileUtils.DecompressTarFile(fileName, toPath);
                var dir = new DirectoryInfo(toPath);
                if (dir.Exists)
                {
                    foreach (var subDir in dir.GetDirectories())
                    {
                        FileUtils.CopyDirectory(subDir.FullName, toPath, false, true);
                        subDir.Delete(true);
                    }
                }
            }
            else if (fileName.Contains(".gz"))
            {
                FileUtils.DecompressFile(fileName, toPath, coreTypeStr);
            }
            else
            {
                FileUtils.ZipExtractToFile(fileName, toPath, "geo");
            }

            if (Utils.IsNonWindows())
            {
                var filesList = new DirectoryInfo(toPath).GetFiles().Select(u => u.FullName).ToList();
                foreach (var file in filesList)
                {
                    await Utils.SetLinuxChmod(Path.Combine(toPath, coreTypeStr.ToLower()));
                }
            }

            // PattN: the new xray.exe is copied over p-xray-p.exe (see above)
            var outcome = ResUI.MsgUpdateV2rayCoreSuccessfully;
            if (xrayFiles != null
                && CoreInfoManager.Instance.FindInstalledXray() is { } xrayExe
                && !CoreInfoManager.SyncXrayCopy(xrayExe, out var copyFailure))
            {
                outcome = copyFailure;
            }
            await UpdateView(item.CoreType, outcome);

            if (File.Exists(fileName))
            {
                File.Delete(fileName);
            }
        }
    }

    /// <summary>
    /// PattN: puts the programs of a downloaded Aether archive into bin/aether, flat, with the archive's LICENSES folder
    /// when it has one (AetherBinaries.Extract), and gives the programs their execute bits outside Windows. A failure is
    /// shown on the row of the core alone, and the other rows are installed as usual. Every
    /// Aether process (the session's core, and those of scans, latency tests and WARP-key runs) is gone by then and none
    /// starts until the files are in place: UpgradeCore holds the cores around every row (critique 17).
    /// </summary>
    private async Task UpgradeAetherCore(string fileName)
    {
        try
        {
            AetherBinaries.Extract(fileName, AetherBinaries.Folder);
            await AetherBinaries.SetExecutableAsync(AetherBinaries.Folder);
            await UpdateView(ECoreType.aether, ResUI.MsgUpdateV2rayCoreSuccessfully);
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
            await UpdateView(ECoreType.aether, ex.Message);
        }
        finally
        {
            try
            {
                File.Delete(fileName);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Logging.SaveLog(_tag, ex);
            }
        }
    }

    private async Task UpdateView(ECoreType? coreType, string msg)
    {
        var item = new CheckUpdateModel()
        {
            CoreType = coreType,
            IsGeoFile = coreType == null,
            Remarks = msg,
        };

        RxSchedulers.MainThreadScheduler.Schedule(() =>
        {
            _ = UpdateViewResult(item);
        });
        await Task.CompletedTask;
    }

    /// <summary>
    /// PattN: shows <paramref name="msg" /> on the row of the Psiphon server list, which UpdateView cannot reach: a row
    /// without a core type is the geo files' row there.
    /// </summary>
    private async Task UpdatePsiphonServersView(string msg)
    {
        var item = new CheckUpdateModel()
        {
            CoreType = null,
            IsGeoFile = false,
            IsPsiphonServers = true,
            Remarks = msg,
        };

        RxSchedulers.MainThreadScheduler.Schedule(() =>
        {
            _ = UpdateViewResult(item);
        });
        await Task.CompletedTask;
    }

    public async Task UpdateViewResult(CheckUpdateModel model)
    {
        // PattN: the Psiphon server list's row is matched by its flag as well, as it has no core type either
        var found = CheckUpdateModels.FirstOrDefault(t => t.CoreType == model.CoreType && t.IsGeoFile == model.IsGeoFile && t.IsPsiphonServers == model.IsPsiphonServers);
        if (found == null)
        {
            return;
        }
        found.Remarks = model.Remarks;
        await Task.CompletedTask;
    }
}
