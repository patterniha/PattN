using System.Diagnostics;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text;

namespace AmazTool;

internal class UpgradeApp
{
    public static void Upgrade(string fileName)
    {
        Console.WriteLine($"{Resx.Resource.StartUnzipping}\n{fileName}");

        Utils.Waiting(5);

        if (!File.Exists(fileName))
        {
            Console.WriteLine(Resx.Resource.UpgradeFileNotFound);
            return;
        }

        Console.WriteLine(Resx.Resource.TryTerminateProcess);
        try
        {
            var existing = Process.GetProcessesByName(Utils.V2rayN);
            foreach (var pp in existing)
            {
                var path = pp.MainModule?.FileName ?? "";
                if (path.StartsWith(Utils.GetPath(Utils.V2rayN)))
                {
                    pp?.Kill();
                    pp?.WaitForExit(1000);
                }
            }
        }
        catch (Exception ex)
        {
            // Access may be denied without admin right. The user may not be an administrator.
            Console.WriteLine(Resx.Resource.FailedTerminateProcess + ex.StackTrace);
        }

        Console.WriteLine(Resx.Resource.StartUnzipping);
        StringBuilder sb = new();
        var installedFiles = new HashSet<string>(UpdateFilesManifest.Comparer(Utils.GetPathComparison()));
        try
        {
            var thisAppOldFile = $"{Utils.GetExePath()}.tmp";
            File.Delete(thisAppOldFile);
            var splitKey = "/";
            var allowedBaseDir = Utils.StartupPath();
            var pathComparison = Utils.GetPathComparison();

            // The files of the version being replaced, as its update recorded them
            var previousFiles = UpdateFilesManifest.Load(allowedBaseDir, pathComparison);

            using var archive = ZipFile.OpenRead(fileName);
            foreach (var entry in archive.Entries)
            {
                try
                {
                    if (entry.Length == 0)
                    {
                        continue;
                    }

                    Console.WriteLine(entry.FullName);

                    var lst = entry.FullName.Split(splitKey);
                    if (lst.Length == 1)
                    {
                        continue;
                    }

                    var fullName = string.Join(splitKey, lst[1..lst.Length]);
                    var entryOutputPath = Utils.GetPath(fullName);
                    if (!Utils.IsPathUnderDirectory(allowedBaseDir, entryOutputPath))
                    {
                        Console.WriteLine($"{Resx.Resource.FailedUpgrade} blocked potential path traversal: {entry.FullName}");
                        return;
                    }

                    installedFiles.Add(UpdateFilesManifest.Normalize(fullName));

                    if (string.Equals(Utils.GetExePath(), entryOutputPath, pathComparison))
                    {
                        File.Move(Utils.GetExePath(), thisAppOldFile);
                    }

                    Directory.CreateDirectory(Path.GetDirectoryName(entryOutputPath)!);
                    //In the bin folder, if the file already exists, it will be skipped
                    if (fullName.StartsWith("bin", pathComparison) && File.Exists(entryOutputPath))
                    {
                        continue;
                    }

                    TryExtractToFile(entry, entryOutputPath);

                    Console.WriteLine(entryOutputPath);
                }
                catch (Exception ex)
                {
                    sb.Append(ex.StackTrace);
                }
            }

            // The clean part of the install: the files of the replaced version that this
            // archive does not carry are gone, so a file a later version renames or drops
            // cannot pile up, while the user's data and the cores are never touched.
            DeleteObsoleteFiles(previousFiles, installedFiles, allowedBaseDir, pathComparison);

            // The helper this archive replaces is of no use once its replacement is in
            // place. Linux lets a running image be deleted; Windows does not, so there
            // the replaced helper waits for this helper to exit before it goes.
            if (File.Exists(thisAppOldFile) && File.Exists(Utils.GetExePath()))
            {
                if (OperatingSystem.IsWindows())
                {
                    ScheduleReplacedHelperCleanup(thisAppOldFile);
                }
                else
                {
                    File.Delete(thisAppOldFile);
                }
            }

            // What this update installed is what the next update cleans by
            UpdateFilesManifest.Save(allowedBaseDir, installedFiles);
        }
        catch (Exception ex)
        {
            Console.WriteLine(Resx.Resource.FailedUpgrade + ex.StackTrace);
            //return;
        }
        if (sb.Length > 0)
        {
            Console.WriteLine(Resx.Resource.FailedUpgrade + sb.ToString());
            //return;
        }

        Console.WriteLine(Resx.Resource.Restartv2rayN);
        Utils.Waiting(2);

        Utils.StartV2RayN();
    }

    private static void DeleteObsoleteFiles(
        HashSet<string>? previousFiles,
        HashSet<string> installedFiles,
        string allowedBaseDir,
        StringComparison pathComparison)
    {
        if (previousFiles is null || previousFiles.Count == 0)
        {
            return;
        }

        foreach (var file in UpdateFilesManifest.FilesToDelete(previousFiles, installedFiles, pathComparison))
        {
            var fullPath = Utils.GetPath(file);
            if (!Utils.IsPathUnderDirectory(allowedBaseDir, fullPath))
            {
                continue;
            }

            try
            {
                if (File.Exists(fullPath))
                {
                    File.Delete(fullPath);
                    Console.WriteLine($"Deleted the file the update no longer carries: {file}");
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                Console.WriteLine($"Could not delete the file the update no longer carries '{file}': {exception.Message}");
            }
        }
    }

    // Windows denies deleting the executable image of a running process, so the copy
    // of the replaced helper is removed by a hidden PowerShell that waits for this
    // helper to exit, the way the native Web update cleans its helper. A helper that
    // cannot schedule its cleanup asks the system to delete the file at reboot.
    private static void ScheduleReplacedHelperCleanup(string replacedFile)
    {
        try
        {
            var powershell = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "WindowsPowerShell", "v1.0", "powershell.exe");
            var escapedPath = Path.GetFullPath(replacedFile).Replace("'", "''", StringComparison.Ordinal);
            var script = $"$targetPid={Environment.ProcessId};$targetPath='{escapedPath}';"
                + "for($i=0;$i -lt 600;$i++){if(-not(Get-Process -Id $targetPid -ErrorAction SilentlyContinue)){break};Start-Sleep -Milliseconds 100};"
                + "Remove-Item -LiteralPath $targetPath -Force -ErrorAction SilentlyContinue";
            var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
            var startInfo = new ProcessStartInfo
            {
                FileName = powershell,
                WorkingDirectory = Path.GetTempPath(),
                UseShellExecute = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            };
            startInfo.ArgumentList.Add("-NoLogo");
            startInfo.ArgumentList.Add("-NoProfile");
            startInfo.ArgumentList.Add("-NonInteractive");
            startInfo.ArgumentList.Add("-ExecutionPolicy");
            startInfo.ArgumentList.Add("Bypass");
            startInfo.ArgumentList.Add("-EncodedCommand");
            startInfo.ArgumentList.Add(encoded);
            Process.Start(startInfo)?.Dispose();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException
            or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            Console.WriteLine($"Could not schedule the cleanup of the replaced helper: {exception.Message}");
            MoveFileEx(Path.GetFullPath(replacedFile), null, MoveFileDelayUntilReboot);
        }
    }

    private const int MoveFileDelayUntilReboot = 0x00000004;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool MoveFileEx(string existingFileName, string? newFileName, int flags);

    private static bool TryExtractToFile(ZipArchiveEntry entry, string outputPath)
    {
        var retryCount = 5;
        var delayMs = 1000;

        for (var i = 1; i <= retryCount; i++)
        {
            try
            {
                entry.ExtractToFile(outputPath, true);
                return true;
            }
            catch
            {
                Thread.Sleep(delayMs * i);
            }
        }
        return false;
    }
}
