using System.ComponentModel;
using System.Runtime.InteropServices;

namespace ServiceLib.Discovery.Services;

/// <summary>
/// Same-directory durable atomic replacement for small/medium application artifacts.
/// File contents are flushed before replacement. Windows requests write-through rename;
/// Unix fsyncs the parent directory after rename when the platform supports directory fsync.
/// </summary>
internal static class DurableAtomicFile
{
    private const uint MoveFileReplaceExisting = 0x00000001;
    private const uint MoveFileWriteThrough = 0x00000008;
    private const int OReadOnly = 0;
    private const int ErrorInvalidArgument = 22;
    private const int ErrorOperationNotSupportedLinux = 95;
    private const int ErrorOperationNotSupportedMac = 45;

    public static async Task WriteAsync(
        string destinationPath,
        ReadOnlyMemory<byte> bytes,
        Func<CancellationToken, Task>? beforeReplace = null,
        CancellationToken cancellationToken = default)
    {
        destinationPath = Path.GetFullPath(destinationPath);
        var directory = Path.GetDirectoryName(destinationPath)
            ?? throw new InvalidOperationException("Atomic-file destination has no parent directory.");
        if (!Directory.Exists(directory))
        {
            throw new DirectoryNotFoundException($"Atomic-file destination directory does not exist: {directory}");
        }

        var temp = Path.Combine(
            directory,
            "." + Path.GetFileName(destinationPath) + ".tmp-" + Guid.NewGuid().ToString("N"));

        try
        {
            await using (var stream = new FileStream(
                temp,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                64 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(bytes, cancellationToken);
                await stream.FlushAsync(cancellationToken);
                stream.Flush(flushToDisk: true);
            }

            if (beforeReplace is not null)
            {
                await beforeReplace(cancellationToken);
            }
            cancellationToken.ThrowIfCancellationRequested();

            Replace(temp, destinationPath);
            FlushParentDirectory(directory);
        }
        finally
        {
            if (File.Exists(temp))
            {
                File.Delete(temp);
            }
        }
    }

    public static void Delete(string destinationPath)
    {
        destinationPath = Path.GetFullPath(destinationPath);
        if (!File.Exists(destinationPath))
        {
            return;
        }

        var directory = Path.GetDirectoryName(destinationPath)
            ?? throw new InvalidOperationException("Durable-delete destination has no parent directory.");
        File.Delete(destinationPath);
        FlushParentDirectory(directory);
    }

    private static void Replace(string sourcePath, string destinationPath)
    {
        if (OperatingSystem.IsWindows())
        {
            if (!MoveFileExW(
                    sourcePath,
                    destinationPath,
                    MoveFileReplaceExisting | MoveFileWriteThrough))
            {
                throw new Win32Exception(
                    Marshal.GetLastPInvokeError(),
                    $"Durable atomic replacement failed for '{destinationPath}'.");
            }
            return;
        }

        File.Move(sourcePath, destinationPath, overwrite: true);
    }

    private static void FlushParentDirectory(string directory)
    {
        if (OperatingSystem.IsWindows())
        {
            // MOVEFILE_WRITE_THROUGH asks the platform to flush the rename before returning.
            return;
        }
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
        {
            return;
        }

        var fd = Open(directory, OReadOnly);
        if (fd < 0)
        {
            throw new IOException(
                $"Could not open parent directory for durability sync: {directory}",
                new Win32Exception(Marshal.GetLastPInvokeError()));
        }

        try
        {
            if (Fsync(fd) == 0)
            {
                return;
            }

            var error = Marshal.GetLastPInvokeError();
            if (error is ErrorInvalidArgument
                or ErrorOperationNotSupportedLinux
                or ErrorOperationNotSupportedMac)
            {
                // Some filesystems/platforms do not support fsync on directory descriptors.
                // The file data is still flushed and the rename remains atomic, but the
                // platform cannot provide the stronger post-power-loss directory guarantee.
                return;
            }

            throw new IOException(
                $"Could not sync parent directory after atomic replacement: {directory}",
                new Win32Exception(error));
        }
        finally
        {
            _ = Close(fd);
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MoveFileExW(
        string existingFileName,
        string newFileName,
        uint flags);

    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int Open(string path, int flags);

    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static extern int Fsync(int fd);

    [DllImport("libc", EntryPoint = "close", SetLastError = true)]
    private static extern int Close(int fd);
}
