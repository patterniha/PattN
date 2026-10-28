using System.Text.Json;

namespace AmazTool;

// The list of the files an update installed, kept beside the application so the next
// update can delete the files of the replaced version that the new archive no longer
// carries. The manifest is written after every upgrade and never travels in the release
// archive: a version older than this feature leaves none, and that first update cleans
// nothing but the helper it replaces.
internal static class UpdateFilesManifest
{
    internal const string FileName = "AmazTool.update-files.json";

    // The directories an update never owns and so never deletes from: the user's
    // configuration and logs, and the cores, geo files and rule sets the application
    // keeps under bin.
    private static readonly string[] ProtectedDirectories = ["bin", "binConfigs", "guiConfigs", "guiLogs"];

    // The executables are never candidates either: a packaging that lost one must not
    // have the updater delete the last copy of the program it is replacing.
    private static readonly string[] ProtectedFiles = ["PattN", "PattN.exe", "AmazTool", "AmazTool.exe"];

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    internal static StringComparer Comparer(StringComparison pathComparison) =>
        pathComparison == StringComparison.Ordinal ? StringComparer.Ordinal : StringComparer.OrdinalIgnoreCase;

    internal static HashSet<string>? Load(string installDirectory, StringComparison pathComparison)
    {
        try
        {
            var path = Path.Combine(installDirectory, FileName);
            if (!File.Exists(path))
            {
                return null;
            }

            var manifest = JsonSerializer.Deserialize<ManifestFile>(File.ReadAllText(path), JsonOptions);
            if (manifest?.Files is null || manifest.Files.Count == 0)
            {
                return null;
            }

            var files = new HashSet<string>(Comparer(pathComparison));
            foreach (var file in manifest.Files)
            {
                if (!string.IsNullOrWhiteSpace(file))
                {
                    files.Add(Normalize(file));
                }
            }
            return files.Count == 0 ? null : files;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            Console.WriteLine($"Could not read the update files manifest: {exception.Message}");
            return null;
        }
    }

    internal static void Save(string installDirectory, IReadOnlyCollection<string> files)
    {
        try
        {
            var manifest = new ManifestFile
            {
                Files = [.. files.Select(Normalize).Where(file => file.Length > 0).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)],
            };
            File.WriteAllText(Path.Combine(installDirectory, FileName), JsonSerializer.Serialize(manifest, JsonOptions));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            Console.WriteLine($"Could not record the update files manifest: {exception.Message}");
        }
    }

    // The archive writes its separators as it pleases; the manifest compares its
    // entries as one list.
    internal static string Normalize(string entry)
    {
        var segments = entry.Split('/', StringSplitOptions.RemoveEmptyEntries);
        return segments.Length == 0 ? string.Empty : string.Join('/', segments);
    }

    // The files of the replaced version the new archive does not carry. The user's
    // data and the cores are never candidates, and the manifest is never its own
    // candidate: losing it would end the clean installs.
    internal static List<string> FilesToDelete(HashSet<string>? previousFiles, HashSet<string> currentFiles, StringComparison pathComparison)
    {
        if (previousFiles is null || previousFiles.Count == 0)
        {
            return [];
        }

        var previous = Clean(previousFiles, pathComparison);
        var current = Clean(currentFiles, pathComparison);
        return
        [
            .. previous
                .Where(file => file != FileName
                    && !IsProtected(file, pathComparison)
                    && !current.Contains(file))
                .Order(StringComparer.Ordinal),
        ];
    }

    private static HashSet<string> Clean(IEnumerable<string> entries, StringComparison pathComparison)
    {
        var files = new HashSet<string>(Comparer(pathComparison));
        foreach (var entry in entries)
        {
            var normalized = Normalize(entry);
            if (normalized.Length > 0)
            {
                files.Add(normalized);
            }
        }
        return files;
    }

    private static bool IsProtected(string file, StringComparison pathComparison)
    {
        var separator = file.IndexOf('/');
        if (separator < 0)
        {
            return ProtectedFiles.Any(executable => string.Equals(executable, file, pathComparison));
        }

        var first = file[..separator];
        return ProtectedDirectories.Any(directory => string.Equals(directory, first, pathComparison));
    }

    private sealed record ManifestFile
    {
        public int Version { get; init; } = 1;
        public List<string> Files { get; init; } = [];
    }
}
