using System.Text;
using ServiceLib.Discovery.Services;

namespace ServiceLib.Tests.Reviver;

public class DurableAtomicFileTests
{
    [Test]
    public async Task WriteAsync_ShouldReplaceContentAndLeaveNoTempFile()
    {
        var root = CreateTempDirectory();
        try
        {
            var path = Path.Combine(root, "state.json");
            await File.WriteAllTextAsync(path, "before");

            await DurableAtomicFile.WriteAsync(
                path,
                Encoding.UTF8.GetBytes("after"));

            await (await File.ReadAllTextAsync(path)).Should().BeEqualTo("after");
            await Directory.GetFiles(root, ".state.json.tmp-*").Length.Should().BeEqualTo(0);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Test]
    public async Task WriteAsync_ShouldRunPreReplaceGuardBeforeMutation()
    {
        var root = CreateTempDirectory();
        try
        {
            var path = Path.Combine(root, "state.json");
            await File.WriteAllTextAsync(path, "before");

            var threw = false;
            try
            {
                await DurableAtomicFile.WriteAsync(
                    path,
                    Encoding.UTF8.GetBytes("after"),
                    _ => throw new InvalidOperationException("stale"));
            }
            catch (InvalidOperationException ex)
            {
                threw = ex.Message == "stale";
            }

            await threw.Should().BeTrue();
            await (await File.ReadAllTextAsync(path)).Should().BeEqualTo("before");
            await Directory.GetFiles(root, ".state.json.tmp-*").Length.Should().BeEqualTo(0);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Test]
    public async Task Delete_ShouldRemoveFileAndBeIdempotent()
    {
        var root = CreateTempDirectory();
        try
        {
            var path = Path.Combine(root, "state.json");
            await File.WriteAllTextAsync(path, "payload");

            DurableAtomicFile.Delete(path);
            DurableAtomicFile.Delete(path);

            await File.Exists(path).Should().BeFalse();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static string CreateTempDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "pattn-durable-file-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }
}
