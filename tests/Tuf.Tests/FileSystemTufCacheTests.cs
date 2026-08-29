using System.Diagnostics;
using System.Text.Json;

namespace Tuf.Tests;

[TestClass]
public sealed class FileSystemTufCacheTests
{
    [TestMethod]
    public void TargetKeys_CannotEscapeCacheDirectory()
    {
        using var directory = new TemporaryDirectory();
        var cache = new FileSystemTufCache(directory.Path);
        var data = "target"u8.ToArray();
        var absolutePath = Path.Combine(
            Path.GetPathRoot(directory.Path)!,
            $"tuf-cache-{Guid.NewGuid():N}");

        cache.StoreTarget("../../outside", data);
        cache.StoreTarget(absolutePath, data);

        TestSeq.AreEqual(data, cache.LoadTarget("../../outside"));
        TestSeq.AreEqual(data, cache.LoadTarget(absolutePath));
        Assert.IsFalse(File.Exists(Path.Combine(directory.Path, "outside")));
        Assert.IsFalse(File.Exists(absolutePath));
        TestSeq.All(
            Directory.GetFiles(Path.Combine(directory.Path, "targets")),
            path => Assert.AreEqual(Path.Combine(directory.Path, "targets"), Path.GetDirectoryName(path)));
    }

    [TestMethod]
    public void MetadataKeys_AreFlattenedAndRoundTrip()
    {
        using var directory = new TemporaryDirectory();
        var cache = new FileSystemTufCache(directory.Path);
        var data = Metadata(1);

        cache.StoreMetadata("../delegatedrole", data);

        TestSeq.AreEqual(data, cache.LoadMetadata("../delegatedrole"));
        Assert.DoesNotContain(
            path => Path.GetFileName(path).Contains("delegatedrole", StringComparison.Ordinal),
            Directory.GetFiles(directory.Path));
    }

    [TestMethod]
    public void NewUnixPaths_AreOwnerOnly()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var directory = new TemporaryDirectory(create: false);
        var cache = new FileSystemTufCache(directory.Path);

        cache.StoreTarget("trusted_root.json", "target"u8.ToArray());

        Assert.AreEqual(
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute,
            File.GetUnixFileMode(directory.Path));
        Assert.AreEqual(
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute,
            File.GetUnixFileMode(Path.Combine(directory.Path, "targets")));
        foreach (var path in Directory.GetFiles(directory.Path, "*", SearchOption.AllDirectories))
        {
            Assert.AreEqual(
                UnixFileMode.UserRead | UnixFileMode.UserWrite,
                File.GetUnixFileMode(path));
        }
    }

    [TestMethod]
    public void IncorrectUnixFileMode_DisablesCache()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var directory = new TemporaryDirectory();
        var cache = new FileSystemTufCache(directory.Path);
        cache.StoreTarget("trusted_root.json", "current"u8.ToArray());
        var targetsPath = Path.Combine(directory.Path, "targets");
        var cachedTarget = TestSeq.Single(
            Directory.GetFiles(targetsPath, "target-*.bin"));
        File.SetUnixFileMode(
            cachedTarget,
            UnixFileMode.UserRead |
            UnixFileMode.UserWrite |
            UnixFileMode.GroupRead |
            UnixFileMode.OtherRead);

        cache = new FileSystemTufCache(directory.Path);

        Assert.IsNull(cache.LoadTarget("trusted_root.json"));
        cache.StoreTarget("other.json", "other"u8.ToArray());
        Assert.IsNull(cache.LoadTarget("other.json"));
        Assert.AreEqual(
            UnixFileMode.UserRead |
            UnixFileMode.UserWrite |
            UnixFileMode.GroupRead |
            UnixFileMode.OtherRead,
            File.GetUnixFileMode(cachedTarget));
    }

    [TestMethod]
    public void IncorrectUnixDirectoryMode_DisablesCache()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var directory = new TemporaryDirectory();
        var targetsPath = Path.Combine(directory.Path, "targets");
        Directory.CreateDirectory(targetsPath);
        var incorrectMode =
            UnixFileMode.UserRead |
            UnixFileMode.UserWrite |
            UnixFileMode.UserExecute |
            UnixFileMode.GroupRead |
            UnixFileMode.GroupExecute;
        File.SetUnixFileMode(directory.Path, incorrectMode);
        File.SetUnixFileMode(targetsPath, incorrectMode);

        var cache = new FileSystemTufCache(directory.Path);
        cache.StoreTarget("artifact", "data"u8.ToArray());

        Assert.IsNull(cache.LoadTarget("artifact"));
        Assert.AreEqual(incorrectMode, File.GetUnixFileMode(directory.Path));
        Assert.AreEqual(incorrectMode, File.GetUnixFileMode(targetsPath));
    }

    [TestMethod]
    public void LeafSymlink_DisablesCacheWithoutFollowing()
    {
        using var directory = new TemporaryDirectory();
        var cache = new FileSystemTufCache(directory.Path);
        cache.StoreTarget("trusted_root.json", "initial"u8.ToArray());
        var cachedPath = TestSeq.Single(
            Directory.GetFiles(Path.Combine(directory.Path, "targets"), "target-*.bin"));
        File.Delete(cachedPath);

        var outsidePath = Path.Combine(directory.Path, "outside");
        File.WriteAllText(outsidePath, "outside");
        if (!TryCreateFileSymlink(cachedPath, outsidePath))
        {
            return;
        }

        Assert.IsNull(cache.LoadTarget("trusted_root.json"));

        cache.StoreTarget("trusted_root.json", "replacement"u8.ToArray());

        Assert.AreEqual("outside", File.ReadAllText(outsidePath));
        Assert.IsNull(cache.LoadTarget("trusted_root.json"));
        Assert.IsNotNull(new FileInfo(cachedPath).LinkTarget);
    }

    [TestMethod]
    public void ManagedTargetsDirectorySymlink_DisablesCache()
    {
        using var outside = new TemporaryDirectory();
        using var directory = new TemporaryDirectory();
        var targetsPath = Path.Combine(directory.Path, "targets");
        if (!TryCreateDirectorySymlink(targetsPath, outside.Path))
        {
            return;
        }

        var cache = new FileSystemTufCache(directory.Path);
        cache.StoreTarget("artifact", "data"u8.ToArray());

        Assert.IsNull(cache.LoadTarget("artifact"));
        Assert.IsEmpty(Directory.GetFiles(outside.Path));
    }

    [TestMethod]
    public void CallerSuppliedCacheRootSymlink_IsSupported()
    {
        using var destination = new TemporaryDirectory();
        using var parent = new TemporaryDirectory();
        var cachePath = Path.Combine(parent.Path, "cache");
        if (!TryCreateDirectorySymlink(cachePath, destination.Path))
        {
            return;
        }

        var cache = new FileSystemTufCache(cachePath);
        cache.StoreTarget("artifact", "data"u8.ToArray());

        TestSeq.AreEqual("data"u8.ToArray(), cache.LoadTarget("artifact"));
    }

    [TestMethod]
    public void MetadataVersion_NeverMovesBackward()
    {
        using var directory = new TemporaryDirectory();
        var cache = new FileSystemTufCache(directory.Path);

        cache.StoreMetadata("targets", Metadata(10));
        cache.StoreMetadata("targets", Metadata(9));

        Assert.AreEqual(10, ReadVersion(cache.LoadMetadata("targets")!));
    }

    [TestMethod]
    public async Task CrossProcessReads_ObserveOnlyCompleteFiles()
    {
        using var directory = new TemporaryDirectory();
        var cache = new FileSystemTufCache(directory.Path);
        var first = Enumerable.Repeat((byte)0x41, 256 * 1024).ToArray();
        var second = Enumerable.Repeat((byte)0x42, 256 * 1024).ToArray();
        cache.StoreTarget("artifact", first);

        using var writer = StartWorker(
            "write-loop",
            directory.Path,
            "artifact",
            "41",
            "42",
            first.Length.ToString(),
            "100");

        var reads = 0;
        while (!writer.HasExited)
        {
            var value = cache.LoadTarget("artifact");
            Assert.IsNotNull(value);
            Assert.IsTrue(value.AsSpan().SequenceEqual(first) || value.AsSpan().SequenceEqual(second));
            reads++;
        }

        await AssertWorkerSucceeded(writer);
        Assert.IsTrue(reads > 0);
    }

    [TestMethod]
    public async Task CrossProcessLockContention_DoesNotBlockOrPersist()
    {
        using var directory = new TemporaryDirectory();
        using var ready = new TemporaryPath();
        using var release = new TemporaryPath();
        var cache = new FileSystemTufCache(directory.Path);
        using var holder = StartWorker("hold-lock", directory.Path, ready.Path, release.Path);
        await WaitForFile(ready.Path);

        await Task.Run(() => cache.StoreTarget("blocked", "data"u8.ToArray()))
            .WaitAsync(TimeSpan.FromSeconds(2));

        Assert.IsNull(cache.LoadTarget("blocked"));
        File.WriteAllText(release.Path, "release");
        await AssertWorkerSucceeded(holder);
    }

    [TestMethod]
    public async Task CrossProcessLock_IsReleasedWhenHolderExits()
    {
        using var directory = new TemporaryDirectory();
        using var ready = new TemporaryPath();
        using var release = new TemporaryPath();
        var cache = new FileSystemTufCache(directory.Path);
        using var holder = StartWorker("hold-lock", directory.Path, ready.Path, release.Path);
        await WaitForFile(ready.Path);

        holder.Kill(entireProcessTree: true);
        await holder.WaitForExitAsync();
        var expected = "data"u8.ToArray();
        var timeout = DateTime.UtcNow.AddSeconds(5);
        byte[]? actual;
        do
        {
            cache.StoreTarget("after-crash", expected);
            actual = cache.LoadTarget("after-crash");
            if (actual is null)
            {
                await Task.Delay(10);
            }
        }
        while (actual is null && DateTime.UtcNow < timeout);

        TestSeq.AreEqual(expected, actual);
    }

    [TestMethod]
    public async Task CrossProcessStaleWriters_CannotRollMetadataBack()
    {
        using var directory = new TemporaryDirectory();
        var cache = new FileSystemTufCache(directory.Path);
        cache.StoreMetadata("targets", Metadata(10));

        var writers = Enumerable.Range(1, 9)
            .Select(version => StartWorker(
                "write-metadata",
                directory.Path,
                "targets",
                version.ToString()))
            .ToArray();

        try
        {
            foreach (var writer in writers)
            {
                await AssertWorkerSucceeded(writer);
            }
        }
        finally
        {
            foreach (var writer in writers)
            {
                writer.Dispose();
            }
        }

        Assert.AreEqual(10, ReadVersion(cache.LoadMetadata("targets")!));
    }

    private static byte[] Metadata(int version) =>
        JsonSerializer.SerializeToUtf8Bytes(new { signed = new { version } });

    private static int ReadVersion(byte[] metadata)
    {
        using var document = JsonDocument.Parse(metadata);
        return document.RootElement.GetProperty("signed").GetProperty("version").GetInt32();
    }

    private static bool TryCreateFileSymlink(string path, string target)
    {
        try
        {
            File.CreateSymbolicLink(path, target);
            return true;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch (PlatformNotSupportedException)
        {
            return false;
        }
    }

    private static bool TryCreateDirectorySymlink(string path, string target)
    {
        try
        {
            Directory.CreateSymbolicLink(path, target);
            return true;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch (PlatformNotSupportedException)
        {
            return false;
        }
    }

    private static Process StartWorker(params string[] arguments)
    {
        var startInfo = new ProcessStartInfo("dotnet")
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false
        };
        startInfo.ArgumentList.Add(GetWorkerPath());
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        return Process.Start(startInfo)
            ?? throw new InvalidOperationException("Failed to start cache test worker.");
    }

    private static string GetWorkerPath()
    {
        var outputDirectory = new DirectoryInfo(AppContext.BaseDirectory);
        var configuration = outputDirectory.Parent?.Name
            ?? throw new InvalidOperationException("Build configuration not found.");
        var directory = outputDirectory;
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Sigstore.slnx")))
        {
            directory = directory.Parent;
        }

        return Path.Combine(
            directory?.FullName ?? throw new InvalidOperationException("Repository root not found."),
            "tests",
            "Tuf.CacheTestWorker",
            "bin",
            configuration,
            "net10.0",
            "Tuf.CacheTestWorker.dll");
    }

    private static async Task AssertWorkerSucceeded(Process process)
    {
        await process.WaitForExitAsync();
        if (process.ExitCode == 0)
        {
            return;
        }

        var output = await process.StandardOutput.ReadToEndAsync();
        var error = await process.StandardError.ReadToEndAsync();
        Assert.Fail($"Worker exited with {process.ExitCode}.{Environment.NewLine}{output}{error}");
    }

    private static async Task WaitForFile(string path)
    {
        var timeout = DateTime.UtcNow.AddSeconds(10);
        while (!File.Exists(path) && DateTime.UtcNow < timeout)
        {
            await Task.Delay(10);
        }

        Assert.IsTrue(File.Exists(path), $"Worker did not create '{path}'.");
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public string Path { get; } =
            System.IO.Path.Combine(System.IO.Path.GetTempPath(), Guid.NewGuid().ToString("N"));

        public TemporaryDirectory(bool create = true)
        {
            if (create)
            {
                if (OperatingSystem.IsWindows())
                {
                    Directory.CreateDirectory(Path);
                }
                else
                {
                    Directory.CreateDirectory(
                        Path,
                        UnixFileMode.UserRead |
                        UnixFileMode.UserWrite |
                        UnixFileMode.UserExecute);
                }
            }
        }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }

    private sealed class TemporaryPath : IDisposable
    {
        public string Path { get; } =
            System.IO.Path.Combine(System.IO.Path.GetTempPath(), Guid.NewGuid().ToString("N"));

        public void Dispose()
        {
            File.Delete(Path);
        }
    }
}
