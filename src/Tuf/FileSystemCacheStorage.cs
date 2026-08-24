namespace Tuf;

/// <summary>
/// Provides the physical file guarantees used by <see cref="FileSystemTufCache"/>.
/// </summary>
internal sealed class FileSystemCacheStorage
{
    private const string LockFileName = ".lock";

    private const UnixFileMode DirectoryMode =
        UnixFileMode.UserRead |
        UnixFileMode.UserWrite |
        UnixFileMode.UserExecute;

    private const UnixFileMode OwnerFileMode =
        UnixFileMode.UserRead |
        UnixFileMode.UserWrite;

    private readonly string _lockPath;

    public FileSystemCacheStorage(string basePath, string targetsPath)
    {
        _lockPath = Path.Combine(basePath, LockFileName);
        IsEnabled =
            TryPrepareDirectory(basePath, allowLink: true) &&
            TryPrepareDirectory(targetsPath, allowLink: false);
    }

    public bool IsEnabled { get; private set; }

    public byte[]? Read(string path)
    {
        if (!IsEnabled)
        {
            return null;
        }

        if (IsLink(path) || Directory.Exists(path))
        {
            IsEnabled = false;
            return null;
        }

        if (!File.Exists(path))
        {
            return null;
        }

        if (!HasExpectedUnixMode(path, OwnerFileMode))
        {
            IsEnabled = false;
            return null;
        }

        try
        {
            using var stream = new FileStream(
                path,
                System.IO.FileMode.Open,
                FileAccess.Read,
                FileShare.Read | FileShare.Delete);
            if (stream.Length > int.MaxValue)
            {
                return null;
            }

            var data = new byte[(int)stream.Length];
            stream.ReadExactly(data);
            return data;
        }
        catch (Exception ex) when (IsFileSystemFailure(ex))
        {
            IsEnabled = false;
            return null;
        }
    }

    public void Write(
        string destinationPath,
        byte[] data,
        Func<byte[], bool>? shouldReplace = null)
    {
        if (!IsEnabled)
        {
            return;
        }

        var tempPath = StageFile(destinationPath, data);
        try
        {
            using var cacheLock = TryAcquireLock();
            if (cacheLock is null || Directory.Exists(destinationPath))
            {
                return;
            }

            if (shouldReplace is not null)
            {
                var existing = Read(destinationPath);
                if (existing is not null && !shouldReplace(existing))
                {
                    return;
                }
            }

            File.Move(tempPath, destinationPath, overwrite: true);
            tempPath = "";
        }
        finally
        {
            DeleteStagedFile(tempPath);
        }
    }

    private FileStream? TryAcquireLock()
    {
        if (!IsEnabled || IsLink(_lockPath) || Directory.Exists(_lockPath))
        {
            IsEnabled = false;
            return null;
        }

        try
        {
            var stream = CreatePrivateFile(
                _lockPath,
                FileMode.OpenOrCreate,
                FileShare.None);
            if (HasExpectedUnixMode(_lockPath, OwnerFileMode))
            {
                return stream;
            }

            stream.Dispose();
            IsEnabled = false;
            return null;
        }
        catch (Exception ex) when (IsFileSystemFailure(ex))
        {
            return null;
        }
    }

    private static string StageFile(string destinationPath, byte[] data)
    {
        var tempPath = Path.Combine(
            Path.GetDirectoryName(destinationPath)!,
            $".{Path.GetFileName(destinationPath)}.{Guid.NewGuid():N}.tmp");
        using var stream = CreatePrivateFile(
            tempPath,
            FileMode.CreateNew,
            FileShare.None);
        stream.Write(data);
        stream.Flush(flushToDisk: true);
        return tempPath;
    }

    private static void DeleteStagedFile(string tempPath)
    {
        if (string.IsNullOrEmpty(tempPath))
        {
            return;
        }

        try
        {
            File.Delete(tempPath);
        }
        catch (Exception ex) when (
            ex is FileNotFoundException or DirectoryNotFoundException)
        {
        }
    }

    private static FileStream CreatePrivateFile(
        string path,
        FileMode mode,
        FileShare share)
    {
        var options = new FileStreamOptions
        {
            Mode = mode,
            Access = FileAccess.ReadWrite,
            Share = share,
            Options = FileOptions.SequentialScan
        };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = OwnerFileMode;
        }

        return new FileStream(path, options);
    }

    private static bool TryPrepareDirectory(string path, bool allowLink)
    {
        try
        {
            if (!allowLink && IsLink(path))
            {
                return false;
            }

            if (!Directory.Exists(path))
            {
                if (OperatingSystem.IsWindows())
                {
                    Directory.CreateDirectory(path);
                }
                else
                {
                    Directory.CreateDirectory(path, DirectoryMode);
                }
            }

            return Directory.Exists(path) &&
                   HasExpectedUnixMode(path, DirectoryMode);
        }
        catch (Exception ex) when (IsFileSystemFailure(ex))
        {
            return false;
        }
    }

    private static bool HasExpectedUnixMode(string path, UnixFileMode expectedMode)
    {
        if (OperatingSystem.IsWindows())
        {
            return true;
        }

        try
        {
            return File.GetUnixFileMode(path) == expectedMode;
        }
        catch (Exception ex) when (IsFileSystemFailure(ex))
        {
            return false;
        }
    }

    private static bool IsLink(string path)
    {
        try
        {
            var info = new FileInfo(path);
            return info.LinkTarget is not null ||
                   info.Exists && (info.Attributes & FileAttributes.ReparsePoint) != 0;
        }
        catch (Exception ex) when (IsFileSystemFailure(ex))
        {
            return true;
        }
    }

    private static bool IsFileSystemFailure(Exception exception) =>
        exception is IOException or UnauthorizedAccessException;
}
