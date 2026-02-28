namespace Tuf;

/// <summary>
/// A file-system backed cache for TUF metadata and targets.
/// Persists metadata to disk so subsequent TUF refreshes can avoid
/// re-walking the entire root chain from the bootstrap root.
/// </summary>
public sealed class FileSystemTufCache : ITufCache
{
    private readonly string _metadataDir;
    private readonly string _targetsDir;

    /// <summary>
    /// Creates a file-system cache rooted at the given directory.
    /// Metadata is stored in <paramref name="basePath"/> and
    /// targets in a <c>targets</c> subdirectory.
    /// </summary>
    public FileSystemTufCache(string basePath)
    {
        _metadataDir = basePath;
        _targetsDir = Path.Combine(basePath, "targets");
        Directory.CreateDirectory(_metadataDir);
        Directory.CreateDirectory(_targetsDir);
    }

    /// <inheritdoc/>
    public byte[]? LoadMetadata(string role)
    {
        var path = Path.Combine(_metadataDir, $"{role}.json");
        return File.Exists(path) ? File.ReadAllBytes(path) : null;
    }

    /// <inheritdoc/>
    public void StoreMetadata(string role, byte[] data)
    {
        var path = Path.Combine(_metadataDir, $"{role}.json");
        File.WriteAllBytes(path, data);
    }

    /// <inheritdoc/>
    public byte[]? LoadTarget(string targetPath)
    {
        var path = Path.Combine(_targetsDir, targetPath);
        return File.Exists(path) ? File.ReadAllBytes(path) : null;
    }

    /// <inheritdoc/>
    public void StoreTarget(string targetPath, byte[] data)
    {
        var path = Path.Combine(_targetsDir, targetPath);
        var dir = Path.GetDirectoryName(path);
        if (dir != null)
            Directory.CreateDirectory(dir);
        File.WriteAllBytes(path, data);
    }
}
