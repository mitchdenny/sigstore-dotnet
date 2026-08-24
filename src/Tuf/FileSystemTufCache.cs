using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

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
    private readonly FileSystemCacheStorage _storage;

    /// <summary>
    /// Creates a file-system cache rooted at the given directory.
    /// Metadata is stored in <paramref name="basePath"/> and
    /// targets in a <c>targets</c> subdirectory.
    /// </summary>
    public FileSystemTufCache(string basePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(basePath);

        _metadataDir = Path.GetFullPath(basePath);
        _targetsDir = Path.Combine(_metadataDir, "targets");
        _storage = new FileSystemCacheStorage(_metadataDir, _targetsDir);
    }

    /// <inheritdoc/>
    public byte[]? LoadMetadata(string role) =>
        _storage.Read(GetMetadataPath(role));

    /// <inheritdoc/>
    public void StoreMetadata(string role, byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        _storage.Write(
            GetMetadataPath(role),
            data,
            existing => ShouldReplaceMetadata(existing, data));
    }

    /// <inheritdoc/>
    public byte[]? LoadTarget(string targetPath) =>
        _storage.Read(GetTargetPath(targetPath));

    /// <inheritdoc/>
    public void StoreTarget(string targetPath, byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        _storage.Write(GetTargetPath(targetPath), data);
    }

    private string GetMetadataPath(string role) =>
        Path.Combine(_metadataDir, GetHashedFileName("metadata", role, ".json"));

    private string GetTargetPath(string targetPath) =>
        Path.Combine(_targetsDir, GetHashedFileName("target", targetPath, ".bin"));

    private static string GetHashedFileName(string kind, string key, string extension)
    {
        var keyBytes = Encoding.UTF8.GetBytes($"{kind}\0{key}");
        var hash = Convert.ToHexString(SHA256.HashData(keyBytes)).ToLowerInvariant();
        return $"{kind}-{hash}{extension}";
    }

    private static bool ShouldReplaceMetadata(byte[] existing, byte[] incoming)
    {
        var existingVersion = TryGetMetadataVersion(existing);
        var incomingVersion = TryGetMetadataVersion(incoming);
        return existingVersion is null ||
               incomingVersion is null ||
               incomingVersion.Value >= existingVersion.Value;
    }

    private static int? TryGetMetadataVersion(byte[] data)
    {
        try
        {
            using var document = JsonDocument.Parse(data);
            return document.RootElement
                .GetProperty("signed")
                .GetProperty("version")
                .GetInt32();
        }
        catch (Exception exception) when (
            exception is JsonException or InvalidOperationException or KeyNotFoundException)
        {
            return null;
        }
    }
}
