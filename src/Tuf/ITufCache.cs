namespace Tuf;

/// <summary>
/// Abstraction over local caching of TUF metadata and targets.
/// </summary>
public interface ITufCache
{
    /// <summary>
    /// Loads cached metadata for a given role.
    /// </summary>
    /// <param name="role">The role name (e.g., "root", "timestamp").</param>
    /// <returns>The cached metadata bytes, or null if not cached.</returns>
    byte[]? LoadMetadata(string role);

    /// <summary>
    /// Stores metadata for a given role in the cache.
    /// </summary>
    /// <param name="role">The role name.</param>
    /// <param name="data">The metadata bytes to cache.</param>
    void StoreMetadata(string role, byte[] data);

    /// <summary>
    /// Loads a cached target file.
    /// </summary>
    /// <param name="targetPath">The target path.</param>
    /// <returns>The cached target bytes, or null if not cached.</returns>
    byte[]? LoadTarget(string targetPath);

    /// <summary>
    /// Stores a target file in the cache.
    /// </summary>
    /// <param name="targetPath">The target path.</param>
    /// <param name="data">The target bytes to cache.</param>
    void StoreTarget(string targetPath, byte[] data);
}
