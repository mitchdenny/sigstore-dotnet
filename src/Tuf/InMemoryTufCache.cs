using System.Collections.Concurrent;

namespace Tuf;

/// <summary>
/// An in-memory cache implementation for TUF metadata and targets.
/// Useful for testing and embedded scenarios.
/// </summary>
public sealed class InMemoryTufCache : ITufCache
{
    private readonly ConcurrentDictionary<string, byte[]> _metadata = new();
    private readonly ConcurrentDictionary<string, byte[]> _targets = new();

    /// <inheritdoc/>
    public byte[]? LoadMetadata(string role) =>
        _metadata.TryGetValue(role, out var data) ? data : null;

    /// <inheritdoc/>
    public void StoreMetadata(string role, byte[] data) =>
        _metadata[role] = data;

    /// <inheritdoc/>
    public byte[]? LoadTarget(string targetPath) =>
        _targets.TryGetValue(targetPath, out var data) ? data : null;

    /// <inheritdoc/>
    public void StoreTarget(string targetPath, byte[] data) =>
        _targets[targetPath] = data;
}
