namespace Tuf;

/// <summary>
/// Abstraction over fetching metadata and targets from a TUF repository.
/// </summary>
public interface ITufRepository
{
    /// <summary>
    /// Fetches metadata for a given role and optional version.
    /// </summary>
    /// <param name="role">The role name (e.g., "root", "timestamp").</param>
    /// <param name="version">Optional version number. If specified, fetches versioned metadata (e.g., "2.root.json").</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The raw metadata bytes, or null if not found (404).</returns>
    Task<byte[]?> FetchMetadataAsync(string role, int? version = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Fetches a target file.
    /// </summary>
    /// <param name="targetPath">The target path as specified in targets metadata.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The raw target bytes, or null if not found.</returns>
    Task<byte[]?> FetchTargetAsync(string targetPath, CancellationToken cancellationToken = default);
}
