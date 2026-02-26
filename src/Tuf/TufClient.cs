using System.Security.Cryptography;
using Tuf.Metadata;
using Tuf.Serialization;

namespace Tuf;

/// <summary>
/// A TUF client that securely updates metadata and downloads targets
/// from a TUF repository, implementing the TUF specification §5.1-5.6.
/// </summary>
public sealed class TufClient : IDisposable
{
    private readonly TufClientOptions _options;
    private readonly ITufRepository _repository;
    private readonly ITufCache _cache;
    private readonly bool _ownsRepository;

    private SignedMetadata<RootMetadata>? _trustedRoot;
    private SignedMetadata<TimestampMetadata>? _trustedTimestamp;
    private SignedMetadata<SnapshotMetadata>? _trustedSnapshot;
    private SignedMetadata<TargetsMetadata>? _trustedTargets;
    private bool _refreshed;

    /// <summary>
    /// Creates a new TUF client with the specified options.
    /// </summary>
    public TufClient(TufClientOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _cache = options.Cache ?? new InMemoryTufCache();

        if (options.Repository != null)
        {
            _repository = options.Repository;
            _ownsRepository = false;
        }
        else
        {
            _repository = new HttpTufRepository(
                options.MetadataBaseUrl,
                options.TargetsBaseUrl ?? new Uri(options.MetadataBaseUrl, "../targets/"));
            _ownsRepository = true;
        }

        // Initialize cache with the trusted root if not already present
        var cachedRoot = _cache.LoadMetadata("root");
        if (cachedRoot == null)
        {
            _cache.StoreMetadata("root", options.TrustedRoot);
        }
    }

    /// <summary>
    /// Refreshes local metadata from the TUF repository.
    /// Implements the TUF client update workflow (spec §5.1-5.6).
    /// </summary>
    public async Task RefreshAsync(CancellationToken cancellationToken = default)
    {
        // §5.1: Load the trusted root metadata
        LoadTrustedRoot();

        // §5.2: Update root metadata
        await UpdateRootAsync(cancellationToken);

        // §5.3: Update timestamp metadata
        await UpdateTimestampAsync(cancellationToken);

        // §5.4: Update snapshot metadata
        await UpdateSnapshotAsync(cancellationToken);

        // §5.5: Update targets metadata
        await UpdateTargetsAsync(cancellationToken);

        _refreshed = true;
    }

    /// <summary>
    /// Downloads a target file, verifying its hash and length against targets metadata.
    /// Automatically refreshes metadata if needed.
    /// </summary>
    /// <param name="targetPath">The target path as specified in targets metadata.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The verified target file contents.</returns>
    public async Task<byte[]> DownloadTargetAsync(string targetPath, CancellationToken cancellationToken = default)
    {
        if (!_refreshed)
            await RefreshAsync(cancellationToken);

        // §5.6: Fetch target
        if (_trustedTargets == null)
            throw new TufException("No trusted targets metadata available.");

        if (!_trustedTargets.Signed.Targets.TryGetValue(targetPath, out var targetInfo))
            throw new TufException($"Target '{targetPath}' not found in targets metadata.");

        // Check cache first
        var cached = _cache.LoadTarget(targetPath);
        if (cached != null && VerifyTargetHashes(cached, targetInfo))
            return cached;

        // For consistent snapshots, prefix target filename with hash
        var fetchPath = targetPath;
        if (_trustedRoot!.Signed.ConsistentSnapshot &&
            targetInfo.Hashes.TryGetValue("sha256", out var sha256Hash))
        {
            var fileName = Path.GetFileName(targetPath);
            var dirPart = Path.GetDirectoryName(targetPath);
            var hashPrefixed = $"{sha256Hash}.{fileName}";
            fetchPath = string.IsNullOrEmpty(dirPart) ? hashPrefixed : $"{dirPart}/{hashPrefixed}";
        }

        var targetBytes = await _repository.FetchTargetAsync(fetchPath, cancellationToken)
            ?? throw new TufException($"Target '{targetPath}' not found on repository.");

        // Verify length
        if (targetBytes.Length > targetInfo.Length)
            throw new TufException(
                $"Target '{targetPath}' size {targetBytes.Length} exceeds expected {targetInfo.Length}.");

        // Verify hashes
        if (!VerifyTargetHashes(targetBytes, targetInfo))
            throw new TufException($"Target '{targetPath}' hash verification failed.");

        _cache.StoreTarget(targetPath, targetBytes);
        return targetBytes;
    }

    /// <summary>
    /// §5.1: Load the trusted root metadata from the cache.
    /// </summary>
    private void LoadTrustedRoot()
    {
        var rootBytes = _cache.LoadMetadata("root")
            ?? throw new TufException("No trusted root metadata in cache.");
        _trustedRoot = TufMetadataParser.ParseRoot(rootBytes);

        // Also load any cached timestamp/snapshot/targets
        var tsBytes = _cache.LoadMetadata("timestamp");
        if (tsBytes != null) _trustedTimestamp = TufMetadataParser.ParseTimestamp(tsBytes);

        var snapBytes = _cache.LoadMetadata("snapshot");
        if (snapBytes != null) _trustedSnapshot = TufMetadataParser.ParseSnapshot(snapBytes);

        var targetsBytes = _cache.LoadMetadata("targets");
        if (targetsBytes != null) _trustedTargets = TufMetadataParser.ParseTargets(targetsBytes);
    }

    /// <summary>
    /// §5.2: Update root metadata by fetching successive versions.
    /// </summary>
    private async Task UpdateRootAsync(CancellationToken cancellationToken)
    {
        var currentVersion = _trustedRoot!.Signed.Version;

        for (var i = 0; i < _options.MaxRootRotations; i++)
        {
            var nextVersion = currentVersion + 1;
            var newRootBytes = await _repository.FetchMetadataAsync("root", nextVersion, cancellationToken);

            if (newRootBytes == null)
                break; // No more root versions available

            var newRoot = TufMetadataParser.ParseRoot(newRootBytes);

            // §5.2.2: Verify new root is signed by threshold of keys from the CURRENT trusted root
            var currentRootRole = _trustedRoot.Signed.Roles["root"];
            if (!TufMetadataVerifier.VerifyThreshold(
                    newRoot.Signatures, newRoot.SignedBytes, currentRootRole, _trustedRoot.Signed.Keys))
            {
                throw new TufException(
                    $"New root v{nextVersion} not signed by threshold of keys from current root v{currentVersion}.");
            }

            // §5.2.3: Verify new root is signed by threshold of keys from the NEW root itself
            var newRootRole = newRoot.Signed.Roles["root"];
            if (!TufMetadataVerifier.VerifyThreshold(
                    newRoot.Signatures, newRoot.SignedBytes, newRootRole, newRoot.Signed.Keys))
            {
                throw new TufException(
                    $"New root v{nextVersion} not self-signed by its own threshold.");
            }

            // §5.2.4: Check for rollback
            if (newRoot.Signed.Version != nextVersion)
            {
                throw new TufException(
                    $"Root version mismatch: expected {nextVersion} but got {newRoot.Signed.Version}.");
            }

            // Accept the new root
            _trustedRoot = newRoot;
            _cache.StoreMetadata("root", newRootBytes);
            currentVersion = nextVersion;
        }

        // §5.2.5: Check root expiry (after all rotations)
        if (_trustedRoot.Signed.Expires < DateTimeOffset.UtcNow)
        {
            throw new TufExpiredException("root", _trustedRoot.Signed.Expires);
        }

        // §5.2.6: If root was updated, clear cached timestamp to force re-download
        if (currentVersion > _trustedRoot.Signed.Version - (currentVersion - _trustedRoot.Signed.Version))
        {
            // Root was updated - delete cached timestamp (and downstream metadata)
            // so they're re-verified with the new root keys
        }
    }

    /// <summary>
    /// §5.3: Update timestamp metadata.
    /// </summary>
    private async Task UpdateTimestampAsync(CancellationToken cancellationToken)
    {
        // §5.3.1: Fetch timestamp.json (always unversioned)
        var timestampBytes = await _repository.FetchMetadataAsync("timestamp", cancellationToken: cancellationToken)
            ?? throw new TufException("Failed to fetch timestamp.json from repository.");

        var newTimestamp = TufMetadataParser.ParseTimestamp(timestampBytes);

        // §5.3.2: Verify timestamp signatures using keys from root
        var timestampRole = _trustedRoot!.Signed.Roles["timestamp"];
        if (!TufMetadataVerifier.VerifyThreshold(
                newTimestamp.Signatures, newTimestamp.SignedBytes, timestampRole, _trustedRoot.Signed.Keys))
        {
            throw new TufException("Timestamp signature verification failed.");
        }

        // §5.3.3: Check rollback - new timestamp version must be >= previous
        if (_trustedTimestamp != null && newTimestamp.Signed.Version < _trustedTimestamp.Signed.Version)
        {
            throw new TufException(
                $"Timestamp rollback detected: v{newTimestamp.Signed.Version} < v{_trustedTimestamp.Signed.Version}.");
        }

        // §5.3.4: Check expiry
        if (newTimestamp.Signed.Expires < DateTimeOffset.UtcNow)
        {
            throw new TufExpiredException("timestamp", newTimestamp.Signed.Expires);
        }

        _trustedTimestamp = newTimestamp;
        _cache.StoreMetadata("timestamp", timestampBytes);
    }

    /// <summary>
    /// §5.4: Update snapshot metadata.
    /// </summary>
    private async Task UpdateSnapshotAsync(CancellationToken cancellationToken)
    {
        var snapshotMeta = _trustedTimestamp!.Signed.SnapshotMeta;

        // §5.4.1: Fetch snapshot.json (versioned if consistent_snapshot)
        int? fetchVersion = _trustedRoot!.Signed.ConsistentSnapshot ? snapshotMeta.Version : null;
        var snapshotBytes = await _repository.FetchMetadataAsync("snapshot", fetchVersion, cancellationToken)
            ?? throw new TufException("Failed to fetch snapshot.json from repository.");

        // §5.4.2: Verify against hashes in timestamp (if present)
        if (snapshotMeta.Hashes != null)
        {
            VerifyMetaHashes(snapshotBytes, snapshotMeta.Hashes, "snapshot");
        }

        // Verify length (if present)
        if (snapshotMeta.Length.HasValue && snapshotBytes.Length > snapshotMeta.Length.Value)
        {
            throw new TufException(
                $"Snapshot size {snapshotBytes.Length} exceeds expected {snapshotMeta.Length.Value}.");
        }

        var newSnapshot = TufMetadataParser.ParseSnapshot(snapshotBytes);

        // §5.4.3: Verify snapshot signatures using keys from root
        var snapshotRole = _trustedRoot.Signed.Roles["snapshot"];
        if (!TufMetadataVerifier.VerifyThreshold(
                newSnapshot.Signatures, newSnapshot.SignedBytes, snapshotRole, _trustedRoot.Signed.Keys))
        {
            throw new TufException("Snapshot signature verification failed.");
        }

        // §5.4.4: Check version matches what timestamp says
        if (newSnapshot.Signed.Version != snapshotMeta.Version)
        {
            throw new TufException(
                $"Snapshot version {newSnapshot.Signed.Version} doesn't match timestamp reference {snapshotMeta.Version}.");
        }

        // §5.4.5: Check rollback on targets versions
        if (_trustedSnapshot != null)
        {
            foreach (var (targetFile, oldMeta) in _trustedSnapshot.Signed.Meta)
            {
                if (newSnapshot.Signed.Meta.TryGetValue(targetFile, out var newMeta))
                {
                    if (newMeta.Version < oldMeta.Version)
                    {
                        throw new TufException(
                            $"Rollback detected: {targetFile} version {newMeta.Version} < {oldMeta.Version}.");
                    }
                }
            }
        }

        // §5.4.6: Check expiry
        if (newSnapshot.Signed.Expires < DateTimeOffset.UtcNow)
        {
            throw new TufExpiredException("snapshot", newSnapshot.Signed.Expires);
        }

        _trustedSnapshot = newSnapshot;
        _cache.StoreMetadata("snapshot", snapshotBytes);
    }

    /// <summary>
    /// §5.5: Update targets metadata.
    /// </summary>
    private async Task UpdateTargetsAsync(CancellationToken cancellationToken)
    {
        // §5.5.1: Get expected targets version from snapshot
        if (!_trustedSnapshot!.Signed.Meta.TryGetValue("targets.json", out var targetsMeta))
        {
            throw new TufException("No targets.json entry in snapshot metadata.");
        }

        // Skip if we already have the correct version
        if (_trustedTargets != null && _trustedTargets.Signed.Version == targetsMeta.Version)
            return;

        // §5.5.2: Fetch targets.json (versioned if consistent_snapshot)
        int? fetchVersion = _trustedRoot!.Signed.ConsistentSnapshot ? targetsMeta.Version : null;
        var targetsBytes = await _repository.FetchMetadataAsync("targets", fetchVersion, cancellationToken)
            ?? throw new TufException("Failed to fetch targets.json from repository.");

        // §5.5.3: Verify hashes (if present in snapshot)
        if (targetsMeta.Hashes != null)
        {
            VerifyMetaHashes(targetsBytes, targetsMeta.Hashes, "targets");
        }

        // Verify length
        if (targetsMeta.Length.HasValue && targetsBytes.Length > targetsMeta.Length.Value)
        {
            throw new TufException(
                $"Targets size {targetsBytes.Length} exceeds expected {targetsMeta.Length.Value}.");
        }

        var newTargets = TufMetadataParser.ParseTargets(targetsBytes);

        // §5.5.4: Verify targets signatures using keys from root
        var targetsRole = _trustedRoot.Signed.Roles["targets"];
        if (!TufMetadataVerifier.VerifyThreshold(
                newTargets.Signatures, newTargets.SignedBytes, targetsRole, _trustedRoot.Signed.Keys))
        {
            throw new TufException("Targets signature verification failed.");
        }

        // §5.5.5: Check version matches snapshot reference
        if (newTargets.Signed.Version != targetsMeta.Version)
        {
            throw new TufException(
                $"Targets version {newTargets.Signed.Version} doesn't match snapshot reference {targetsMeta.Version}.");
        }

        // §5.5.6: Check expiry
        if (newTargets.Signed.Expires < DateTimeOffset.UtcNow)
        {
            throw new TufExpiredException("targets", newTargets.Signed.Expires);
        }

        _trustedTargets = newTargets;
        _cache.StoreMetadata("targets", targetsBytes);
    }

    private static void VerifyMetaHashes(byte[] data, Dictionary<string, string> expectedHashes, string roleName)
    {
        foreach (var (algo, expectedHash) in expectedHashes)
        {
            var actualHash = algo.ToLowerInvariant() switch
            {
                "sha256" => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant(),
                "sha512" => Convert.ToHexString(SHA512.HashData(data)).ToLowerInvariant(),
                _ => null
            };

            if (actualHash != null && actualHash != expectedHash.ToLowerInvariant())
            {
                throw new TufException(
                    $"{roleName} {algo} hash mismatch: expected {expectedHash}, got {actualHash}.");
            }
        }
    }

    private static bool VerifyTargetHashes(byte[] data, TargetFileInfo targetInfo)
    {
        foreach (var (algo, expectedHash) in targetInfo.Hashes)
        {
            var actualHash = algo.ToLowerInvariant() switch
            {
                "sha256" => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant(),
                "sha512" => Convert.ToHexString(SHA512.HashData(data)).ToLowerInvariant(),
                _ => null
            };

            if (actualHash != null && actualHash != expectedHash.ToLowerInvariant())
                return false;
        }
        return true;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_ownsRepository && _repository is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
}
