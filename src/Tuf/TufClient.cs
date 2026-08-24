using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
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
    private readonly byte[] _bootstrapRoot;
    private readonly bool _ownsRepository;
    private readonly SemaphoreSlim _operationGate = new(1, 1);

    private SignedMetadata<RootMetadata>? _trustedRoot;
    private SignedMetadata<TimestampMetadata>? _trustedTimestamp;
    private SignedMetadata<SnapshotMetadata>? _trustedSnapshot;
    private SignedMetadata<TargetsMetadata>? _trustedTargets;
    private readonly Dictionary<string, SignedMetadata<TargetsMetadata>> _trustedDelegatedTargets = new(StringComparer.Ordinal);

    /// <summary>
    /// Creates a new TUF client with the specified options.
    /// </summary>
    public TufClient(TufClientOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _cache = options.Cache ?? new InMemoryTufCache();
        _bootstrapRoot = options.TrustedRoot ?? throw new ArgumentNullException(nameof(options.TrustedRoot));

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
    /// Gets the current trusted metadata from the TUF repository.
    /// Implements the TUF client update workflow (spec §5.1-5.6).
    /// </summary>
    public async Task<TufMetadataResult> GetTrustedMetadataAsync(
        CancellationToken cancellationToken = default)
    {
        using var operation = TufInstrumentation.StartMetadataRefresh();
        var queueStartedAt = Stopwatch.GetTimestamp();
        var gateAcquired = false;
        var queueRecorded = false;
        try
        {
            await _operationGate.WaitAsync(cancellationToken);
            gateAcquired = true;
            TufInstrumentation.RecordMetadataRefreshQueue(queueStartedAt);
            queueRecorded = true;
            return await GetTrustedMetadataCoreAsync(cancellationToken);
        }
        catch (Exception exception)
        {
            var errorType = TufInstrumentation.GetErrorType(
                exception,
                cancellationToken);
            if (!queueRecorded)
            {
                TufInstrumentation.RecordMetadataRefreshQueue(
                    queueStartedAt,
                    errorType);
            }

            operation.SetError(errorType);
            throw;
        }
        finally
        {
            if (gateAcquired)
            {
                _operationGate.Release();
            }
        }
    }

    /// <summary>
    /// Refreshes local metadata from the TUF repository.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    [Obsolete("Use GetTrustedMetadataAsync instead.")]
    public async Task RefreshAsync(CancellationToken cancellationToken = default)
    {
        await GetTrustedMetadataAsync(cancellationToken);
    }

    private async Task<TufMetadataResult> GetTrustedMetadataCoreAsync(
        CancellationToken cancellationToken)
    {
        // §5.1: Load the trusted root metadata
        await UpdateRootPhaseAsync(cancellationToken);

        // §5.3: Update timestamp metadata
        await UpdateTimestampPhaseAsync(cancellationToken);

        // §5.4: Update snapshot metadata
        await UpdateSnapshotPhaseAsync(cancellationToken);

        // §5.5: Update targets metadata
        await UpdateTargetsPhaseAsync(cancellationToken);

        return CreateMetadataResult();
    }

    private TufMetadataResult CreateMetadataResult()
    {
        if (_trustedRoot is null ||
            _trustedTimestamp is null ||
            _trustedSnapshot is null ||
            _trustedTargets is null)
        {
            throw new TufException(
                "The TUF operation did not produce complete trusted metadata.");
        }

        var expires = new[]
        {
            _trustedRoot.Signed.Expires,
            _trustedTimestamp.Signed.Expires,
            _trustedSnapshot.Signed.Expires,
            _trustedTargets.Signed.Expires
        }.Min();

        foreach (var delegatedTargets in _trustedDelegatedTargets.Values)
        {
            if (delegatedTargets.Signed.Expires < expires)
            {
                expires = delegatedTargets.Signed.Expires;
            }
        }

        return new TufMetadataResult { Expires = expires };
    }

    /// <summary>
    /// Gets a target file, verifying its hash and length against current trusted metadata.
    /// </summary>
    /// <param name="targetPath">The target path as specified in targets metadata.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The verified target and the metadata that authorized it.</returns>
    public async Task<TufTargetResult> GetTargetAsync(
        string targetPath,
        CancellationToken cancellationToken = default)
    {
        using var operation = TufInstrumentation.StartTargetGet();
        var queueStartedAt = Stopwatch.GetTimestamp();
        var gateAcquired = false;
        var queueRecorded = false;
        try
        {
            await _operationGate.WaitAsync(cancellationToken);
            gateAcquired = true;
            TufInstrumentation.RecordTargetGetQueue(queueStartedAt);
            queueRecorded = true;
            return await GetTargetCoreAsync(
                targetPath,
                operation,
                cancellationToken);
        }
        catch (Exception exception)
        {
            var errorType = TufInstrumentation.GetErrorType(
                exception,
                cancellationToken);
            if (!queueRecorded)
            {
                TufInstrumentation.RecordTargetGetQueue(
                    queueStartedAt,
                    errorType);
            }

            operation.SetError(errorType);
            throw;
        }
        finally
        {
            if (gateAcquired)
            {
                _operationGate.Release();
            }
        }
    }

    /// <summary>
    /// Downloads a target file and returns its verified contents.
    /// </summary>
    /// <param name="targetPath">The target path as specified in targets metadata.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The verified target contents.</returns>
    [Obsolete("Use GetTargetAsync instead.")]
    public async Task<byte[]> DownloadTargetAsync(
        string targetPath,
        CancellationToken cancellationToken = default)
    {
        var result = await GetTargetAsync(targetPath, cancellationToken);
        return result.Content.ToArray();
    }

    private async Task<TufTargetResult> GetTargetCoreAsync(
        string targetPath,
        TufTelemetryOperation operation,
        CancellationToken cancellationToken)
    {
        using (var refreshOperation =
               TufInstrumentation.StartMetadataRefresh())
        {
            try
            {
                await GetTrustedMetadataCoreAsync(cancellationToken);
            }
            catch (Exception exception)
            {
                refreshOperation.SetError(exception, cancellationToken);
                throw;
            }
        }

        if (_trustedTargets == null)
            throw new TufException("No trusted targets metadata available.");

        var targetInfo = await FindTargetInfoPhaseAsync(
            targetPath,
            cancellationToken);
        if (targetInfo == null)
        {
            operation.SetError("target_not_found");
            throw new TufException($"Target '{targetPath}' not found in targets metadata.");
        }

        // Check cache first
        var cached = _cache.LoadTarget(targetPath);
        if (cached != null &&
            cached.LongLength == targetInfo.Length &&
            VerifyTargetHashes(cached, targetInfo))
        {
            operation.SetTag("tuf.target.cache_hit", true);
            TufInstrumentation.RecordTargetSize(cached.LongLength, cacheHit: true);
            return new TufTargetResult
            {
                Content = cached,
                Metadata = CreateMetadataResult()
            };
        }

        // For consistent snapshots, prefix target filename with hash
        var fetchPath = targetPath;
        if (_trustedRoot!.Signed.ConsistentSnapshot)
        {
            string? hashPrefix = null;
            foreach (var hash in targetInfo.Hashes.Values)
            {
                hashPrefix = hash;
                break;
            }

            if (!string.IsNullOrEmpty(hashPrefix))
            {
                var fileName = Path.GetFileName(targetPath);
                var dirPart = Path.GetDirectoryName(targetPath);
                var hashPrefixed = $"{hashPrefix}.{fileName}";
                fetchPath = string.IsNullOrEmpty(dirPart) ? hashPrefixed : $"{dirPart}/{hashPrefixed}";
            }
        }

        operation.SetTag("tuf.target.cache_hit", false);
        var targetBytes = await _repository.FetchTargetAsync(fetchPath, cancellationToken)
            ?? throw CreateTargetNotFoundException(operation, targetPath);

        // Verify length
        if (targetBytes.LongLength != targetInfo.Length)
        {
            operation.SetError("target_verification_failed");
            throw new TufException(
                $"Target '{targetPath}' size {targetBytes.Length} does not match expected {targetInfo.Length}.");
        }

        // Verify hashes
        if (!VerifyTargetHashes(targetBytes, targetInfo))
        {
            operation.SetError("target_verification_failed");
            throw new TufException($"Target '{targetPath}' hash verification failed.");
        }

        _cache.StoreTarget(targetPath, targetBytes);
        TufInstrumentation.RecordTargetSize(
            targetBytes.LongLength,
            cacheHit: false);
        return new TufTargetResult
        {
            Content = targetBytes,
            Metadata = CreateMetadataResult()
        };
    }

    private static TufException CreateTargetNotFoundException(
        TufTelemetryOperation operation,
        string targetPath)
    {
        operation.SetError("target_not_found");
        return new TufException(
            $"Target '{targetPath}' not found on repository.");
    }

    private async Task UpdateRootPhaseAsync(
        CancellationToken cancellationToken)
    {
        using var activity =
            TufInstrumentation.StartActivity("tuf.metadata.root.update");
        try
        {
            LoadTrustedRoot();
            await UpdateRootAsync(cancellationToken);
        }
        catch (Exception exception)
        {
            TufInstrumentation.SetError(
                activity,
                exception,
                cancellationToken);
            throw;
        }
    }

    private async Task UpdateTimestampPhaseAsync(
        CancellationToken cancellationToken)
    {
        using var activity =
            TufInstrumentation.StartActivity("tuf.metadata.timestamp.update");
        try
        {
            await UpdateTimestampAsync(cancellationToken);
        }
        catch (Exception exception)
        {
            TufInstrumentation.SetError(
                activity,
                exception,
                cancellationToken);
            throw;
        }
    }

    private async Task UpdateSnapshotPhaseAsync(
        CancellationToken cancellationToken)
    {
        using var activity =
            TufInstrumentation.StartActivity("tuf.metadata.snapshot.update");
        try
        {
            await UpdateSnapshotAsync(cancellationToken);
        }
        catch (Exception exception)
        {
            TufInstrumentation.SetError(
                activity,
                exception,
                cancellationToken);
            throw;
        }
    }

    private async Task UpdateTargetsPhaseAsync(
        CancellationToken cancellationToken)
    {
        using var activity =
            TufInstrumentation.StartActivity("tuf.metadata.targets.update");
        try
        {
            await UpdateTargetsAsync(cancellationToken);
        }
        catch (Exception exception)
        {
            TufInstrumentation.SetError(
                activity,
                exception,
                cancellationToken);
            throw;
        }
    }

    private async Task<TargetFileInfo?> FindTargetInfoPhaseAsync(
        string targetPath,
        CancellationToken cancellationToken)
    {
        using var activity =
            TufInstrumentation.StartActivity("tuf.target.resolve");
        try
        {
            return await FindTargetInfoAsync(targetPath, cancellationToken);
        }
        catch (Exception exception)
        {
            TufInstrumentation.SetError(
                activity,
                exception,
                cancellationToken);
            throw;
        }
    }

    /// <summary>
    /// §5.1: Load the trusted root metadata from the cache.
    /// </summary>
    private void LoadTrustedRoot()
    {
        var rootBytes = _cache.LoadMetadata("root") ?? _bootstrapRoot;

        ResetTrustedMetadata();
        _trustedRoot = ParseAndValidateTrustedRoot(rootBytes);
    }

    private static SignedMetadata<RootMetadata> ParseAndValidateTrustedRoot(byte[] rootBytes)
    {
        SignedMetadata<RootMetadata> trustedRoot;
        try
        {
            trustedRoot = TufMetadataParser.ParseRoot(rootBytes);
        }
        catch (JsonException ex)
        {
            throw new TufException("Trusted root metadata is invalid.", ex);
        }

        ValidateTrustedRoot(trustedRoot);
        return trustedRoot;
    }

    private void ResetTrustedMetadata()
    {
        _trustedTimestamp = null;
        _trustedSnapshot = null;
        _trustedTargets = null;
        _trustedDelegatedTargets.Clear();
    }

    private static void ValidateTrustedRoot(SignedMetadata<RootMetadata> trustedRoot)
    {
        if (!trustedRoot.Signed.Roles.TryGetValue("root", out var rootRole))
        {
            throw new TufException("Trusted root metadata is missing the root role.");
        }

        if (!TufMetadataVerifier.VerifyThreshold(
                trustedRoot.Signatures,
                trustedRoot.SignedBytes,
                rootRole,
                trustedRoot.Signed.Keys))
        {
            throw new TufException("Trusted root signature verification failed.");
        }
    }

    /// <summary>
    /// §5.2: Update root metadata by fetching and verifying every successive version.
    /// TUF's maximum-rotation limit bounds the walk; it does not permit skipping versions.
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
        EnsureFinalRootValid();

    }

    private void EnsureFinalRootValid()
    {
        if (_trustedRoot!.Signed.Expires < DateTimeOffset.UtcNow)
        {
            throw new TufExpiredException("root", _trustedRoot.Signed.Expires);
        }
    }

    /// <summary>
    /// §5.3: Update timestamp metadata.
    /// </summary>
    private async Task UpdateTimestampAsync(CancellationToken cancellationToken)
    {
        TryLoadLocalTimestamp();

        // §5.3.1: Fetch timestamp.json (always unversioned)
        var timestampBytes = await _repository.FetchMetadataAsync("timestamp", cancellationToken: cancellationToken)
            ?? throw new TufException(
                "Failed to fetch timestamp.json from repository.");

        var newTimestamp = TufMetadataParser.ParseTimestamp(timestampBytes);

        VerifyTimestampSignatures(newTimestamp);

        // §5.3.3: Check rollback - new timestamp version must be >= previous
        if (_trustedTimestamp != null && newTimestamp.Signed.Version < _trustedTimestamp.Signed.Version)
        {
            throw new TufException(
                $"Timestamp rollback detected: v{newTimestamp.Signed.Version} < v{_trustedTimestamp.Signed.Version}.");
        }

        if (_trustedTimestamp != null &&
            newTimestamp.Signed.Version == _trustedTimestamp.Signed.Version)
        {
            return;
        }

        if (_trustedTimestamp != null &&
            newTimestamp.Signed.SnapshotMeta.Version < _trustedTimestamp.Signed.SnapshotMeta.Version)
        {
            throw new TufException(
                $"Snapshot rollback detected: v{newTimestamp.Signed.SnapshotMeta.Version} < v{_trustedTimestamp.Signed.SnapshotMeta.Version}.");
        }

        _trustedTimestamp = newTimestamp;
        EnsureFinalTimestampValid();
        _cache.StoreMetadata("timestamp", timestampBytes);
    }

    /// <summary>
    /// §5.4: Update snapshot metadata.
    /// </summary>
    private async Task UpdateSnapshotAsync(CancellationToken cancellationToken)
    {
        EnsureFinalTimestampValid();

        if (TryLoadLocalSnapshot(requireCurrentTimestamp: false))
        {
            return;
        }

        var snapshotMeta = _trustedTimestamp!.Signed.SnapshotMeta;

        // §5.4.1: Fetch snapshot.json (versioned if consistent_snapshot)
        int? fetchVersion = _trustedRoot!.Signed.ConsistentSnapshot ? snapshotMeta.Version : null;
        var snapshotBytes = await _repository.FetchMetadataAsync("snapshot", fetchVersion, cancellationToken)
            ?? throw new TufException(
                "Failed to fetch snapshot.json from repository.");

        var newSnapshot = TufMetadataParser.ParseSnapshot(snapshotBytes);
        VerifySnapshotMetadata(snapshotBytes, newSnapshot, verifyTimestampReference: true);

        _trustedSnapshot = newSnapshot;
        EnsureFinalSnapshotValid();
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

        if (TryLoadLocalTargets())
            return;

        // §5.5.2: Fetch targets.json (versioned if consistent_snapshot)
        int? fetchVersion = _trustedRoot!.Signed.ConsistentSnapshot ? targetsMeta.Version : null;
        var targetsBytes = await _repository.FetchMetadataAsync("targets", fetchVersion, cancellationToken)
            ?? throw new TufException(
                "Failed to fetch targets.json from repository.");

        var newTargets = TufMetadataParser.ParseTargets(targetsBytes);
        VerifyTargetsMetadata("targets", "root", targetsBytes, newTargets);

        _trustedTargets = newTargets;
        _trustedDelegatedTargets.Clear();
        _trustedDelegatedTargets["targets"] = newTargets;
        _cache.StoreMetadata("targets", targetsBytes);
    }

    private bool TryLoadLocalTimestamp()
    {
        if (_trustedTimestamp != null)
        {
            return _trustedTimestamp.Signed.Expires >= DateTimeOffset.UtcNow;
        }

        var timestampBytes = _cache.LoadMetadata("timestamp");
        if (timestampBytes == null)
        {
            return false;
        }

        try
        {
            var timestamp = TufMetadataParser.ParseTimestamp(timestampBytes);
            VerifyTimestampSignatures(timestamp);
            _trustedTimestamp = timestamp;
            return _trustedTimestamp.Signed.Expires >= DateTimeOffset.UtcNow;
        }
        catch (JsonException)
        {
            return false;
        }
        catch (TufException)
        {
            return false;
        }
    }

    private bool TryLoadLocalSnapshot(bool requireCurrentTimestamp)
    {
        if (_trustedSnapshot != null)
        {
            try
            {
                EnsureFinalSnapshotValid();
                return true;
            }
            catch (TufException)
            {
                return false;
            }
        }

        var snapshotBytes = _cache.LoadMetadata("snapshot");
        if (snapshotBytes == null)
        {
            return false;
        }

        try
        {
            var snapshot = TufMetadataParser.ParseSnapshot(snapshotBytes);
            var matchesCurrentTimestamp =
                snapshot.Signed.Version ==
                _trustedTimestamp!.Signed.SnapshotMeta.Version;
            VerifySnapshotMetadata(
                snapshotBytes,
                snapshot,
                requireCurrentTimestamp || matchesCurrentTimestamp);
            _trustedSnapshot = snapshot;
            EnsureFinalSnapshotValid();
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
        catch (TufException)
        {
            return false;
        }
    }

    private bool TryLoadLocalTargets()
    {
        if (_trustedTargets != null)
        {
            return _trustedSnapshot != null &&
                _trustedSnapshot.Signed.Meta.TryGetValue("targets.json", out var targetsMeta) &&
                _trustedTargets.Signed.Version == targetsMeta.Version &&
                _trustedTargets.Signed.Expires >= DateTimeOffset.UtcNow;
        }

        var targetsBytes = _cache.LoadMetadata("targets");
        if (targetsBytes == null)
        {
            return false;
        }

        try
        {
            var targets = TufMetadataParser.ParseTargets(targetsBytes);
            VerifyTargetsMetadata("targets", "root", targetsBytes, targets);
            _trustedTargets = targets;
            _trustedDelegatedTargets.Clear();
            _trustedDelegatedTargets["targets"] = targets;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
        catch (TufException)
        {
            return false;
        }
    }

    private async Task<TargetFileInfo?> FindTargetInfoAsync(string targetPath, CancellationToken cancellationToken)
    {
        var rolesToVisit = new List<(string Role, string Parent)>
        {
            ("targets", "root")
        };
        var visitedRoles = new HashSet<string>(StringComparer.Ordinal);

        while (visitedRoles.Count <= _options.MaxDelegations && rolesToVisit.Count > 0)
        {
            var current = rolesToVisit[^1];
            rolesToVisit.RemoveAt(rolesToVisit.Count - 1);

            if (visitedRoles.Contains(current.Role))
            {
                continue;
            }

            var targets = await LoadTargetsRoleAsync(current.Role, current.Parent, cancellationToken);

            if (targets.Signed.Targets.TryGetValue(targetPath, out var targetInfo))
            {
                return targetInfo;
            }

            visitedRoles.Add(current.Role);

            if (targets.Signed.Delegations == null)
            {
                continue;
            }

            var childRolesToVisit = new List<(string Role, string Parent)>();
            foreach (var childRole in targets.Signed.Delegations.GetRolesForTarget(targetPath))
            {
                childRolesToVisit.Add((childRole.Name, current.Role));
                if (childRole.Terminating)
                {
                    rolesToVisit.Clear();
                    break;
                }
            }

            childRolesToVisit.Reverse();
            rolesToVisit.AddRange(childRolesToVisit);
        }

        return null;
    }

    private async Task<SignedMetadata<TargetsMetadata>> LoadTargetsRoleAsync(
        string roleName,
        string parentRoleName,
        CancellationToken cancellationToken)
    {
        if (_trustedDelegatedTargets.TryGetValue(roleName, out var existing))
        {
            return existing;
        }

        if (!_trustedSnapshot!.Signed.Meta.TryGetValue($"{roleName}.json", out _))
        {
            throw new TufException($"Role {roleName} was delegated but is not part of snapshot.");
        }

        var meta = _trustedSnapshot.Signed.Meta[$"{roleName}.json"];
        int? fetchVersion = _trustedRoot!.Signed.ConsistentSnapshot ? meta.Version : null;
        var targetsBytes = await _repository.FetchMetadataAsync(roleName, fetchVersion, cancellationToken)
            ?? throw new TufException(
                $"Failed to fetch {roleName}.json from repository.");
        var targets = TufMetadataParser.ParseTargets(targetsBytes);

        VerifyTargetsMetadata(roleName, parentRoleName, targetsBytes, targets);

        _trustedDelegatedTargets[roleName] = targets;
        _cache.StoreMetadata(roleName, targetsBytes);
        return targets;
    }

    private void VerifyTargetsMetadata(
        string roleName,
        string parentRoleName,
        byte[] targetsBytes,
        SignedMetadata<TargetsMetadata> targets)
    {
        if (!_trustedSnapshot!.Signed.Meta.TryGetValue($"{roleName}.json", out var targetsMeta))
        {
            throw new TufException($"Role {roleName} was delegated but is not part of snapshot.");
        }

        if (targetsMeta.Hashes != null)
        {
            VerifyMetaHashes(targetsBytes, targetsMeta.Hashes, roleName);
        }

        if (targetsMeta.Length.HasValue &&
            targetsBytes.LongLength != targetsMeta.Length.Value)
        {
            throw new TufException(
                $"{roleName} size {targetsBytes.Length} does not match expected {targetsMeta.Length.Value}.");
        }

        TufRole signingRole;
        Dictionary<string, TufKey> signingKeys;

        if (parentRoleName == "root")
        {
            signingRole = _trustedRoot!.Signed.Roles[roleName];
            signingKeys = _trustedRoot.Signed.Keys;
        }
        else
        {
            if (!_trustedDelegatedTargets.TryGetValue(parentRoleName, out var parentTargets))
            {
                throw new TufException($"Delegating role '{parentRoleName}' is not loaded.");
            }

            var parentDelegations = parentTargets.Signed.Delegations
                ?? throw new TufException($"Delegating role '{parentRoleName}' has no delegations.");

            if (!parentDelegations.TryGetRole(roleName, out var delegatedRole))
            {
                throw new TufException($"Role '{roleName}' is not delegated by '{parentRoleName}'.");
            }

            signingRole = new TufRole
            {
                KeyIds = delegatedRole.KeyIds,
                Threshold = delegatedRole.Threshold
            };
            signingKeys = parentDelegations.Keys;
        }

        if (!TufMetadataVerifier.VerifyThreshold(
                targets.Signatures,
                targets.SignedBytes,
                signingRole,
                signingKeys))
        {
            var displayName = roleName == "targets" ? "Targets" : $"Targets role '{roleName}'";
            throw new TufException($"{displayName} signature verification failed.");
        }

        if (targets.Signed.Version != targetsMeta.Version)
        {
            throw new TufException(
                $"{roleName} version {targets.Signed.Version} doesn't match snapshot reference {targetsMeta.Version}.");
        }

        if (targets.Signed.Expires < DateTimeOffset.UtcNow)
        {
            throw new TufExpiredException(roleName, targets.Signed.Expires);
        }
    }

    private void VerifyTimestampSignatures(SignedMetadata<TimestampMetadata> timestamp)
    {
        var timestampRole = _trustedRoot!.Signed.Roles["timestamp"];
        if (!TufMetadataVerifier.VerifyThreshold(
                timestamp.Signatures,
                timestamp.SignedBytes,
                timestampRole,
                _trustedRoot.Signed.Keys))
        {
            throw new TufException("Timestamp signature verification failed.");
        }
    }

    private void VerifySnapshotMetadata(
        byte[] snapshotBytes,
        SignedMetadata<SnapshotMetadata> snapshot,
        bool verifyTimestampReference)
    {
        var snapshotMeta = _trustedTimestamp!.Signed.SnapshotMeta;

        if (verifyTimestampReference && snapshotMeta.Hashes != null)
        {
            VerifyMetaHashes(snapshotBytes, snapshotMeta.Hashes, "snapshot");
        }

        if (verifyTimestampReference &&
            snapshotMeta.Length.HasValue &&
            snapshotBytes.LongLength != snapshotMeta.Length.Value)
        {
            throw new TufException(
                $"Snapshot size {snapshotBytes.Length} does not match expected {snapshotMeta.Length.Value}.");
        }

        var snapshotRole = _trustedRoot!.Signed.Roles["snapshot"];
        if (!TufMetadataVerifier.VerifyThreshold(
                snapshot.Signatures,
                snapshot.SignedBytes,
                snapshotRole,
                _trustedRoot.Signed.Keys))
        {
            throw new TufException("Snapshot signature verification failed.");
        }

        if (_trustedSnapshot != null)
        {
            foreach (var (targetFile, oldMeta) in _trustedSnapshot.Signed.Meta)
            {
                if (!snapshot.Signed.Meta.TryGetValue(targetFile, out var newMeta))
                {
                    throw new TufException($"Snapshot is missing metadata for '{targetFile}'.");
                }

                if (newMeta.Version < oldMeta.Version)
                {
                    throw new TufException(
                        $"Rollback detected: {targetFile} version {newMeta.Version} < {oldMeta.Version}.");
                }
            }
        }
    }

    private void EnsureFinalTimestampValid()
    {
        if (_trustedTimestamp == null)
        {
            throw new TufException("No trusted timestamp metadata available.");
        }

        if (_trustedTimestamp.Signed.Expires < DateTimeOffset.UtcNow)
        {
            throw new TufExpiredException("timestamp", _trustedTimestamp.Signed.Expires);
        }
    }

    private void EnsureFinalSnapshotValid()
    {
        if (_trustedSnapshot == null)
        {
            throw new TufException("No trusted snapshot metadata available.");
        }

        if (_trustedSnapshot.Signed.Expires < DateTimeOffset.UtcNow)
        {
            throw new TufExpiredException("snapshot", _trustedSnapshot.Signed.Expires);
        }

        if (_trustedSnapshot.Signed.Version != _trustedTimestamp!.Signed.SnapshotMeta.Version)
        {
            throw new TufException(
                $"Snapshot version {_trustedSnapshot.Signed.Version} doesn't match timestamp reference {_trustedTimestamp.Signed.SnapshotMeta.Version}.");
        }
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
        var verifiedAnySupportedHash = false;

        foreach (var (algo, expectedHash) in targetInfo.Hashes)
        {
            var actualHash = algo.ToLowerInvariant() switch
            {
                "sha256" => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant(),
                "sha512" => Convert.ToHexString(SHA512.HashData(data)).ToLowerInvariant(),
                _ => null
            };

            if (actualHash == null)
            {
                continue;
            }

            verifiedAnySupportedHash = true;
            if (actualHash != expectedHash.ToLowerInvariant())
                return false;
        }

        return verifiedAnySupportedHash;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_ownsRepository && _repository is IDisposable disposable)
        {
            disposable.Dispose();
        }

        _operationGate.Dispose();
    }
}
