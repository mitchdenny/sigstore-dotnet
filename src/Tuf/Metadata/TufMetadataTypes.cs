namespace Tuf.Metadata;

/// <summary>
/// TUF root metadata. Defines the keys and roles for the entire TUF repository.
/// </summary>
public sealed class RootMetadata : TufMetadata
{
    /// <summary>
    /// Whether the root metadata specifies consistent snapshots (versioned filenames).
    /// </summary>
    public bool ConsistentSnapshot { get; init; }

    /// <summary>
    /// The keys available in this root, keyed by key ID.
    /// </summary>
    public required Dictionary<string, TufKey> Keys { get; init; }

    /// <summary>
    /// The role definitions, keyed by role name (e.g., "root", "targets", "snapshot", "timestamp").
    /// </summary>
    public required Dictionary<string, TufRole> Roles { get; init; }
}

/// <summary>
/// TUF timestamp metadata. Points to the current snapshot metadata.
/// </summary>
public sealed class TimestampMetadata : TufMetadata
{
    /// <summary>
    /// Metadata about the current snapshot.json file (version, hashes, length).
    /// </summary>
    public required MetaFileInfo SnapshotMeta { get; init; }
}

/// <summary>
/// TUF snapshot metadata. Points to current versions of all targets metadata.
/// </summary>
public sealed class SnapshotMetadata : TufMetadata
{
    /// <summary>
    /// Metadata about each targets file, keyed by filename (e.g., "targets.json").
    /// </summary>
    public required Dictionary<string, MetaFileInfo> Meta { get; init; }
}

/// <summary>
/// TUF targets metadata. Describes available target files and optional delegations.
/// </summary>
public sealed class TargetsMetadata : TufMetadata
{
    /// <summary>
    /// The target files described by this metadata, keyed by target path.
    /// </summary>
    public required Dictionary<string, TargetFileInfo> Targets { get; init; }

    /// <summary>
    /// Optional delegations to other roles.
    /// </summary>
    public Delegations? Delegations { get; init; }
}

/// <summary>
/// Information about a metadata file referenced by another metadata file.
/// </summary>
public sealed class MetaFileInfo
{
    /// <summary>
    /// The expected version of the metadata file.
    /// </summary>
    public required int Version { get; init; }

    /// <summary>
    /// The expected length of the metadata file in bytes. Optional.
    /// </summary>
    public long? Length { get; init; }

    /// <summary>
    /// The expected hashes of the metadata file, keyed by algorithm name (e.g., "sha256").
    /// </summary>
    public Dictionary<string, string>? Hashes { get; init; }
}

/// <summary>
/// Information about a target file.
/// </summary>
public sealed class TargetFileInfo
{
    /// <summary>
    /// The expected length of the target file in bytes.
    /// </summary>
    public required long Length { get; init; }

    /// <summary>
    /// The expected hashes of the target file, keyed by algorithm name.
    /// </summary>
    public required Dictionary<string, string> Hashes { get; init; }

    /// <summary>
    /// Optional custom metadata for this target.
    /// </summary>
    public Dictionary<string, object>? Custom { get; init; }
}

/// <summary>
/// Delegation information within targets metadata.
/// </summary>
public sealed class Delegations
{
    /// <summary>
    /// The keys available for delegated roles, keyed by key ID.
    /// </summary>
    public required Dictionary<string, TufKey> Keys { get; init; }

    /// <summary>
    /// The delegated roles in priority order.
    /// </summary>
    public required List<DelegatedRole> Roles { get; init; }
}

/// <summary>
/// A delegated targets role.
/// </summary>
public sealed class DelegatedRole
{
    /// <summary>
    /// The name of the delegated role.
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// The key IDs authorized for this delegated role.
    /// </summary>
    public required List<string> KeyIds { get; init; }

    /// <summary>
    /// The minimum number of signatures required.
    /// </summary>
    public required int Threshold { get; init; }

    /// <summary>
    /// Whether this delegation terminates the search (if true, no further delegations are consulted).
    /// </summary>
    public bool Terminating { get; init; }

    /// <summary>
    /// The target path patterns this delegation is responsible for.
    /// </summary>
    public List<string>? Paths { get; init; }

    /// <summary>
    /// Hash prefix path patterns this delegation is responsible for.
    /// </summary>
    public List<string>? PathHashPrefixes { get; init; }
}
