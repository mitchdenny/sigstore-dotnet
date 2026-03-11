using System.IO.Enumeration;
using System.Security.Cryptography;
using System.Text;

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

    /// <summary>
    /// Returns delegated roles that are responsible for a target path,
    /// preserving delegation priority order.
    /// </summary>
    public IEnumerable<DelegatedRole> GetRolesForTarget(string targetPath)
    {
        foreach (var role in Roles)
        {
            if (role.IsDelegatedPath(targetPath))
            {
                yield return role;
            }
        }
    }

    /// <summary>
    /// Looks up a delegated role by name.
    /// </summary>
    public bool TryGetRole(string roleName, out DelegatedRole delegatedRole)
    {
        foreach (var role in Roles)
        {
            if (role.Name == roleName)
            {
                delegatedRole = role;
                return true;
            }
        }

        delegatedRole = null!;
        return false;
    }
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

    /// <summary>
    /// Returns whether this delegation is responsible for the given target path.
    /// </summary>
    public bool IsDelegatedPath(string targetPath)
    {
        if (Paths is { Count: > 0 })
        {
            foreach (var pathPattern in Paths)
            {
                if (IsTargetInPathPattern(targetPath, pathPattern))
                {
                    return true;
                }
            }
        }
        else if (PathHashPrefixes is { Count: > 0 })
        {
            var targetPathHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(targetPath)))
                .ToLowerInvariant();

            foreach (var pathHashPrefix in PathHashPrefixes)
            {
                if (targetPathHash.StartsWith(pathHashPrefix, StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static bool IsTargetInPathPattern(string targetPath, string pathPattern)
    {
        var targetParts = targetPath.Split('/');
        var patternParts = pathPattern.Split('/');

        if (targetParts.Length != patternParts.Length)
        {
            return false;
        }

        for (var i = 0; i < targetParts.Length; i++)
        {
            if (!FileSystemName.MatchesSimpleExpression(patternParts[i], targetParts[i], ignoreCase: false))
            {
                return false;
            }
        }

        return true;
    }
}
