using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Tuf.Metadata;
using Tuf.Serialization;

namespace Tuf.Tests;

/// <summary>
/// An in-memory TUF repository simulator for testing the TUF client.
/// Generates and serves TUF metadata with configurable keys, thresholds, and targets.
/// Supports intentional breakage for attack simulation.
/// </summary>
internal sealed class RepositorySimulator : ITufRepository
{
    private readonly ECDsa _rootKey;
    private readonly ECDsa _targetsKey;
    private readonly ECDsa _snapshotKey;
    private readonly ECDsa _timestampKey;

    private readonly string _rootKeyId;
    private readonly string _targetsKeyId;
    private readonly string _snapshotKeyId;
    private readonly string _timestampKeyId;

    private readonly Dictionary<string, byte[]> _metadata = new();
    private readonly Dictionary<string, byte[]> _targets = new();
    private readonly List<string> _requestLog = new();

    public int RootVersion { get; set; } = 1;
    public int TimestampVersion { get; set; } = 1;
    public int SnapshotVersion { get; set; } = 1;
    public int TargetsVersion { get; set; } = 1;
    public bool ConsistentSnapshot { get; set; }
    public DateTimeOffset RootExpiry { get; set; } = DateTimeOffset.UtcNow.AddYears(1);
    public DateTimeOffset TimestampExpiry { get; set; } = DateTimeOffset.UtcNow.AddDays(1);
    public DateTimeOffset SnapshotExpiry { get; set; } = DateTimeOffset.UtcNow.AddDays(7);
    public DateTimeOffset TargetsExpiry { get; set; } = DateTimeOffset.UtcNow.AddDays(30);

    public IReadOnlyList<string> RequestLog => _requestLog;
    public IReadOnlyDictionary<string, byte[]> StoredTargets => _targets;

    /// <summary>
    /// Set to non-null to serve tampered bytes instead of real root for a specific version.
    /// </summary>
    public Dictionary<int, byte[]> TamperedRoots { get; } = new();

    /// <summary>
    /// Set to true to produce unsigned metadata for a specific role.
    /// </summary>
    public HashSet<string> UnsignedRoles { get; } = new();

    /// <summary>
    /// Set to true to serve expired metadata (override expiry to the past).
    /// </summary>
    public HashSet<string> ExpiredRoles { get; } = new();

    /// <summary>
    /// Serve a different version number than what's actually in the metadata.
    /// </summary>
    public Dictionary<string, int> VersionOverrides { get; } = new();

    public RepositorySimulator()
    {
        _rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _targetsKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _snapshotKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _timestampKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        _rootKeyId = ComputeKeyId(_rootKey);
        _targetsKeyId = ComputeKeyId(_targetsKey);
        _snapshotKeyId = ComputeKeyId(_snapshotKey);
        _timestampKeyId = ComputeKeyId(_timestampKey);

        PublishAll();
    }

    /// <summary>
    /// Gets the initial root.json bytes for bootstrapping a TUF client.
    /// </summary>
    public byte[] GetInitialRoot() => _metadata[$"1.root.json"];

    /// <summary>
    /// Adds a target file to the repository and publishes updated metadata.
    /// </summary>
    public void AddTarget(string path, byte[] content)
    {
        _targets[path] = content;
    }

    /// <summary>
    /// Bumps version numbers and publishes all metadata.
    /// </summary>
    public void PublishAll()
    {
        PublishRoot();
        PublishTargets();
        PublishSnapshot();
        PublishTimestamp();
    }

    /// <summary>
    /// Bumps root version and publishes a new root.json.
    /// </summary>
    public void BumpRootVersion()
    {
        RootVersion++;
        PublishRoot();
    }

    /// <summary>
    /// Bumps all non-root metadata versions and publishes.
    /// </summary>
    public void BumpNonRootVersions()
    {
        TargetsVersion++;
        SnapshotVersion++;
        TimestampVersion++;
        PublishTargets();
        PublishSnapshot();
        PublishTimestamp();
    }

    private void PublishRoot()
    {
        var signed = new Dictionary<string, object>
        {
            ["_type"] = "root",
            ["spec_version"] = "1.0",
            ["version"] = RootVersion,
            ["expires"] = (ExpiredRoles.Contains("root")
                ? DateTimeOffset.UtcNow.AddDays(-1)
                : RootExpiry).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            ["consistent_snapshot"] = ConsistentSnapshot,
            ["keys"] = BuildKeysDict(),
            ["roles"] = BuildRolesDict()
        };

        var envelope = SignEnvelope(signed, UnsignedRoles.Contains("root") ? null : _rootKey);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(envelope);
        _metadata[$"{RootVersion}.root.json"] = bytes;
        _metadata["root.json"] = bytes;
    }

    private void PublishTargets()
    {
        var targetsDict = new Dictionary<string, object>();
        foreach (var (path, content) in _targets)
        {
            targetsDict[path] = new Dictionary<string, object>
            {
                ["length"] = content.Length,
                ["hashes"] = new Dictionary<string, string>
                {
                    ["sha256"] = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant()
                }
            };
        }

        var signed = new Dictionary<string, object>
        {
            ["_type"] = "targets",
            ["spec_version"] = "1.0",
            ["version"] = TargetsVersion,
            ["expires"] = (ExpiredRoles.Contains("targets")
                ? DateTimeOffset.UtcNow.AddDays(-1)
                : TargetsExpiry).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            ["targets"] = targetsDict
        };

        var envelope = SignEnvelope(signed, UnsignedRoles.Contains("targets") ? null : _targetsKey);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(envelope);
        _metadata[$"{TargetsVersion}.targets.json"] = bytes;
        _metadata["targets.json"] = bytes;
    }

    private void PublishSnapshot()
    {
        var meta = new Dictionary<string, object>
        {
            ["targets.json"] = new Dictionary<string, object>
            {
                ["version"] = TargetsVersion
            }
        };

        var signed = new Dictionary<string, object>
        {
            ["_type"] = "snapshot",
            ["spec_version"] = "1.0",
            ["version"] = SnapshotVersion,
            ["expires"] = (ExpiredRoles.Contains("snapshot")
                ? DateTimeOffset.UtcNow.AddDays(-1)
                : SnapshotExpiry).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            ["meta"] = meta
        };

        var envelope = SignEnvelope(signed, UnsignedRoles.Contains("snapshot") ? null : _snapshotKey);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(envelope);
        _metadata[$"{SnapshotVersion}.snapshot.json"] = bytes;
        _metadata["snapshot.json"] = bytes;
    }

    private void PublishTimestamp()
    {
        var snapshotBytes = _metadata.GetValueOrDefault("snapshot.json");
        var snapshotHash = snapshotBytes != null
            ? Convert.ToHexString(SHA256.HashData(snapshotBytes)).ToLowerInvariant()
            : "";

        var signed = new Dictionary<string, object>
        {
            ["_type"] = "timestamp",
            ["spec_version"] = "1.0",
            ["version"] = TimestampVersion,
            ["expires"] = (ExpiredRoles.Contains("timestamp")
                ? DateTimeOffset.UtcNow.AddDays(-1)
                : TimestampExpiry).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            ["meta"] = new Dictionary<string, object>
            {
                ["snapshot.json"] = new Dictionary<string, object>
                {
                    ["version"] = SnapshotVersion,
                    ["hashes"] = new Dictionary<string, string>
                    {
                        ["sha256"] = snapshotHash
                    },
                    ["length"] = snapshotBytes?.Length ?? 0
                }
            }
        };

        var envelope = SignEnvelope(signed, UnsignedRoles.Contains("timestamp") ? null : _timestampKey);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(envelope);
        _metadata["timestamp.json"] = bytes;
    }

    private Dictionary<string, object> BuildKeysDict()
    {
        return new Dictionary<string, object>
        {
            [_rootKeyId] = BuildKeyEntry(_rootKey),
            [_targetsKeyId] = BuildKeyEntry(_targetsKey),
            [_snapshotKeyId] = BuildKeyEntry(_snapshotKey),
            [_timestampKeyId] = BuildKeyEntry(_timestampKey)
        };
    }

    private Dictionary<string, object> BuildRolesDict()
    {
        return new Dictionary<string, object>
        {
            ["root"] = new Dictionary<string, object>
            {
                ["keyids"] = new[] { _rootKeyId },
                ["threshold"] = 1
            },
            ["targets"] = new Dictionary<string, object>
            {
                ["keyids"] = new[] { _targetsKeyId },
                ["threshold"] = 1
            },
            ["snapshot"] = new Dictionary<string, object>
            {
                ["keyids"] = new[] { _snapshotKeyId },
                ["threshold"] = 1
            },
            ["timestamp"] = new Dictionary<string, object>
            {
                ["keyids"] = new[] { _timestampKeyId },
                ["threshold"] = 1
            }
        };
    }

    private static Dictionary<string, object> BuildKeyEntry(ECDsa key)
    {
        var pem = key.ExportSubjectPublicKeyInfoPem();
        return new Dictionary<string, object>
        {
            ["keytype"] = "ecdsa",
            ["scheme"] = "ecdsa-sha2-nistp256",
            ["keyval"] = new Dictionary<string, string>
            {
                ["public"] = pem
            }
        };
    }

    private Dictionary<string, object> SignEnvelope(Dictionary<string, object> signed, ECDsa? signingKey)
    {
        // Canonicalize the signed dict
        var canonicalBytes = OlpcCanonicalJson(signed);

        var signatures = new List<Dictionary<string, string>>();
        if (signingKey != null)
        {
            var sig = signingKey.SignData(canonicalBytes, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            var keyId = ComputeKeyId(signingKey);
            signatures.Add(new Dictionary<string, string>
            {
                ["keyid"] = keyId,
                ["sig"] = Convert.ToHexString(sig).ToLowerInvariant()
            });
        }

        return new Dictionary<string, object>
        {
            ["signatures"] = signatures,
            ["signed"] = signed
        };
    }

    /// <summary>
    /// OLPC Canonical JSON for signing. Must match the same canonical form
    /// used by TufMetadataParser.CanonicalizeJson.
    /// </summary>
    private static byte[] OlpcCanonicalJson(object obj)
    {
        using var ms = new MemoryStream();
        WriteOlpc(ms, obj);
        return ms.ToArray();
    }

    private static void WriteOlpc(MemoryStream ms, object obj)
    {
        switch (obj)
        {
            case string s:
                ms.WriteByte((byte)'"');
                var utf8 = Encoding.UTF8.GetBytes(s);
                foreach (var b in utf8)
                {
                    switch (b)
                    {
                        case (byte)'\\': ms.WriteByte((byte)'\\'); ms.WriteByte((byte)'\\'); break;
                        case (byte)'"': ms.WriteByte((byte)'\\'); ms.WriteByte((byte)'"'); break;
                        default: ms.WriteByte(b); break;
                    }
                }
                ms.WriteByte((byte)'"');
                break;

            case bool b:
                ms.Write(Encoding.UTF8.GetBytes(b ? "true" : "false"));
                break;

            case int i:
                ms.Write(Encoding.UTF8.GetBytes(i.ToString()));
                break;

            case long l:
                ms.Write(Encoding.UTF8.GetBytes(l.ToString()));
                break;

            case Dictionary<string, object> dict:
                ms.WriteByte((byte)'{');
                var sortedKeys = dict.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();
                for (var i = 0; i < sortedKeys.Count; i++)
                {
                    if (i > 0) ms.WriteByte((byte)',');
                    WriteOlpc(ms, sortedKeys[i]);
                    ms.WriteByte((byte)':');
                    WriteOlpc(ms, dict[sortedKeys[i]]);
                }
                ms.WriteByte((byte)'}');
                break;

            case Dictionary<string, string> strDict:
                ms.WriteByte((byte)'{');
                var sortedStrKeys = strDict.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();
                for (var i = 0; i < sortedStrKeys.Count; i++)
                {
                    if (i > 0) ms.WriteByte((byte)',');
                    WriteOlpc(ms, sortedStrKeys[i]);
                    ms.WriteByte((byte)':');
                    WriteOlpc(ms, (object)strDict[sortedStrKeys[i]]);
                }
                ms.WriteByte((byte)'}');
                break;

            case IEnumerable<object> list:
                ms.WriteByte((byte)'[');
                var items = list.ToList();
                for (var i = 0; i < items.Count; i++)
                {
                    if (i > 0) ms.WriteByte((byte)',');
                    WriteOlpc(ms, items[i]);
                }
                ms.WriteByte((byte)']');
                break;

            default:
                throw new NotSupportedException($"OLPC canonical: unsupported type {obj.GetType().Name}");
        }
    }

    private static string ComputeKeyId(ECDsa key)
    {
        var pem = key.ExportSubjectPublicKeyInfoPem();
        var keyEntry = new Dictionary<string, object>
        {
            ["keytype"] = "ecdsa",
            ["keyval"] = new Dictionary<string, string>
            {
                ["public"] = pem
            },
            ["scheme"] = "ecdsa-sha2-nistp256"
        };
        var canonical = OlpcCanonicalJson(keyEntry);
        return Convert.ToHexString(SHA256.HashData(canonical)).ToLowerInvariant();
    }

    // ITufRepository implementation

    public Task<byte[]?> FetchMetadataAsync(string role, int? version = null, CancellationToken cancellationToken = default)
    {
        var key = version.HasValue ? $"{version}.{role}.json" : $"{role}.json";
        _requestLog.Add(key);

        // Check for tampered roots
        if (role == "root" && version.HasValue && TamperedRoots.TryGetValue(version.Value, out var tampered))
            return Task.FromResult<byte[]?>(tampered);

        return Task.FromResult(_metadata.GetValueOrDefault(key));
    }

    public Task<byte[]?> FetchTargetAsync(string targetPath, CancellationToken cancellationToken = default)
    {
        _requestLog.Add($"target:{targetPath}");
        return Task.FromResult(_targets.GetValueOrDefault(targetPath));
    }
}
