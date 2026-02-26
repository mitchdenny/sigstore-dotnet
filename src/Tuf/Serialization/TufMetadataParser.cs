using System.Text.Json;
using Tuf.Metadata;

namespace Tuf.Serialization;

/// <summary>
/// Parses TUF metadata JSON into domain model types.
/// </summary>
internal static class TufMetadataParser
{
    /// <summary>
    /// Parses a TUF signed envelope, extracting signatures and the raw signed bytes for verification.
    /// </summary>
    public static (List<TufSignature> Signatures, byte[] SignedBytes, JsonElement SignedElement) ParseEnvelope(byte[] json)
    {
        var envelope = JsonSerializer.Deserialize(json, TufEnvelopeJsonContext.Default.SignedEnvelopeJson)
                       ?? throw new JsonException("Failed to deserialize TUF metadata envelope.");

        var signatures = envelope.Signatures?.Select(s => new TufSignature
        {
            KeyId = s.Keyid ?? throw new JsonException("Missing keyid in signature."),
            Sig = s.Sig ?? ""
        }).ToList() ?? [];

        // Extract the raw "signed" bytes for signature verification
        var signedBytes = JsonSerializer.SerializeToUtf8Bytes(
            envelope.Signed, TufEnvelopeJsonContext.Default.JsonElement);

        return (signatures, signedBytes, envelope.Signed);
    }

    /// <summary>
    /// Parses a root metadata JSON element.
    /// </summary>
    public static SignedMetadata<RootMetadata> ParseRoot(byte[] json)
    {
        var (signatures, signedBytes, signedElement) = ParseEnvelope(json);
        var dto = signedElement.Deserialize(TufMetadataJsonContext.Default.RootSignedJson)
                  ?? throw new JsonException("Failed to deserialize root metadata.");

        ValidateType(dto.Type, "root");

        var keys = dto.Keys?.ToDictionary(
            kvp => kvp.Key,
            kvp => new TufKey
            {
                KeyType = kvp.Value.Keytype ?? "",
                Scheme = kvp.Value.Scheme ?? "",
                KeyVal = kvp.Value.Keyval ?? new Dictionary<string, string>()
            }) ?? new Dictionary<string, TufKey>();

        var roles = dto.Roles?.ToDictionary(
            kvp => kvp.Key,
            kvp => new TufRole
            {
                KeyIds = kvp.Value.Keyids ?? [],
                Threshold = kvp.Value.Threshold
            }) ?? new Dictionary<string, TufRole>();

        return new SignedMetadata<RootMetadata>
        {
            Signatures = signatures,
            SignedBytes = signedBytes,
            Signed = new RootMetadata
            {
                Type = "root",
                SpecVersion = dto.SpecVersion ?? "1.0",
                Version = dto.Version,
                Expires = ParseExpires(dto.Expires),
                ConsistentSnapshot = dto.ConsistentSnapshot,
                Keys = keys,
                Roles = roles
            }
        };
    }

    /// <summary>
    /// Parses a timestamp metadata JSON element.
    /// </summary>
    public static SignedMetadata<TimestampMetadata> ParseTimestamp(byte[] json)
    {
        var (signatures, signedBytes, signedElement) = ParseEnvelope(json);
        var dto = signedElement.Deserialize(TufMetadataJsonContext.Default.TimestampSignedJson)
                  ?? throw new JsonException("Failed to deserialize timestamp metadata.");

        ValidateType(dto.Type, "timestamp");

        var snapshotMeta = dto.Meta?.GetValueOrDefault("snapshot.json");

        return new SignedMetadata<TimestampMetadata>
        {
            Signatures = signatures,
            SignedBytes = signedBytes,
            Signed = new TimestampMetadata
            {
                Type = "timestamp",
                SpecVersion = dto.SpecVersion ?? "1.0",
                Version = dto.Version,
                Expires = ParseExpires(dto.Expires),
                SnapshotMeta = snapshotMeta != null
                    ? ParseMetaFileInfo(snapshotMeta)
                    : throw new JsonException("Missing snapshot.json in timestamp meta.")
            }
        };
    }

    /// <summary>
    /// Parses a snapshot metadata JSON element.
    /// </summary>
    public static SignedMetadata<SnapshotMetadata> ParseSnapshot(byte[] json)
    {
        var (signatures, signedBytes, signedElement) = ParseEnvelope(json);
        var dto = signedElement.Deserialize(TufMetadataJsonContext.Default.SnapshotSignedJson)
                  ?? throw new JsonException("Failed to deserialize snapshot metadata.");

        ValidateType(dto.Type, "snapshot");

        var meta = dto.Meta?.ToDictionary(
            kvp => kvp.Key,
            kvp => ParseMetaFileInfo(kvp.Value)) ?? new Dictionary<string, MetaFileInfo>();

        return new SignedMetadata<SnapshotMetadata>
        {
            Signatures = signatures,
            SignedBytes = signedBytes,
            Signed = new SnapshotMetadata
            {
                Type = "snapshot",
                SpecVersion = dto.SpecVersion ?? "1.0",
                Version = dto.Version,
                Expires = ParseExpires(dto.Expires),
                Meta = meta
            }
        };
    }

    /// <summary>
    /// Parses a targets metadata JSON element.
    /// </summary>
    public static SignedMetadata<TargetsMetadata> ParseTargets(byte[] json)
    {
        var (signatures, signedBytes, signedElement) = ParseEnvelope(json);
        var dto = signedElement.Deserialize(TufMetadataJsonContext.Default.TargetsSignedJson)
                  ?? throw new JsonException("Failed to deserialize targets metadata.");

        ValidateType(dto.Type, "targets");

        var targets = dto.Targets?.ToDictionary(
            kvp => kvp.Key,
            kvp => new TargetFileInfo
            {
                Length = kvp.Value.Length,
                Hashes = kvp.Value.Hashes ?? new Dictionary<string, string>()
            }) ?? new Dictionary<string, TargetFileInfo>();

        Delegations? delegations = null;
        if (dto.Delegations != null)
        {
            delegations = ParseDelegations(dto.Delegations);
        }

        return new SignedMetadata<TargetsMetadata>
        {
            Signatures = signatures,
            SignedBytes = signedBytes,
            Signed = new TargetsMetadata
            {
                Type = "targets",
                SpecVersion = dto.SpecVersion ?? "1.0",
                Version = dto.Version,
                Expires = ParseExpires(dto.Expires),
                Targets = targets,
                Delegations = delegations
            }
        };
    }

    private static MetaFileInfo ParseMetaFileInfo(MetaFileJson dto) => new()
    {
        Version = dto.Version,
        Length = dto.Length,
        Hashes = dto.Hashes
    };

    private static Delegations ParseDelegations(DelegationsJson dto)
    {
        var keys = dto.Keys?.ToDictionary(
            kvp => kvp.Key,
            kvp => new TufKey
            {
                KeyType = kvp.Value.Keytype ?? "",
                Scheme = kvp.Value.Scheme ?? "",
                KeyVal = kvp.Value.Keyval ?? new Dictionary<string, string>()
            }) ?? new Dictionary<string, TufKey>();

        var roles = dto.Roles?.Select(r => new DelegatedRole
        {
            Name = r.Name ?? "",
            KeyIds = r.Keyids ?? [],
            Threshold = r.Threshold,
            Terminating = r.Terminating,
            Paths = r.Paths,
            PathHashPrefixes = r.PathHashPrefixes
        }).ToList() ?? [];

        return new Delegations
        {
            Keys = keys,
            Roles = roles
        };
    }

    private static void ValidateType(string? type, string expected)
    {
        if (type != expected)
            throw new JsonException($"Expected metadata type '{expected}' but got '{type}'.");
    }

    private static DateTimeOffset ParseExpires(string? expires) =>
        expires != null
            ? DateTimeOffset.Parse(expires)
            : throw new JsonException("Missing expires field.");
}
