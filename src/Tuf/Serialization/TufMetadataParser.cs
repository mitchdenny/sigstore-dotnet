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

        // Extract the raw "signed" bytes from the original JSON for signature verification.
        // We must use the exact bytes from the original, not re-serialize, to preserve canonical form.
        var signedBytes = ExtractSignedBytes(json);

        return (signatures, signedBytes, envelope.Signed);
    }

    /// <summary>
    /// Extracts the canonical JSON bytes of the "signed" value from the TUF envelope JSON.
    /// TUF signatures are computed over canonical JSON (sorted keys, no whitespace).
    /// </summary>
    private static byte[] ExtractSignedBytes(byte[] json)
    {
        using var doc = JsonDocument.Parse(json);
        var signedElement = doc.RootElement.GetProperty("signed");
        return CanonicalizeJson(signedElement);
    }

    /// <summary>
    /// Produces canonical JSON (sorted keys, no whitespace) from a JsonElement.
    /// This follows the canonical JSON format used by TUF/securesystemslib.
    /// </summary>
    /// <summary>
    /// Produces OLPC Canonical JSON bytes from a JsonElement.
    /// Per http://wiki.laptop.org/go/Canonical_JSON and securesystemslib:
    /// - Sorted dict keys
    /// - No whitespace between tokens
    /// - Only \ and " are escaped in strings (raw bytes for everything else including newlines)
    /// - Integers only (no floats)
    /// </summary>
    private static byte[] CanonicalizeJson(JsonElement element)
    {
        using var ms = new MemoryStream();
        WriteCanonical(ms, element);
        return ms.ToArray();
    }

    private static void WriteCanonical(MemoryStream ms, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                ms.WriteByte((byte)'{');
                var properties = element.EnumerateObject()
                    .OrderBy(p => p.Name, StringComparer.Ordinal)
                    .ToList();
                for (var i = 0; i < properties.Count; i++)
                {
                    if (i > 0)
                        ms.WriteByte((byte)',');
                    WriteCanonicalString(ms, properties[i].Name);
                    ms.WriteByte((byte)':');
                    WriteCanonical(ms, properties[i].Value);
                }
                ms.WriteByte((byte)'}');
                break;

            case JsonValueKind.Array:
                ms.WriteByte((byte)'[');
                var index = 0;
                foreach (var item in element.EnumerateArray())
                {
                    if (index > 0)
                        ms.WriteByte((byte)',');
                    WriteCanonical(ms, item);
                    index++;
                }
                ms.WriteByte((byte)']');
                break;

            case JsonValueKind.String:
                WriteCanonicalString(ms, element.GetString()!);
                break;

            case JsonValueKind.Number:
                var numBytes = System.Text.Encoding.UTF8.GetBytes(element.GetRawText());
                ms.Write(numBytes);
                break;

            case JsonValueKind.True:
                ms.Write("true"u8);
                break;

            case JsonValueKind.False:
                ms.Write("false"u8);
                break;

            case JsonValueKind.Null:
                ms.Write("null"u8);
                break;
        }
    }

    /// <summary>
    /// Writes a string in OLPC canonical form: only \ and " are escaped.
    /// All other characters (including control characters like \n) are written as raw UTF-8 bytes.
    /// </summary>
    private static void WriteCanonicalString(MemoryStream ms, string value)
    {
        ms.WriteByte((byte)'"');
        var utf8Bytes = System.Text.Encoding.UTF8.GetBytes(value);
        foreach (var b in utf8Bytes)
        {
            switch (b)
            {
                case (byte)'\\':
                    ms.WriteByte((byte)'\\');
                    ms.WriteByte((byte)'\\');
                    break;
                case (byte)'"':
                    ms.WriteByte((byte)'\\');
                    ms.WriteByte((byte)'"');
                    break;
                default:
                    ms.WriteByte(b);
                    break;
            }
        }
        ms.WriteByte((byte)'"');
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
