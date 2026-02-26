using System.Text.Json;
using System.Text.Json.Serialization;

namespace Tuf.Serialization;

// JSON DTO types that mirror the TUF metadata JSON schema.

internal sealed class SignedEnvelopeJson
{
    public List<SignatureJson>? Signatures { get; set; }
    public JsonElement Signed { get; set; }
}

internal sealed class SignatureJson
{
    public string? Keyid { get; set; }
    public string? Sig { get; set; }
}

internal sealed class RootSignedJson
{
    [JsonPropertyName("_type")]
    public string? Type { get; set; }
    [JsonPropertyName("spec_version")]
    public string? SpecVersion { get; set; }
    public int Version { get; set; }
    public string? Expires { get; set; }
    [JsonPropertyName("consistent_snapshot")]
    public bool ConsistentSnapshot { get; set; }
    public Dictionary<string, KeyJson>? Keys { get; set; }
    public Dictionary<string, RoleJson>? Roles { get; set; }
}

internal sealed class KeyJson
{
    public string? Keytype { get; set; }
    public string? Scheme { get; set; }
    public Dictionary<string, string>? Keyval { get; set; }
    [JsonPropertyName("keyid_hash_algorithms")]
    public List<string>? KeyidHashAlgorithms { get; set; }
}

internal sealed class RoleJson
{
    public List<string>? Keyids { get; set; }
    public int Threshold { get; set; }
}

internal sealed class TimestampSignedJson
{
    [JsonPropertyName("_type")]
    public string? Type { get; set; }
    [JsonPropertyName("spec_version")]
    public string? SpecVersion { get; set; }
    public int Version { get; set; }
    public string? Expires { get; set; }
    public Dictionary<string, MetaFileJson>? Meta { get; set; }
}

internal sealed class SnapshotSignedJson
{
    [JsonPropertyName("_type")]
    public string? Type { get; set; }
    [JsonPropertyName("spec_version")]
    public string? SpecVersion { get; set; }
    public int Version { get; set; }
    public string? Expires { get; set; }
    public Dictionary<string, MetaFileJson>? Meta { get; set; }
}

internal sealed class MetaFileJson
{
    public int Version { get; set; }
    public long? Length { get; set; }
    public Dictionary<string, string>? Hashes { get; set; }
}

internal sealed class TargetsSignedJson
{
    [JsonPropertyName("_type")]
    public string? Type { get; set; }
    [JsonPropertyName("spec_version")]
    public string? SpecVersion { get; set; }
    public int Version { get; set; }
    public string? Expires { get; set; }
    public Dictionary<string, TargetFileJson>? Targets { get; set; }
    public DelegationsJson? Delegations { get; set; }
}

internal sealed class TargetFileJson
{
    public long Length { get; set; }
    public Dictionary<string, string>? Hashes { get; set; }
    public Dictionary<string, object>? Custom { get; set; }
}

internal sealed class DelegationsJson
{
    public Dictionary<string, KeyJson>? Keys { get; set; }
    public List<DelegatedRoleJson>? Roles { get; set; }
}

internal sealed class DelegatedRoleJson
{
    public string? Name { get; set; }
    public List<string>? Keyids { get; set; }
    public int Threshold { get; set; }
    public bool Terminating { get; set; }
    public List<string>? Paths { get; set; }
    [JsonPropertyName("path_hash_prefixes")]
    public List<string>? PathHashPrefixes { get; set; }
}

// Source-generated JSON serializer contexts for AOT compatibility

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    PropertyNameCaseInsensitive = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(SignedEnvelopeJson))]
internal sealed partial class TufEnvelopeJsonContext : JsonSerializerContext;

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    PropertyNameCaseInsensitive = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(RootSignedJson))]
[JsonSerializable(typeof(TimestampSignedJson))]
[JsonSerializable(typeof(SnapshotSignedJson))]
[JsonSerializable(typeof(TargetsSignedJson))]
internal sealed partial class TufMetadataJsonContext : JsonSerializerContext;
