namespace Tuf.Metadata;

/// <summary>
/// Represents a TUF signed metadata envelope containing signatures and signed content.
/// </summary>
public sealed class SignedMetadata<T> where T : TufMetadata
{
    /// <summary>
    /// The signatures over the canonical JSON of <see cref="Signed"/>.
    /// </summary>
    public required List<TufSignature> Signatures { get; init; }

    /// <summary>
    /// The signed metadata content.
    /// </summary>
    public required T Signed { get; init; }

    /// <summary>
    /// The raw canonical JSON bytes of the "signed" portion, used for signature verification.
    /// </summary>
    public required byte[] SignedBytes { get; init; }
}

/// <summary>
/// Base class for all TUF metadata types.
/// </summary>
public abstract class TufMetadata
{
    /// <summary>
    /// The type of metadata (e.g., "root", "timestamp", "snapshot", "targets").
    /// </summary>
    public required string Type { get; init; }

    /// <summary>
    /// The TUF specification version this metadata conforms to.
    /// </summary>
    public required string SpecVersion { get; init; }

    /// <summary>
    /// The version number of this metadata. Monotonically increasing.
    /// </summary>
    public required int Version { get; init; }

    /// <summary>
    /// The expiration time for this metadata.
    /// </summary>
    public required DateTimeOffset Expires { get; init; }
}

/// <summary>
/// A cryptographic signature over TUF metadata.
/// </summary>
public sealed class TufSignature
{
    /// <summary>
    /// The identifier of the key used to create this signature.
    /// </summary>
    public required string KeyId { get; init; }

    /// <summary>
    /// The hex-encoded signature value.
    /// </summary>
    public required string Sig { get; init; }
}

/// <summary>
/// A cryptographic key used in TUF metadata.
/// </summary>
public sealed class TufKey
{
    /// <summary>
    /// The key type (e.g., "ed25519", "ecdsa-sha2-nistp256", "rsa").
    /// </summary>
    public required string KeyType { get; init; }

    /// <summary>
    /// The signing scheme (e.g., "ed25519", "ecdsa-sha2-nistp256", "rsassa-pss-sha256").
    /// </summary>
    public required string Scheme { get; init; }

    /// <summary>
    /// The key value dictionary. Typically contains "public" with the hex-encoded public key.
    /// </summary>
    public required Dictionary<string, string> KeyVal { get; init; }
}

/// <summary>
/// Defines a TUF role with key IDs and a signing threshold.
/// </summary>
public sealed class TufRole
{
    /// <summary>
    /// The key IDs authorized for this role.
    /// </summary>
    public required List<string> KeyIds { get; init; }

    /// <summary>
    /// The minimum number of signatures required from the authorized keys.
    /// </summary>
    public required int Threshold { get; init; }
}
