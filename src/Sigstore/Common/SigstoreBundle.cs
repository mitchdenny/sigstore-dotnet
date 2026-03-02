
namespace Sigstore;

/// <summary>
/// Represents a Sigstore bundle containing signature and verification material.
/// This is the primary unit of exchange for signed artifacts.
/// </summary>
public sealed class SigstoreBundle
{
    /// <summary>
    /// The media type of the bundle (e.g., "application/vnd.dev.sigstore.bundle.v0.3+json").
    /// </summary>
    public string MediaType { get; init; } = "application/vnd.dev.sigstore.bundle.v0.3+json";

    /// <summary>
    /// The verification material (certificate or public key, log entries, timestamps).
    /// </summary>
    public VerificationMaterial? VerificationMaterial { get; init; }

    /// <summary>
    /// The message signature (for artifact signing).
    /// </summary>
    public MessageSignature? MessageSignature { get; init; }

    /// <summary>
    /// The DSSE envelope (for in-toto attestation signing).
    /// </summary>
    public DsseEnvelope? DsseEnvelope { get; init; }

    /// <summary>
    /// Deserializes a Sigstore bundle from JSON.
    /// </summary>
    public static SigstoreBundle Deserialize(string json)
    {
        return BundleSerializer.Deserialize(json);
    }

    /// <summary>
    /// Deserializes a Sigstore bundle from a stream.
    /// </summary>
    public static SigstoreBundle Deserialize(Stream stream)
    {
        return BundleSerializer.Deserialize(stream);
    }

    /// <summary>
    /// Serializes this bundle to canonical JSON.
    /// </summary>
    public string Serialize()
    {
        return BundleSerializer.Serialize(this);
    }

    /// <summary>
    /// Serializes this bundle to canonical JSON written directly to a stream.
    /// </summary>
    public void Serialize(Stream stream)
    {
        BundleSerializer.Serialize(this, stream);
    }

    /// <summary>
    /// Loads a Sigstore bundle from a JSON file.
    /// </summary>
    public static async Task<SigstoreBundle> LoadAsync(string path, CancellationToken cancellationToken = default)
    {
        await using var stream = File.OpenRead(path);
        return Deserialize(stream);
    }

    /// <summary>
    /// Saves this bundle to a JSON file.
    /// </summary>
    public async Task SaveAsync(string path, CancellationToken cancellationToken = default)
    {
        var json = Serialize();
        await File.WriteAllTextAsync(path, json, cancellationToken);
    }
}

/// <summary>
/// Verification material embedded in a Sigstore bundle.
/// </summary>
public sealed class VerificationMaterial
{
    /// <summary>
    /// The signing certificate (leaf certificate, DER-encoded).
    /// </summary>
    public ReadOnlyMemory<byte>? Certificate { get; init; }

    /// <summary>
    /// The certificate chain (for v0.1/v0.2 bundles).
    /// </summary>
    public IReadOnlyList<ReadOnlyMemory<byte>>? CertificateChain { get; init; }

    /// <summary>
    /// Public key identifier hint (for key-based verification).
    /// </summary>
    public string? PublicKeyHint { get; init; }

    /// <summary>
    /// Transparency log entries with inclusion proofs.
    /// </summary>
    public IReadOnlyList<TransparencyLogEntry> TlogEntries { get; init; } = [];

    /// <summary>
    /// RFC 3161 signed timestamps.
    /// </summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> Rfc3161Timestamps { get; init; } = [];
}

/// <summary>
/// A message signature over an artifact.
/// </summary>
public sealed class MessageSignature
{
    /// <summary>
    /// The digest of the signed message.
    /// </summary>
    public HashOutput? MessageDigest { get; init; }

    /// <summary>
    /// The raw signature bytes.
    /// </summary>
    public ReadOnlyMemory<byte> Signature { get; init; }
}

/// <summary>
/// A hash output (algorithm + digest bytes).
/// </summary>
public sealed class HashOutput
{
    /// <summary>The hash algorithm used.</summary>
    public HashAlgorithmType Algorithm { get; init; }
    /// <summary>The digest bytes.</summary>
    public ReadOnlyMemory<byte> Digest { get; init; }
}

/// <summary>
/// Supported hash algorithms.
/// </summary>
public enum HashAlgorithmType
{
    /// <summary>Unspecified hash algorithm.</summary>
    Unspecified = 0,
    /// <summary>SHA2-256.</summary>
    Sha2_256 = 1,
    /// <summary>SHA2-384.</summary>
    Sha2_384 = 2,
    /// <summary>SHA2-512.</summary>
    Sha2_512 = 3,
    /// <summary>SHA3-256.</summary>
    Sha3_256 = 4,
    /// <summary>SHA3-384.</summary>
    Sha3_384 = 5
}

/// <summary>
/// A transparency log entry with inclusion proof and checkpoint.
/// </summary>
public sealed class TransparencyLogEntry
{
    /// <summary>
    /// The index of the entry in the log.
    /// </summary>
    public long LogIndex { get; init; }

    /// <summary>
    /// The log ID (SHA-256 of the log's public key).
    /// </summary>
    public ReadOnlyMemory<byte> LogId { get; init; }

    /// <summary>
    /// The kind (type) and version of the log entry.
    /// </summary>
    public string? Kind { get; init; }

    /// <summary>
    /// The API version of the log entry type.
    /// </summary>
    public string? KindVersion { get; init; }

    /// <summary>
    /// The body of the log entry (base64-encoded JSON with kind/apiVersion).
    /// </summary>
    public string? Body { get; init; }

    /// <summary>
    /// The integrated time (Unix timestamp).
    /// </summary>
    public long IntegratedTime { get; init; }

    /// <summary>
    /// The inclusion proof.
    /// </summary>
    public InclusionProof? InclusionProof { get; init; }

    /// <summary>
    /// The inclusion promise (deprecated, for v0.1 bundles).
    /// </summary>
    public ReadOnlyMemory<byte>? InclusionPromise { get; init; }

    /// <summary>
    /// Checkpoint key ID for Rekor v2 verification.
    /// </summary>
    public ReadOnlyMemory<byte>? CheckpointKeyId { get; init; }}

/// <summary>
/// A Merkle tree inclusion proof.
/// </summary>
public sealed class InclusionProof
{
    /// <summary>The index of the entry in the log.</summary>
    public long LogIndex { get; init; }
    /// <summary>The size of the Merkle tree at the time of the proof.</summary>
    public long TreeSize { get; init; }
    /// <summary>The root hash of the Merkle tree.</summary>
    public ReadOnlyMemory<byte> RootHash { get; init; }
    /// <summary>The intermediate hashes forming the inclusion proof path.</summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> Hashes { get; init; } = [];

    /// <summary>
    /// The signed checkpoint from the transparency log.
    /// </summary>
    public string? Checkpoint { get; init; }
}

/// <summary>
/// A DSSE (Dead Simple Signing Envelope) for in-toto attestations.
/// </summary>
public sealed class DsseEnvelope
{
    /// <summary>The payload content type (e.g., "application/vnd.in-toto+json").</summary>
    public string PayloadType { get; init; } = "";
    /// <summary>The raw payload bytes.</summary>
    public ReadOnlyMemory<byte> Payload { get; init; }
    /// <summary>The signatures over the PAE-encoded payload.</summary>
    public IReadOnlyList<DsseSignature> Signatures { get; init; } = [];
}

/// <summary>
/// A signature within a DSSE envelope.
/// </summary>
public sealed class DsseSignature
{
    /// <summary>The key identifier for the signer.</summary>
    public string KeyId { get; init; } = "";
    /// <summary>The raw signature bytes.</summary>
    public ReadOnlyMemory<byte> Sig { get; init; }
}
