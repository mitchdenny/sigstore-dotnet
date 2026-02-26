using Sigstore.Bundle;

namespace Sigstore.Common;

/// <summary>
/// Represents a Sigstore bundle containing signature and verification material.
/// This is the primary unit of exchange for signed artifacts.
/// </summary>
public class SigstoreBundle
{
    /// <summary>
    /// The media type of the bundle (e.g., "application/vnd.dev.sigstore.bundle.v0.3+json").
    /// </summary>
    public string MediaType { get; set; } = "application/vnd.dev.sigstore.bundle.v0.3+json";

    /// <summary>
    /// The verification material (certificate or public key, log entries, timestamps).
    /// </summary>
    public VerificationMaterial? VerificationMaterial { get; set; }

    /// <summary>
    /// The message signature (for artifact signing).
    /// </summary>
    public MessageSignature? MessageSignature { get; set; }

    /// <summary>
    /// The DSSE envelope (for in-toto attestation signing).
    /// </summary>
    public DsseEnvelope? DsseEnvelope { get; set; }

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
}

/// <summary>
/// Verification material embedded in a Sigstore bundle.
/// </summary>
public class VerificationMaterial
{
    /// <summary>
    /// The signing certificate (leaf certificate, DER-encoded).
    /// </summary>
    public byte[]? Certificate { get; set; }

    /// <summary>
    /// The certificate chain (for v0.1/v0.2 bundles).
    /// </summary>
    public List<byte[]>? CertificateChain { get; set; }

    /// <summary>
    /// Public key identifier hint (for key-based verification).
    /// </summary>
    public string? PublicKeyHint { get; set; }

    /// <summary>
    /// Transparency log entries with inclusion proofs.
    /// </summary>
    public List<TransparencyLogEntry> TlogEntries { get; set; } = [];

    /// <summary>
    /// RFC 3161 signed timestamps.
    /// </summary>
    public List<byte[]> Rfc3161Timestamps { get; set; } = [];
}

/// <summary>
/// A message signature over an artifact.
/// </summary>
public class MessageSignature
{
    /// <summary>
    /// The digest of the signed message.
    /// </summary>
    public HashOutput? MessageDigest { get; set; }

    /// <summary>
    /// The raw signature bytes.
    /// </summary>
    public byte[] Signature { get; set; } = [];
}

/// <summary>
/// A hash output (algorithm + digest bytes).
/// </summary>
public class HashOutput
{
    /// <summary>The hash algorithm used.</summary>
    public HashAlgorithmType Algorithm { get; set; }
    /// <summary>The digest bytes.</summary>
    public byte[] Digest { get; set; } = [];
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
public class TransparencyLogEntry
{
    /// <summary>
    /// The index of the entry in the log.
    /// </summary>
    public long LogIndex { get; set; }

    /// <summary>
    /// The log ID (SHA-256 of the log's public key).
    /// </summary>
    public byte[] LogId { get; set; } = [];

    /// <summary>
    /// The body of the log entry (base64-encoded JSON with kind/apiVersion).
    /// </summary>
    public string? Body { get; set; }

    /// <summary>
    /// The integrated time (Unix timestamp).
    /// </summary>
    public long IntegratedTime { get; set; }

    /// <summary>
    /// The inclusion proof.
    /// </summary>
    public InclusionProof? InclusionProof { get; set; }

    /// <summary>
    /// The inclusion promise (deprecated, for v0.1 bundles).
    /// </summary>
    public byte[]? InclusionPromise { get; set; }

    /// <summary>
    /// Checkpoint key ID for Rekor v2 verification.
    /// </summary>
    public byte[]? CheckpointKeyId { get; set; }
}

/// <summary>
/// A Merkle tree inclusion proof.
/// </summary>
public class InclusionProof
{
    /// <summary>The index of the entry in the log.</summary>
    public long LogIndex { get; set; }
    /// <summary>The size of the Merkle tree at the time of the proof.</summary>
    public long TreeSize { get; set; }
    /// <summary>The root hash of the Merkle tree.</summary>
    public byte[] RootHash { get; set; } = [];
    /// <summary>The intermediate hashes forming the inclusion proof path.</summary>
    public List<byte[]> Hashes { get; set; } = [];

    /// <summary>
    /// The signed checkpoint from the transparency log.
    /// </summary>
    public string? Checkpoint { get; set; }
}

/// <summary>
/// A DSSE (Dead Simple Signing Envelope) for in-toto attestations.
/// </summary>
public class DsseEnvelope
{
    /// <summary>The payload content type (e.g., "application/vnd.in-toto+json").</summary>
    public string PayloadType { get; set; } = "";
    /// <summary>The raw payload bytes.</summary>
    public byte[] Payload { get; set; } = [];
    /// <summary>The signatures over the PAE-encoded payload.</summary>
    public List<DsseSignature> Signatures { get; set; } = [];
}

/// <summary>
/// A signature within a DSSE envelope.
/// </summary>
public class DsseSignature
{
    /// <summary>The key identifier for the signer.</summary>
    public string KeyId { get; set; } = "";
    /// <summary>The raw signature bytes.</summary>
    public byte[] Sig { get; set; } = [];
}
