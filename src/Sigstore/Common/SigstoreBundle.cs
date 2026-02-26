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
        throw new NotImplementedException();
    }

    /// <summary>
    /// Deserializes a Sigstore bundle from a stream.
    /// </summary>
    public static SigstoreBundle Deserialize(Stream stream)
    {
        throw new NotImplementedException();
    }

    /// <summary>
    /// Serializes this bundle to canonical JSON.
    /// </summary>
    public string Serialize()
    {
        throw new NotImplementedException();
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
    public HashAlgorithmType Algorithm { get; set; }
    public byte[] Digest { get; set; } = [];
}

/// <summary>
/// Supported hash algorithms.
/// </summary>
public enum HashAlgorithmType
{
    Unspecified = 0,
    Sha2_256 = 1,
    Sha2_384 = 2,
    Sha2_512 = 3,
    Sha3_256 = 4,
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
    public long LogIndex { get; set; }
    public long TreeSize { get; set; }
    public byte[] RootHash { get; set; } = [];
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
    public string PayloadType { get; set; } = "";
    public byte[] Payload { get; set; } = [];
    public List<DsseSignature> Signatures { get; set; } = [];
}

/// <summary>
/// A signature within a DSSE envelope.
/// </summary>
public class DsseSignature
{
    public string KeyId { get; set; } = "";
    public byte[] Sig { get; set; } = [];
}
