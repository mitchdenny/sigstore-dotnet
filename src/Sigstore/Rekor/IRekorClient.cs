using Sigstore.Common;

namespace Sigstore.Rekor;

/// <summary>
/// Client for interacting with a Rekor transparency log instance.
/// Supports both v1 and v2 APIs.
/// </summary>
public interface IRekorClient
{
    /// <summary>
    /// Submits signing metadata to the transparency log as a hashedrekord entry.
    /// </summary>
    Task<TransparencyLogEntry> SubmitEntryAsync(
        RekorEntry entry,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Submits a DSSE envelope to the transparency log as a dsse entry.
    /// </summary>
    Task<TransparencyLogEntry> SubmitDsseEntryAsync(
        RekorDsseEntry entry,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// An entry to submit to the Rekor transparency log.
/// </summary>
public class RekorEntry
{
    /// <summary>
    /// The signature bytes.
    /// </summary>
    public required ReadOnlyMemory<byte> Signature { get; init; }

    /// <summary>
    /// The artifact hash.
    /// </summary>
    public required ReadOnlyMemory<byte> ArtifactDigest { get; init; }

    /// <summary>
    /// The hash algorithm used for the artifact digest.
    /// </summary>
    public HashAlgorithmType DigestAlgorithm { get; init; } = HashAlgorithmType.Sha2_256;

    /// <summary>
    /// The signing certificate (PEM-encoded) or public key.
    /// </summary>
    public required string VerificationMaterial { get; init; }
}

/// <summary>
/// A DSSE entry to submit to the Rekor transparency log.
/// </summary>
public class RekorDsseEntry
{
    /// <summary>The DSSE envelope payload bytes.</summary>
    public required byte[] Payload { get; init; }

    /// <summary>The DSSE envelope payload type.</summary>
    public required string PayloadType { get; init; }

    /// <summary>The signature over the PAE.</summary>
    public required byte[] Signature { get; init; }

    /// <summary>The signing certificate (PEM-encoded).</summary>
    public required string VerificationMaterial { get; init; }
}
