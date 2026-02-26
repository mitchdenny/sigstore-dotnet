using Sigstore.Common;

namespace Sigstore.Rekor;

/// <summary>
/// Client for interacting with a Rekor transparency log instance.
/// Supports both v1 and v2 APIs.
/// </summary>
public interface IRekorClient
{
    /// <summary>
    /// Submits signing metadata to the transparency log.
    /// </summary>
    /// <param name="entry">The entry to submit.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The log entry with inclusion proof and signed checkpoint.</returns>
    Task<TransparencyLogEntry> SubmitEntryAsync(
        RekorEntry entry,
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
