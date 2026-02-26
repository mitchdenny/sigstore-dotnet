namespace Sigstore.Transparency;

/// <summary>
/// Pure computation for verifying signed checkpoints from transparency logs.
/// No I/O — operates entirely on in-memory data.
/// </summary>
public static class CheckpointVerifier
{
    /// <summary>
    /// Verifies a signed checkpoint against the trusted root.
    /// </summary>
    /// <param name="checkpoint">The checkpoint text (note format).</param>
    /// <param name="logPublicKey">The public key of the transparency log.</param>
    /// <param name="expectedKeyId">The expected checkpoint key ID.</param>
    /// <returns>The parsed checkpoint data if valid, null otherwise.</returns>
    public static CheckpointData? VerifyCheckpoint(
        string checkpoint,
        ReadOnlySpan<byte> logPublicKey,
        ReadOnlySpan<byte> expectedKeyId)
    {
        // TODO: Implement signed note / checkpoint verification per C2SP spec
        throw new NotImplementedException();
    }
}

/// <summary>
/// Parsed data from a verified transparency log checkpoint.
/// </summary>
public class CheckpointData
{
    /// <summary>
    /// The log origin (base URL).
    /// </summary>
    public required string Origin { get; init; }

    /// <summary>
    /// The tree size at checkpoint time.
    /// </summary>
    public required long TreeSize { get; init; }

    /// <summary>
    /// The root hash of the Merkle tree at checkpoint time.
    /// </summary>
    public required byte[] RootHash { get; init; }
}
