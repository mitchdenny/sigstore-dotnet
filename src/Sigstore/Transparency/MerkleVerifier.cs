namespace Sigstore.Transparency;

/// <summary>
/// Pure computation for verifying Merkle tree inclusion proofs.
/// No I/O — operates entirely on in-memory data.
/// </summary>
public static class MerkleVerifier
{
    /// <summary>
    /// Verifies a Merkle tree inclusion proof.
    /// </summary>
    /// <param name="leafHash">The hash of the leaf entry.</param>
    /// <param name="leafIndex">The index of the leaf in the tree.</param>
    /// <param name="treeSize">The total size of the tree.</param>
    /// <param name="proofHashes">The hashes along the path from the leaf to the root.</param>
    /// <param name="expectedRootHash">The expected root hash.</param>
    /// <returns>True if the inclusion proof is valid.</returns>
    public static bool VerifyInclusionProof(
        ReadOnlySpan<byte> leafHash,
        long leafIndex,
        long treeSize,
        IReadOnlyList<byte[]> proofHashes,
        ReadOnlySpan<byte> expectedRootHash)
    {
        // TODO: Implement RFC 6962 §2.1.1 Merkle inclusion proof verification
        throw new NotImplementedException();
    }
}
