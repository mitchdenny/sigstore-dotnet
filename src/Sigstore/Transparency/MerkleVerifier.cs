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
        if (leafIndex < 0 || leafIndex >= treeSize)
            return false;

        if (treeSize == 1 && proofHashes.Count == 0)
            return leafHash.SequenceEqual(expectedRootHash);

        long index = leafIndex;
        long size = treeSize;
        Span<byte> current = stackalloc byte[32];
        leafHash.CopyTo(current);

        for (int i = 0; i < proofHashes.Count; i++)
        {
            var proof = proofHashes[i].AsSpan();
            if (index % 2 == 1 || index == size - 1)
            {
                // proof goes on the left
                current = HashChildren(proof, current);
            }
            else
            {
                // proof goes on the right
                current = HashChildren(current, proof);
            }

            index /= 2;
            size = (size + 1) / 2;
        }

        return current.SequenceEqual(expectedRootHash);
    }

    internal static byte[] HashChildren(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        Span<byte> buffer = stackalloc byte[1 + 32 + 32];
        buffer[0] = 0x01;
        left.CopyTo(buffer.Slice(1));
        right.CopyTo(buffer.Slice(33));
        return System.Security.Cryptography.SHA256.HashData(buffer);
    }

    internal static byte[] HashLeaf(ReadOnlySpan<byte> data)
    {
        Span<byte> buffer = stackalloc byte[1 + data.Length];
        buffer[0] = 0x00;
        data.CopyTo(buffer.Slice(1));
        return System.Security.Cryptography.SHA256.HashData(buffer);
    }
}
