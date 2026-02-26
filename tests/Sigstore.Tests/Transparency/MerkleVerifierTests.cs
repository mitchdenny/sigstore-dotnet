using System.Security.Cryptography;
using Sigstore.Transparency;

namespace Sigstore.Tests.Transparency;

public class MerkleVerifierTests
{
    private static byte[] HashLeaf(byte[] data)
    {
        var buffer = new byte[1 + data.Length];
        buffer[0] = 0x00;
        data.CopyTo(buffer, 1);
        return SHA256.HashData(buffer);
    }

    private static byte[] HashChildren(byte[] left, byte[] right)
    {
        var buffer = new byte[1 + 32 + 32];
        buffer[0] = 0x01;
        left.CopyTo(buffer, 1);
        right.CopyTo(buffer, 33);
        return SHA256.HashData(buffer);
    }

    [Fact]
    public void VerifyInclusionProof_SingleLeafTree_EmptyProof()
    {
        // Tree with one leaf: leaf IS the root
        var leafData = "hello"u8.ToArray();
        var leafHash = HashLeaf(leafData);

        var result = MerkleVerifier.VerifyInclusionProof(
            leafHash, leafIndex: 0, treeSize: 1,
            proofHashes: Array.Empty<byte[]>(),
            expectedRootHash: leafHash);

        Assert.True(result);
    }

    [Fact]
    public void VerifyInclusionProof_TwoLeafTree_VerifyLeft()
    {
        // Tree: root = H(leaf0 || leaf1)
        var leaf0 = HashLeaf("a"u8.ToArray());
        var leaf1 = HashLeaf("b"u8.ToArray());
        var root = HashChildren(leaf0, leaf1);

        // Prove leaf0 (index 0): proof is [leaf1]
        var result = MerkleVerifier.VerifyInclusionProof(
            leaf0, leafIndex: 0, treeSize: 2,
            proofHashes: new[] { leaf1 },
            expectedRootHash: root);

        Assert.True(result);
    }

    [Fact]
    public void VerifyInclusionProof_TwoLeafTree_VerifyRight()
    {
        var leaf0 = HashLeaf("a"u8.ToArray());
        var leaf1 = HashLeaf("b"u8.ToArray());
        var root = HashChildren(leaf0, leaf1);

        // Prove leaf1 (index 1): proof is [leaf0]
        var result = MerkleVerifier.VerifyInclusionProof(
            leaf1, leafIndex: 1, treeSize: 2,
            proofHashes: new[] { leaf0 },
            expectedRootHash: root);

        Assert.True(result);
    }

    [Fact]
    public void VerifyInclusionProof_FourLeafTree()
    {
        //       root
        //      /    \
        //    n01     n23
        //   / \     / \
        //  l0  l1  l2  l3
        var l0 = HashLeaf("a"u8.ToArray());
        var l1 = HashLeaf("b"u8.ToArray());
        var l2 = HashLeaf("c"u8.ToArray());
        var l3 = HashLeaf("d"u8.ToArray());
        var n01 = HashChildren(l0, l1);
        var n23 = HashChildren(l2, l3);
        var root = HashChildren(n01, n23);

        // Prove l2 (index 2): proof is [l3, n01]
        // Step 1: index=2, size=4 -> even, proof on right: H(l2 || l3) = n23
        // Step 2: index=1, size=2 -> odd, proof on left: H(n01 || n23) = root
        var result = MerkleVerifier.VerifyInclusionProof(
            l2, leafIndex: 2, treeSize: 4,
            proofHashes: new[] { l3, n01 },
            expectedRootHash: root);

        Assert.True(result);
    }

    [Fact]
    public void VerifyInclusionProof_WrongRootHash_ReturnsFalse()
    {
        var leaf0 = HashLeaf("a"u8.ToArray());
        var leaf1 = HashLeaf("b"u8.ToArray());
        var root = HashChildren(leaf0, leaf1);
        var wrongRoot = new byte[32]; // all zeros

        var result = MerkleVerifier.VerifyInclusionProof(
            leaf0, leafIndex: 0, treeSize: 2,
            proofHashes: new[] { leaf1 },
            expectedRootHash: wrongRoot);

        Assert.False(result);
    }

    [Fact]
    public void VerifyInclusionProof_TamperedProofHash_ReturnsFalse()
    {
        var leaf0 = HashLeaf("a"u8.ToArray());
        var leaf1 = HashLeaf("b"u8.ToArray());
        var root = HashChildren(leaf0, leaf1);

        var tamperedProof = new byte[32];
        Array.Fill(tamperedProof, (byte)0xFF);

        var result = MerkleVerifier.VerifyInclusionProof(
            leaf0, leafIndex: 0, treeSize: 2,
            proofHashes: new[] { tamperedProof },
            expectedRootHash: root);

        Assert.False(result);
    }

    [Fact]
    public void VerifyInclusionProof_InvalidIndex_ReturnsFalse()
    {
        var leafHash = HashLeaf("a"u8.ToArray());

        var result = MerkleVerifier.VerifyInclusionProof(
            leafHash, leafIndex: -1, treeSize: 1,
            proofHashes: Array.Empty<byte[]>(),
            expectedRootHash: leafHash);

        Assert.False(result);
    }

    [Fact]
    public void VerifyInclusionProof_IndexOutOfRange_ReturnsFalse()
    {
        var leafHash = HashLeaf("a"u8.ToArray());

        var result = MerkleVerifier.VerifyInclusionProof(
            leafHash, leafIndex: 5, treeSize: 3,
            proofHashes: Array.Empty<byte[]>(),
            expectedRootHash: leafHash);

        Assert.False(result);
    }

    [Fact]
    public void VerifyInclusionProof_ThreeLeafTree()
    {
        //       root
        //      /    \
        //    n01     l2  (l2 promoted since it's the last node at that level)
        //   / \
        //  l0  l1
        var l0 = HashLeaf("a"u8.ToArray());
        var l1 = HashLeaf("b"u8.ToArray());
        var l2 = HashLeaf("c"u8.ToArray());
        var n01 = HashChildren(l0, l1);
        var root = HashChildren(n01, l2);

        // Prove l0 (index 0, size 3): proof is [l1, l2]
        var result = MerkleVerifier.VerifyInclusionProof(
            l0, leafIndex: 0, treeSize: 3,
            proofHashes: new[] { l1, l2 },
            expectedRootHash: root);

        Assert.True(result);

        // Prove l2 (index 2, size 3): proof is [n01]
        // index=2, size=3 -> index == size-1, proof on left: H(n01 || l2) = root
        result = MerkleVerifier.VerifyInclusionProof(
            l2, leafIndex: 2, treeSize: 3,
            proofHashes: new[] { n01 },
            expectedRootHash: root);

        Assert.True(result);
    }
}
