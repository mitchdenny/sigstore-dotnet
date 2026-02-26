using System.Security.Cryptography;
using System.Text;

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
        // Split into note body and signature lines at the blank line
        var blankIdx = checkpoint.IndexOf("\n\n", StringComparison.Ordinal);
        if (blankIdx < 0)
            return null;

        var noteBody = checkpoint.Substring(0, blankIdx + 1); // include the trailing newline
        var signatureSection = checkpoint.Substring(blankIdx + 2);

        // Parse the note body: line 1 = origin, line 2 = tree size, line 3 = base64 root hash
        var bodyLines = noteBody.Split('\n');
        if (bodyLines.Length < 3)
            return null;

        var origin = bodyLines[0];
        if (!long.TryParse(bodyLines[1], out var treeSize))
            return null;

        byte[] rootHash;
        try
        {
            rootHash = Convert.FromBase64String(bodyLines[2]);
        }
        catch
        {
            return null;
        }

        // Parse signature lines (start with "— ")
        var sigLines = signatureSection.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        bool signatureVerified = false;

        var noteBodyBytes = Encoding.UTF8.GetBytes(noteBody);

        foreach (var sigLine in sigLines)
        {
            if (!sigLine.StartsWith("\u2014 ", StringComparison.Ordinal))
                continue;

            // Format: "— <name> <base64(keyId + signature)>"
            var parts = sigLine.Substring(2).Split(' ', 2);
            if (parts.Length < 2)
                continue;

            byte[] sigData;
            try
            {
                sigData = Convert.FromBase64String(parts[1]);
            }
            catch
            {
                continue;
            }

            if (sigData.Length < 4)
                continue;

            // First 4 bytes are the key ID
            var keyId = sigData.AsSpan(0, 4);
            var signature = sigData.AsSpan(4);

            if (!keyId.SequenceEqual(expectedKeyId))
                continue;

            // Try Ed25519 (64-byte signatures, 32 or 44 byte public key)
            if (signature.Length == 64 && (logPublicKey.Length == 32 || logPublicKey.Length == 44))
            {
                try
                {
                    signatureVerified = VerifyEd25519(logPublicKey, noteBodyBytes, signature);
                }
                catch
                {
                    // Fall through
                }
            }

            // Try ECDSA
            if (!signatureVerified)
            {
                try
                {
                    using var ecdsa = ECDsa.Create();
                    ecdsa.ImportSubjectPublicKeyInfo(logPublicKey, out _);
                    signatureVerified = ecdsa.VerifyData(noteBodyBytes, signature,
                        HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
                }
                catch
                {
                    // Not an ECDSA key or verification failed
                }
            }

            if (signatureVerified)
                break;
        }

        if (!signatureVerified)
            return null;

        return new CheckpointData
        {
            Origin = origin,
            TreeSize = treeSize,
            RootHash = rootHash
        };
    }

    /// <summary>
    /// Parses checkpoint data without verifying signatures.
    /// </summary>
    public static CheckpointData? ParseCheckpoint(string checkpoint)
    {
        var blankIdx = checkpoint.IndexOf("\n\n", StringComparison.Ordinal);
        var noteBody = blankIdx >= 0 ? checkpoint.Substring(0, blankIdx + 1) : checkpoint;

        var bodyLines = noteBody.Split('\n');
        if (bodyLines.Length < 3)
            return null;

        var origin = bodyLines[0];
        if (!long.TryParse(bodyLines[1], out var treeSize))
            return null;

        byte[] rootHash;
        try
        {
            rootHash = Convert.FromBase64String(bodyLines[2]);
        }
        catch
        {
            return null;
        }

        return new CheckpointData
        {
            Origin = origin,
            TreeSize = treeSize,
            RootHash = rootHash
        };
    }

    private static bool VerifyEd25519(ReadOnlySpan<byte> publicKey, byte[] message, ReadOnlySpan<byte> signature)
    {
        ReadOnlySpan<byte> rawKey;
        if (publicKey.Length == 44)
        {
            // SPKI format — extract the 32-byte raw key (skip 12-byte header)
            rawKey = publicKey.Slice(12);
        }
        else if (publicKey.Length == 32)
        {
            rawKey = publicKey;
        }
        else
        {
            return false;
        }

        var algorithm = NSec.Cryptography.SignatureAlgorithm.Ed25519;
        var pk = NSec.Cryptography.PublicKey.Import(algorithm, rawKey, NSec.Cryptography.KeyBlobFormat.RawPublicKey);
        return algorithm.Verify(pk, message, signature);
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
