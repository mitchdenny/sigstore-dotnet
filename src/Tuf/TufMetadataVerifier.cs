using System.Security.Cryptography;
using System.Text;
using Tuf.Metadata;

namespace Tuf;

/// <summary>
/// Verifies cryptographic signatures on TUF metadata.
/// </summary>
public static class TufMetadataVerifier
{
    /// <summary>
    /// Verifies that the signed metadata meets the threshold requirement for the given role.
    /// </summary>
    /// <param name="signatures">The signatures from the metadata envelope.</param>
    /// <param name="signedBytes">The canonical JSON bytes of the "signed" portion.</param>
    /// <param name="role">The role definition containing authorized key IDs and threshold.</param>
    /// <param name="keys">The key definitions, keyed by key ID.</param>
    /// <returns>True if the threshold is met, false otherwise.</returns>
    public static bool VerifyThreshold(
        IReadOnlyList<TufSignature> signatures,
        byte[] signedBytes,
        TufRole role,
        IReadOnlyDictionary<string, TufKey> keys)
    {
        if (role.Threshold <= 0)
            return false;

        var validKeyIds = new HashSet<string>();

        foreach (var sig in signatures)
        {
            // Only consider signatures from keys authorized for this role
            if (!role.KeyIds.Contains(sig.KeyId))
                continue;

            // Don't count the same key twice
            if (validKeyIds.Contains(sig.KeyId))
                continue;

            // Skip empty signatures
            if (string.IsNullOrEmpty(sig.Sig))
                continue;

            if (!keys.TryGetValue(sig.KeyId, out var key))
                continue;

            if (VerifySignature(signedBytes, sig.Sig, key))
            {
                validKeyIds.Add(sig.KeyId);
                if (validKeyIds.Count >= role.Threshold)
                    return true;
            }
        }

        return validKeyIds.Count >= role.Threshold;
    }

    /// <summary>
    /// Verifies a single signature against the signed data using the provided key.
    /// </summary>
    internal static bool VerifySignature(byte[] signedBytes, string hexSig, TufKey key)
    {
        try
        {
            var sigBytes = Convert.FromHexString(hexSig);
            var scheme = key.Scheme.ToLowerInvariant();
            var keyType = key.KeyType.ToLowerInvariant();

            if (!key.KeyVal.TryGetValue("public", out var publicKeyPem))
                return false;

            return scheme switch
            {
                "ecdsa-sha2-nistp256" => VerifyEcdsa(signedBytes, sigBytes, publicKeyPem, HashAlgorithmName.SHA256),
                "ecdsa-sha2-nistp384" => VerifyEcdsa(signedBytes, sigBytes, publicKeyPem, HashAlgorithmName.SHA384),
                "ed25519" => VerifyEd25519(signedBytes, sigBytes, publicKeyPem),
                "rsassa-pss-sha256" => VerifyRsaPss(signedBytes, sigBytes, publicKeyPem, HashAlgorithmName.SHA256),
                "rsassa-pss-sha384" => VerifyRsaPss(signedBytes, sigBytes, publicKeyPem, HashAlgorithmName.SHA384),
                "rsassa-pss-sha512" => VerifyRsaPss(signedBytes, sigBytes, publicKeyPem, HashAlgorithmName.SHA512),
                _ when keyType == "ecdsa" => VerifyEcdsa(signedBytes, sigBytes, publicKeyPem, HashAlgorithmName.SHA256),
                _ when keyType == "ed25519" => VerifyEd25519(signedBytes, sigBytes, publicKeyPem),
                _ when keyType == "rsa" => VerifyRsaPss(signedBytes, sigBytes, publicKeyPem, HashAlgorithmName.SHA256),
                _ => false
            };
        }
        catch
        {
            return false;
        }
    }

    private static bool VerifyEcdsa(byte[] data, byte[] signature, string pem, HashAlgorithmName hashAlgorithm)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(pem);
        return ecdsa.VerifyData(data, signature, hashAlgorithm, DSASignatureFormat.Rfc3279DerSequence);
    }

    private static bool VerifyEd25519(byte[] data, byte[] signature, string pem)
    {
        // .NET 10 doesn't have built-in Ed25519 via ImportFromPem.
        // Use NSec.Cryptography for Ed25519 verification.
        var pemBytes = Encoding.ASCII.GetBytes(pem);
        var derBytes = ExtractDerFromPem(pemBytes);

        // Ed25519 SPKI DER: 30 2a 30 05 06 03 2b 65 70 03 21 00 <32 bytes>
        // The actual public key is the last 32 bytes
        if (derBytes.Length < 44 || signature.Length != 64)
            return false;

        var publicKeyRaw = derBytes[^32..];
        var algorithm = NSec.Cryptography.SignatureAlgorithm.Ed25519;
        var publicKey = NSec.Cryptography.PublicKey.Import(algorithm, publicKeyRaw,
            NSec.Cryptography.KeyBlobFormat.RawPublicKey);

        return algorithm.Verify(publicKey, data, signature);
    }

    private static bool VerifyRsaPss(byte[] data, byte[] signature, string pem, HashAlgorithmName hashAlgorithm)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return rsa.VerifyData(data, signature, hashAlgorithm, RSASignaturePadding.Pss);
    }

    private static byte[] ExtractDerFromPem(byte[] pem)
    {
        var pemString = Encoding.ASCII.GetString(pem);
        var lines = pemString.Split('\n')
            .Where(l => !l.StartsWith("-----") && !string.IsNullOrWhiteSpace(l))
            .Select(l => l.Trim());
        var base64 = string.Join("", lines);
        return Convert.FromBase64String(base64);
    }
}
