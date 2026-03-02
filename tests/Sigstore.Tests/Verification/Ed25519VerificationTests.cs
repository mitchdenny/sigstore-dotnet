using NSec.Cryptography;
using Sigstore;

namespace Sigstore.Tests.Verification;

public class Ed25519VerificationTests
{
    [Fact]
    public void VerifyEd25519Data_ValidSignature_WithRawKey()
    {
        var algorithm = SignatureAlgorithm.Ed25519;
        using var key = Key.Create(algorithm);
        var data = "hello ed25519"u8.ToArray();
        var signature = algorithm.Sign(key, data);
        var rawPublicKey = key.Export(KeyBlobFormat.RawPublicKey);

        var result = SigstoreVerifier.VerifyEd25519Data(data, signature, rawPublicKey);

        Assert.True(result);
    }

    [Fact]
    public void VerifyEd25519Data_ValidSignature_WithSpkiKey()
    {
        var algorithm = SignatureAlgorithm.Ed25519;
        using var key = Key.Create(algorithm);
        var data = "hello ed25519 spki"u8.ToArray();
        var signature = algorithm.Sign(key, data);

        // Build a 44-byte SPKI: 12-byte prefix + 32-byte raw key
        var rawKey = key.Export(KeyBlobFormat.RawPublicKey);
        // Ed25519 SPKI prefix (OID 1.3.101.112)
        byte[] spkiPrefix = [0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00];
        var spki = new byte[44];
        spkiPrefix.CopyTo(spki, 0);
        rawKey.CopyTo(spki, 12);

        var result = SigstoreVerifier.VerifyEd25519Data(data, signature, spki);

        Assert.True(result);
    }

    [Fact]
    public void VerifyEd25519Data_InvalidSignature_ReturnsFalse()
    {
        var algorithm = SignatureAlgorithm.Ed25519;
        using var key = Key.Create(algorithm);
        var data = "hello ed25519"u8.ToArray();
        var signature = algorithm.Sign(key, data);
        var rawPublicKey = key.Export(KeyBlobFormat.RawPublicKey);

        // Corrupt the signature
        var badSig = signature.ToArray();
        badSig[0] ^= 0xFF;

        var result = SigstoreVerifier.VerifyEd25519Data(data, badSig, rawPublicKey);

        Assert.False(result);
    }

    [Fact]
    public void VerifyEd25519Data_WrongKeyLength_ReturnsFalse()
    {
        var data = "hello"u8.ToArray();
        var signature = new byte[64];
        var badKey = new byte[20]; // Not 32 or 44

        var result = SigstoreVerifier.VerifyEd25519Data(data, signature, badKey);

        Assert.False(result);
    }

    [Fact]
    public void VerifyEd25519Data_WrongKey_ReturnsFalse()
    {
        var algorithm = SignatureAlgorithm.Ed25519;
        using var signingKey = Key.Create(algorithm);
        using var wrongKey = Key.Create(algorithm);
        var data = "hello ed25519"u8.ToArray();
        var signature = algorithm.Sign(signingKey, data);
        var wrongPublicKey = wrongKey.Export(KeyBlobFormat.RawPublicKey);

        var result = SigstoreVerifier.VerifyEd25519Data(data, signature, wrongPublicKey);

        Assert.False(result);
    }
}
