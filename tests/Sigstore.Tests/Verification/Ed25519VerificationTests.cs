using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Sigstore;

namespace Sigstore.Tests.Verification;

public class Ed25519VerificationTests
{
    [Fact]
    public void VerifyEd25519Data_ValidSignature_WithRawKey()
    {
        var key = CreateKey();
        var data = "hello ed25519"u8.ToArray();
        var signature = Sign(key, data);
        var rawPublicKey = key.GeneratePublicKey().GetEncoded();

        var result = SigstoreVerifier.VerifyEd25519Data(data, signature, rawPublicKey);

        Assert.True(result);
    }

    [Fact]
    public void VerifyEd25519Data_ValidSignature_WithSpkiKey()
    {
        var key = CreateKey();
        var data = "hello ed25519 spki"u8.ToArray();
        var signature = Sign(key, data);

        // Build a 44-byte SPKI: 12-byte prefix + 32-byte raw key
        var rawKey = key.GeneratePublicKey().GetEncoded();
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
        var key = CreateKey();
        var data = "hello ed25519"u8.ToArray();
        var signature = Sign(key, data);
        var rawPublicKey = key.GeneratePublicKey().GetEncoded();

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
        var signingKey = CreateKey();
        var wrongKey = CreateKey(1);
        var data = "hello ed25519"u8.ToArray();
        var signature = Sign(signingKey, data);
        var wrongPublicKey = wrongKey.GeneratePublicKey().GetEncoded();

        var result = SigstoreVerifier.VerifyEd25519Data(data, signature, wrongPublicKey);

        Assert.False(result);
    }

    [Fact]
    public void VerifyEd25519Data_Rfc8032TestVector_ReturnsTrue()
    {
        var publicKey = Convert.FromHexString(
            "D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A");
        var signature = Convert.FromHexString(
            "E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E06522490155" +
            "5FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B");

        var result = SigstoreVerifier.VerifyEd25519Data([], signature, publicKey);

        Assert.True(result);
    }

    [Fact]
    public void VerifyEd25519Data_InvalidSpkiPrefix_ReturnsFalse()
    {
        var key = CreateKey();
        var data = "hello ed25519 spki"u8.ToArray();
        var signature = Sign(key, data);
        var invalidSpki = new byte[44];
        key.GeneratePublicKey().GetEncoded().CopyTo(invalidSpki, 12);

        var result = SigstoreVerifier.VerifyEd25519Data(data, signature, invalidSpki);

        Assert.False(result);
    }

    private static Ed25519PrivateKeyParameters CreateKey(byte seedValue = 0)
    {
        var seed = new byte[Ed25519PrivateKeyParameters.KeySize];
        seed.AsSpan().Fill(seedValue);
        return new Ed25519PrivateKeyParameters(seed);
    }

    private static byte[] Sign(Ed25519PrivateKeyParameters key, ReadOnlySpan<byte> data)
    {
        var signature = new byte[Ed25519PrivateKeyParameters.SignatureSize];
        key.Sign(Ed25519.Algorithm.Ed25519, null, data, signature);
        return signature;
    }
}
