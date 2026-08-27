using Sigstore;

namespace Sigstore.Tests.Transparency;

[TestClass]
public class CheckpointVerifierTests
{
    [TestMethod]
    public void ParseCheckpoint_ValidFormat_ReturnsData()
    {
        var rootHashBytes = new byte[32];
        Array.Fill(rootHashBytes, (byte)0xAB);
        var rootHashB64 = Convert.ToBase64String(rootHashBytes);

        var checkpoint = $"rekor.sigstore.dev\n123456\n{rootHashB64}\n\n\u2014 rekor.sigstore.dev ABCD+signature\n";

        var data = CheckpointVerifier.ParseCheckpoint(checkpoint);

        Assert.IsNotNull(data);
        Assert.AreEqual("rekor.sigstore.dev", data.Origin);
        Assert.AreEqual(123456, data.TreeSize);
        TestSeq.AreEqual(rootHashBytes, data.RootHash);
    }

    [TestMethod]
    public void ParseCheckpoint_MissingTreeSize_ReturnsNull()
    {
        var checkpoint = "rekor.sigstore.dev\nnotanumber\nAAAA\n\n\u2014 sig\n";
        var data = CheckpointVerifier.ParseCheckpoint(checkpoint);
        Assert.IsNull(data);
    }

    [TestMethod]
    public void ParseCheckpoint_TooFewLines_ReturnsNull()
    {
        var checkpoint = "rekor.sigstore.dev\n";
        var data = CheckpointVerifier.ParseCheckpoint(checkpoint);
        Assert.IsNull(data);
    }

    [TestMethod]
    public void ParseCheckpoint_InvalidBase64RootHash_ReturnsNull()
    {
        var checkpoint = "rekor.sigstore.dev\n100\n!!!invalid-base64!!!\n\n\u2014 sig\n";
        var data = CheckpointVerifier.ParseCheckpoint(checkpoint);
        Assert.IsNull(data);
    }

    [TestMethod]
    public void VerifyCheckpoint_InvalidFormat_ReturnsNull()
    {
        var result = CheckpointVerifier.VerifyCheckpoint(
            "not a valid checkpoint",
            ReadOnlySpan<byte>.Empty,
            ReadOnlySpan<byte>.Empty);

        Assert.IsNull(result);
    }

    [TestMethod]
    public void VerifyCheckpoint_NoMatchingKeyId_ReturnsNull()
    {
        var rootHashBytes = new byte[32];
        var rootHashB64 = Convert.ToBase64String(rootHashBytes);
        // Signature line with key ID [0x01, 0x02, 0x03, 0x04] + 64 bytes of signature
        var sigPayload = new byte[4 + 64];
        sigPayload[0] = 0x01; sigPayload[1] = 0x02; sigPayload[2] = 0x03; sigPayload[3] = 0x04;
        var sigB64 = Convert.ToBase64String(sigPayload);

        var checkpoint = $"origin\n100\n{rootHashB64}\n\n\u2014 origin {sigB64}\n";

        // Expected key ID doesn't match
        byte[] expectedKeyId = [0xFF, 0xFF, 0xFF, 0xFF];
        byte[] pubKey = new byte[32];

        var result = CheckpointVerifier.VerifyCheckpoint(
            checkpoint,
            pubKey,
            expectedKeyId);

        Assert.IsNull(result);
    }

    [TestMethod]
    public void VerifyCheckpoint_WithEcdsaSignature_Verifies()
    {
        using var ecdsa = System.Security.Cryptography.ECDsa.Create(
            System.Security.Cryptography.ECCurve.NamedCurves.nistP256);

        var rootHash = new byte[32];
        var rootHashB64 = Convert.ToBase64String(rootHash);
        var noteBody = $"test-origin\n42\n{rootHashB64}\n";
        var noteBodyBytes = System.Text.Encoding.UTF8.GetBytes(noteBody);

        var signature = ecdsa.SignData(noteBodyBytes, System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.DSASignatureFormat.Rfc3279DerSequence);
        var pubKeySpki = ecdsa.ExportSubjectPublicKeyInfo();

        // Build key ID (first 4 bytes of some identifier)
        byte[] keyId = [0xDE, 0xAD, 0xBE, 0xEF];
        var sigPayload = new byte[4 + signature.Length];
        keyId.CopyTo(sigPayload, 0);
        signature.CopyTo(sigPayload, 4);
        var sigB64 = Convert.ToBase64String(sigPayload);

        var checkpoint = $"{noteBody}\n\u2014 test-origin {sigB64}\n";

        var result = CheckpointVerifier.VerifyCheckpoint(
            checkpoint,
            pubKeySpki,
            keyId);

        Assert.IsNotNull(result);
        Assert.AreEqual("test-origin", result.Origin);
        Assert.AreEqual(42, result.TreeSize);
        TestSeq.AreEqual(rootHash, result.RootHash);
    }
}
