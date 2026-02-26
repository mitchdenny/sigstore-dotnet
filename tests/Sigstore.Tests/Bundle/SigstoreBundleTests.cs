using Sigstore.Common;

namespace Sigstore.Tests.Bundle;

public class SigstoreBundleTests
{
    [Fact]
    public void DefaultMediaType_IsV03()
    {
        var bundle = new SigstoreBundle();

        Assert.Equal("application/vnd.dev.sigstore.bundle.v0.3+json", bundle.MediaType);
    }

    [Fact]
    public void NewBundle_HasNullOptionalProperties()
    {
        var bundle = new SigstoreBundle();

        Assert.Null(bundle.VerificationMaterial);
        Assert.Null(bundle.MessageSignature);
        Assert.Null(bundle.DsseEnvelope);
    }

    [Fact]
    public void VerificationMaterial_DefaultsToEmptyCollections()
    {
        var material = new VerificationMaterial();

        Assert.Empty(material.TlogEntries);
        Assert.Empty(material.Rfc3161Timestamps);
        Assert.Null(material.Certificate);
        Assert.Null(material.CertificateChain);
        Assert.Null(material.PublicKeyHint);
    }

    [Fact]
    public void MessageSignature_DefaultsToEmptySignature()
    {
        var sig = new MessageSignature();

        Assert.Empty(sig.Signature);
        Assert.Null(sig.MessageDigest);
    }

    [Fact]
    public void HashOutput_SetsAlgorithmAndDigest()
    {
        var hash = new HashOutput
        {
            Algorithm = HashAlgorithmType.Sha2_256,
            Digest = new byte[] { 1, 2, 3 }
        };

        Assert.Equal(HashAlgorithmType.Sha2_256, hash.Algorithm);
        Assert.Equal(new byte[] { 1, 2, 3 }, hash.Digest);
    }

    [Fact]
    public void TransparencyLogEntry_DefaultsToEmptyCollections()
    {
        var entry = new TransparencyLogEntry();

        Assert.Empty(entry.LogId);
        Assert.Null(entry.Body);
        Assert.Null(entry.InclusionProof);
        Assert.Null(entry.InclusionPromise);
    }

    [Fact]
    public void InclusionProof_DefaultsToEmptyCollections()
    {
        var proof = new InclusionProof();

        Assert.Empty(proof.RootHash);
        Assert.Empty(proof.Hashes);
        Assert.Null(proof.Checkpoint);
    }

    [Fact]
    public void DsseEnvelope_DefaultsToEmptyCollections()
    {
        var envelope = new DsseEnvelope();

        Assert.Equal("", envelope.PayloadType);
        Assert.Empty(envelope.Payload);
        Assert.Empty(envelope.Signatures);
    }

    [Fact]
    public void HashAlgorithmType_HasExpectedValues()
    {
        Assert.Equal(0, (int)HashAlgorithmType.Unspecified);
        Assert.Equal(1, (int)HashAlgorithmType.Sha2_256);
        Assert.Equal(2, (int)HashAlgorithmType.Sha2_384);
        Assert.Equal(3, (int)HashAlgorithmType.Sha2_512);
        Assert.Equal(4, (int)HashAlgorithmType.Sha3_256);
        Assert.Equal(5, (int)HashAlgorithmType.Sha3_384);
    }
}
