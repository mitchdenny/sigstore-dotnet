using System.Text.Json;
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

    // --- Serialization / Deserialization tests ---

    // A realistic v0.1 bundle with certificate chain, tlog entry, and message signature
    private const string V01BundleJson = """
        {
          "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
          "verificationMaterial": {
            "x509CertificateChain": {
              "certificates": [
                {"rawBytes": "AQID"}
              ]
            },
            "tlogEntries": [
              {
                "logIndex": "27246492",
                "logId": {"keyId": "BAUG"},
                "kindVersion": {"kind": "hashedrekord", "version": "0.0.1"},
                "integratedTime": "1689177396",
                "inclusionPromise": {"signedEntryTimestamp": "BwgJ"},
                "inclusionProof": {
                  "logIndex": "23083061",
                  "rootHash": "CgsM",
                  "treeSize": "23083062",
                  "hashes": ["DQ4P"],
                  "checkpoint": {"envelope": "rekor.sigstore.dev - 12345"}
                },
                "canonicalizedBody": "EBES"
              }
            ]
          },
          "messageSignature": {
            "messageDigest": {
              "algorithm": "SHA2_256",
              "digest": "FBUWFxgZ"
            },
            "signature": "GhscHR4f"
          }
        }
        """;

    [Fact]
    public void Deserialize_V01Bundle_ParsesCorrectly()
    {
        var bundle = SigstoreBundle.Deserialize(V01BundleJson);

        Assert.Equal("application/vnd.dev.sigstore.bundle+json;version=0.1", bundle.MediaType);
        Assert.NotNull(bundle.VerificationMaterial);
        Assert.NotNull(bundle.MessageSignature);
        Assert.Null(bundle.DsseEnvelope);

        // Certificate chain
        Assert.NotNull(bundle.VerificationMaterial.CertificateChain);
        Assert.Single(bundle.VerificationMaterial.CertificateChain);
        Assert.Equal(new byte[] { 1, 2, 3 }, bundle.VerificationMaterial.CertificateChain[0]);

        // Tlog entry
        Assert.Single(bundle.VerificationMaterial.TlogEntries);
        var entry = bundle.VerificationMaterial.TlogEntries[0];
        Assert.Equal(27246492L, entry.LogIndex);
        Assert.Equal(new byte[] { 4, 5, 6 }, entry.LogId);
        Assert.Equal(1689177396L, entry.IntegratedTime);
        Assert.Equal("EBES", entry.Body);
        Assert.NotNull(entry.InclusionPromise);
        Assert.Equal(new byte[] { 7, 8, 9 }, entry.InclusionPromise);

        // Inclusion proof
        Assert.NotNull(entry.InclusionProof);
        Assert.Equal(23083061L, entry.InclusionProof.LogIndex);
        Assert.Equal(23083062L, entry.InclusionProof.TreeSize);
        Assert.Equal(new byte[] { 10, 11, 12 }, entry.InclusionProof.RootHash);
        Assert.Single(entry.InclusionProof.Hashes);
        Assert.Equal(new byte[] { 13, 14, 15 }, entry.InclusionProof.Hashes[0]);
        Assert.Equal("rekor.sigstore.dev - 12345", entry.InclusionProof.Checkpoint);

        // Message signature
        Assert.Equal(HashAlgorithmType.Sha2_256, bundle.MessageSignature.MessageDigest!.Algorithm);
        Assert.Equal(new byte[] { 20, 21, 22, 23, 24, 25 }, bundle.MessageSignature.MessageDigest.Digest);
        Assert.Equal(new byte[] { 26, 27, 28, 29, 30, 31 }, bundle.MessageSignature.Signature);
    }

    [Fact]
    public void Deserialize_V03BundleWithCertificate_ParsesCorrectly()
    {
        var json = """
            {
              "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
              "verificationMaterial": {
                "certificate": {"rawBytes": "AQID"},
                "tlogEntries": [],
                "timestampVerificationData": {
                  "rfc3161Timestamps": [{"signedTimestamp": "BAUG"}]
                }
              },
              "messageSignature": {
                "messageDigest": {"algorithm": "SHA2_256", "digest": "BwgJ"},
                "signature": "CgsM"
              }
            }
            """;

        var bundle = SigstoreBundle.Deserialize(json);

        Assert.Equal("application/vnd.dev.sigstore.bundle.v0.3+json", bundle.MediaType);
        Assert.NotNull(bundle.VerificationMaterial);
        Assert.Equal(new byte[] { 1, 2, 3 }, bundle.VerificationMaterial.Certificate);
        Assert.Null(bundle.VerificationMaterial.CertificateChain);
        Assert.Single(bundle.VerificationMaterial.Rfc3161Timestamps);
        Assert.Equal(new byte[] { 4, 5, 6 }, bundle.VerificationMaterial.Rfc3161Timestamps[0]);
    }

    [Fact]
    public void Deserialize_DsseEnvelope_ParsesCorrectly()
    {
        var json = """
            {
              "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
              "verificationMaterial": {
                "certificate": {"rawBytes": "AQID"},
                "tlogEntries": []
              },
              "dsseEnvelope": {
                "payloadType": "application/vnd.in-toto+json",
                "payload": "BAUG",
                "signatures": [{"keyid": "", "sig": "BwgJ"}]
              }
            }
            """;

        var bundle = SigstoreBundle.Deserialize(json);

        Assert.NotNull(bundle.DsseEnvelope);
        Assert.Null(bundle.MessageSignature);
        Assert.Equal("application/vnd.in-toto+json", bundle.DsseEnvelope.PayloadType);
        Assert.Equal(new byte[] { 4, 5, 6 }, bundle.DsseEnvelope.Payload);
        Assert.Single(bundle.DsseEnvelope.Signatures);
        Assert.Equal(new byte[] { 7, 8, 9 }, bundle.DsseEnvelope.Signatures[0].Sig);
    }

    [Fact]
    public void Deserialize_Stream_ParsesCorrectly()
    {
        using var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(V01BundleJson));
        var bundle = SigstoreBundle.Deserialize(stream);

        Assert.Equal("application/vnd.dev.sigstore.bundle+json;version=0.1", bundle.MediaType);
        Assert.NotNull(bundle.VerificationMaterial);
        Assert.Single(bundle.VerificationMaterial.TlogEntries);
    }

    [Fact]
    public void Serialize_ProducesLowerCamelCaseKeys()
    {
        var bundle = SigstoreBundle.Deserialize(V01BundleJson);
        var json = bundle.Serialize();

        Assert.Contains("\"mediaType\"", json);
        Assert.Contains("\"verificationMaterial\"", json);
        Assert.Contains("\"messageSignature\"", json);
        Assert.Contains("\"messageDigest\"", json);
        Assert.DoesNotContain("\"MediaType\"", json);
        Assert.DoesNotContain("\"VerificationMaterial\"", json);
    }

    [Fact]
    public void Serialize_NumericFieldsAsStrings()
    {
        var bundle = SigstoreBundle.Deserialize(V01BundleJson);
        var json = bundle.Serialize();

        // logIndex, integratedTime, treeSize should be strings
        Assert.Contains("\"27246492\"", json);
        Assert.Contains("\"1689177396\"", json);
        Assert.Contains("\"23083062\"", json);
    }

    [Fact]
    public void Serialize_Base64EncodesBytes()
    {
        var bundle = SigstoreBundle.Deserialize(V01BundleJson);
        var json = bundle.Serialize();

        // Certificate rawBytes should be base64 encoded
        Assert.Contains("AQID", json);  // base64 of [1,2,3]
    }

    [Fact]
    public void RoundTrip_V01Bundle_PreservesData()
    {
        var bundle1 = SigstoreBundle.Deserialize(V01BundleJson);
        var json = bundle1.Serialize();
        var bundle2 = SigstoreBundle.Deserialize(json);

        Assert.Equal(bundle1.MediaType, bundle2.MediaType);

        // Verification material
        Assert.NotNull(bundle2.VerificationMaterial);
        Assert.Equal(
            bundle1.VerificationMaterial!.CertificateChain![0],
            bundle2.VerificationMaterial.CertificateChain![0]);

        // Tlog entry
        var e1 = bundle1.VerificationMaterial.TlogEntries[0];
        var e2 = bundle2.VerificationMaterial.TlogEntries[0];
        Assert.Equal(e1.LogIndex, e2.LogIndex);
        Assert.Equal(e1.LogId, e2.LogId);
        Assert.Equal(e1.IntegratedTime, e2.IntegratedTime);
        Assert.Equal(e1.Body, e2.Body);
        Assert.Equal(e1.InclusionPromise, e2.InclusionPromise);

        // Inclusion proof
        Assert.Equal(e1.InclusionProof!.LogIndex, e2.InclusionProof!.LogIndex);
        Assert.Equal(e1.InclusionProof.TreeSize, e2.InclusionProof.TreeSize);
        Assert.Equal(e1.InclusionProof.RootHash, e2.InclusionProof.RootHash);
        Assert.Equal(e1.InclusionProof.Hashes[0], e2.InclusionProof.Hashes[0]);
        Assert.Equal(e1.InclusionProof.Checkpoint, e2.InclusionProof.Checkpoint);

        // Message signature
        Assert.Equal(bundle1.MessageSignature!.Signature, bundle2.MessageSignature!.Signature);
        Assert.Equal(
            bundle1.MessageSignature.MessageDigest!.Algorithm,
            bundle2.MessageSignature.MessageDigest!.Algorithm);
        Assert.Equal(
            bundle1.MessageSignature.MessageDigest.Digest,
            bundle2.MessageSignature.MessageDigest.Digest);
    }

    [Fact]
    public void RoundTrip_DsseEnvelope_PreservesData()
    {
        var json = """
            {
              "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
              "verificationMaterial": {
                "certificate": {"rawBytes": "AQID"},
                "tlogEntries": []
              },
              "dsseEnvelope": {
                "payloadType": "application/vnd.in-toto+json",
                "payload": "BAUG",
                "signatures": [{"keyid": "mykey", "sig": "BwgJ"}]
              }
            }
            """;

        var bundle1 = SigstoreBundle.Deserialize(json);
        var serialized = bundle1.Serialize();
        var bundle2 = SigstoreBundle.Deserialize(serialized);

        Assert.NotNull(bundle2.DsseEnvelope);
        Assert.Equal(bundle1.DsseEnvelope!.PayloadType, bundle2.DsseEnvelope.PayloadType);
        Assert.Equal(bundle1.DsseEnvelope.Payload, bundle2.DsseEnvelope.Payload);
        Assert.Equal(bundle1.DsseEnvelope.Signatures[0].KeyId, bundle2.DsseEnvelope.Signatures[0].KeyId);
        Assert.Equal(bundle1.DsseEnvelope.Signatures[0].Sig, bundle2.DsseEnvelope.Signatures[0].Sig);
    }

    [Fact]
    public void Deserialize_NullOptionalFields_HandlesGracefully()
    {
        var json = """
            {
              "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
              "verificationMaterial": {
                "tlogEntries": []
              },
              "messageSignature": {
                "signature": "AQID"
              }
            }
            """;

        var bundle = SigstoreBundle.Deserialize(json);

        Assert.NotNull(bundle.VerificationMaterial);
        Assert.Null(bundle.VerificationMaterial.Certificate);
        Assert.Null(bundle.VerificationMaterial.CertificateChain);
        Assert.Null(bundle.VerificationMaterial.PublicKeyHint);
        Assert.Empty(bundle.VerificationMaterial.TlogEntries);
        Assert.Empty(bundle.VerificationMaterial.Rfc3161Timestamps);
        Assert.Null(bundle.MessageSignature!.MessageDigest);
    }

    [Fact]
    public void Deserialize_EmptyCollections_HandlesGracefully()
    {
        var json = """
            {
              "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
              "verificationMaterial": {
                "tlogEntries": [],
                "timestampVerificationData": {
                  "rfc3161Timestamps": []
                }
              }
            }
            """;

        var bundle = SigstoreBundle.Deserialize(json);

        Assert.Empty(bundle.VerificationMaterial!.TlogEntries);
        Assert.Empty(bundle.VerificationMaterial.Rfc3161Timestamps);
    }

    [Fact]
    public void Serialize_OmitsNullFields()
    {
        var bundle = new SigstoreBundle
        {
            VerificationMaterial = new VerificationMaterial()
        };

        var json = bundle.Serialize();

        Assert.DoesNotContain("messageSignature", json);
        Assert.DoesNotContain("dsseEnvelope", json);
        Assert.DoesNotContain("certificate", json);
        Assert.DoesNotContain("x509CertificateChain", json);
    }

    [Fact]
    public void Deserialize_PublicKeyHint_ParsesCorrectly()
    {
        var json = """
            {
              "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
              "verificationMaterial": {
                "publicKey": {"hint": "my-key-id"},
                "tlogEntries": []
              },
              "messageSignature": {
                "signature": "AQID"
              }
            }
            """;

        var bundle = SigstoreBundle.Deserialize(json);

        Assert.Equal("my-key-id", bundle.VerificationMaterial!.PublicKeyHint);
    }

    [Fact]
    public void Deserialize_InvalidJson_Throws()
    {
        Assert.Throws<JsonException>(() => SigstoreBundle.Deserialize("not json"));
    }

    [Fact]
    public void Serialize_HashAlgorithms_UseStringValues()
    {
        var bundle = new SigstoreBundle
        {
            MessageSignature = new MessageSignature
            {
                MessageDigest = new HashOutput
                {
                    Algorithm = HashAlgorithmType.Sha2_384,
                    Digest = [1, 2, 3]
                },
                Signature = [4, 5, 6]
            }
        };

        var json = bundle.Serialize();

        Assert.Contains("SHA2_384", json);
    }
}
