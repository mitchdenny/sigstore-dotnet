using System.Text.Json;
using Sigstore;

namespace Sigstore.Tests.Bundle;

[TestClass]
public class SigstoreBundleTests
{
    [TestMethod]
    public void DefaultMediaType_IsV03()
    {
        var bundle = new SigstoreBundle();

        Assert.AreEqual("application/vnd.dev.sigstore.bundle.v0.3+json", bundle.MediaType);
    }

    [TestMethod]
    public void NewBundle_HasNullOptionalProperties()
    {
        var bundle = new SigstoreBundle();

        Assert.IsNull(bundle.VerificationMaterial);
        Assert.IsNull(bundle.MessageSignature);
        Assert.IsNull(bundle.DsseEnvelope);
    }

    [TestMethod]
    public void VerificationMaterial_DefaultsToEmptyCollections()
    {
        var material = new VerificationMaterial();

        Assert.IsEmpty(material.TlogEntries);
        Assert.IsEmpty(material.Rfc3161Timestamps);
        Assert.IsNull(material.Certificate);
        Assert.IsNull(material.CertificateChain);
        Assert.IsNull(material.PublicKeyHint);
    }

    [TestMethod]
    public void MessageSignature_DefaultsToEmptySignature()
    {
        var sig = new MessageSignature();

        Assert.IsTrue(sig.Signature.Length == 0);
        Assert.IsNull(sig.MessageDigest);
    }

    [TestMethod]
    public void HashOutput_SetsAlgorithmAndDigest()
    {
        var hash = new HashOutput
        {
            Algorithm = HashAlgorithmType.Sha256,
            Digest = new byte[] { 1, 2, 3 }
        };

        Assert.AreEqual(HashAlgorithmType.Sha256, hash.Algorithm);
        TestSeq.AreEqual(new byte[] { 1, 2, 3 }, hash.Digest.ToArray());
    }

    [TestMethod]
    public void TransparencyLogEntry_DefaultsToEmptyCollections()
    {
        var entry = new TransparencyLogEntry();

        Assert.IsTrue(entry.LogId.Length == 0);
        Assert.IsNull(entry.Body);
        Assert.IsNull(entry.InclusionProof);
        Assert.IsNull(entry.InclusionPromise);
    }

    [TestMethod]
    public void InclusionProof_DefaultsToEmptyCollections()
    {
        var proof = new InclusionProof();

        Assert.IsTrue(proof.RootHash.Length == 0);
        Assert.IsEmpty(proof.Hashes);
        Assert.IsNull(proof.Checkpoint);
    }

    [TestMethod]
    public void DsseEnvelope_DefaultsToEmptyCollections()
    {
        var envelope = new DsseEnvelope();

        Assert.AreEqual("", envelope.PayloadType);
        Assert.IsTrue(envelope.Payload.Length == 0);
        Assert.IsEmpty(envelope.Signatures);
    }

    [TestMethod]
    public void HashAlgorithmType_HasExpectedValues()
    {
        Assert.AreEqual(0, (int)HashAlgorithmType.Unspecified);
        Assert.AreEqual(1, (int)HashAlgorithmType.Sha256);
        Assert.AreEqual(2, (int)HashAlgorithmType.Sha384);
        Assert.AreEqual(3, (int)HashAlgorithmType.Sha512);
        Assert.AreEqual(4, (int)HashAlgorithmType.Sha3256);
        Assert.AreEqual(5, (int)HashAlgorithmType.Sha3384);
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

    [TestMethod]
    public void Deserialize_V01Bundle_ParsesCorrectly()
    {
        var bundle = SigstoreBundle.Deserialize(V01BundleJson);

        Assert.AreEqual("application/vnd.dev.sigstore.bundle+json;version=0.1", bundle.MediaType);
        Assert.IsNotNull(bundle.VerificationMaterial);
        Assert.IsNotNull(bundle.MessageSignature);
        Assert.IsNull(bundle.DsseEnvelope);

        // Certificate chain
        Assert.IsNotNull(bundle.VerificationMaterial.CertificateChain);
        TestSeq.Single(bundle.VerificationMaterial.CertificateChain);
        TestSeq.AreEqual(new byte[] { 1, 2, 3 }, bundle.VerificationMaterial.CertificateChain[0].ToArray());

        // Tlog entry
        TestSeq.Single(bundle.VerificationMaterial.TlogEntries);
        var entry = bundle.VerificationMaterial.TlogEntries[0];
        Assert.AreEqual(27246492L, entry.LogIndex);
        TestSeq.AreEqual(new byte[] { 4, 5, 6 }, entry.LogId.ToArray());
        Assert.AreEqual(1689177396L, entry.IntegratedTime);
        Assert.AreEqual("EBES", entry.Body);
        Assert.IsNotNull(entry.InclusionPromise);
        TestSeq.AreEqual(new byte[] { 7, 8, 9 }, entry.InclusionPromise.Value.ToArray());

        // Inclusion proof
        Assert.IsNotNull(entry.InclusionProof);
        Assert.AreEqual(23083061L, entry.InclusionProof.LogIndex);
        Assert.AreEqual(23083062L, entry.InclusionProof.TreeSize);
        TestSeq.AreEqual(new byte[] { 10, 11, 12 }, entry.InclusionProof.RootHash.ToArray());
        TestSeq.Single(entry.InclusionProof.Hashes);
        TestSeq.AreEqual(new byte[] { 13, 14, 15 }, entry.InclusionProof.Hashes[0].ToArray());
        Assert.AreEqual("rekor.sigstore.dev - 12345", entry.InclusionProof.Checkpoint);

        // Message signature
        Assert.AreEqual(HashAlgorithmType.Sha256, bundle.MessageSignature.MessageDigest!.Algorithm);
        TestSeq.AreEqual(new byte[] { 20, 21, 22, 23, 24, 25 }, bundle.MessageSignature.MessageDigest.Digest.ToArray());
        TestSeq.AreEqual(new byte[] { 26, 27, 28, 29, 30, 31 }, bundle.MessageSignature.Signature.ToArray());
    }

    [TestMethod]
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

        Assert.AreEqual("application/vnd.dev.sigstore.bundle.v0.3+json", bundle.MediaType);
        Assert.IsNotNull(bundle.VerificationMaterial);
        TestSeq.AreEqual(new byte[] { 1, 2, 3 }, bundle.VerificationMaterial.Certificate!.Value.ToArray());
        Assert.IsNull(bundle.VerificationMaterial.CertificateChain);
        TestSeq.Single(bundle.VerificationMaterial.Rfc3161Timestamps);
        TestSeq.AreEqual(new byte[] { 4, 5, 6 }, bundle.VerificationMaterial.Rfc3161Timestamps[0].ToArray());
    }

    [TestMethod]
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

        Assert.IsNotNull(bundle.DsseEnvelope);
        Assert.IsNull(bundle.MessageSignature);
        Assert.AreEqual("application/vnd.in-toto+json", bundle.DsseEnvelope.PayloadType);
        TestSeq.AreEqual(new byte[] { 4, 5, 6 }, bundle.DsseEnvelope.Payload.ToArray());
        TestSeq.Single(bundle.DsseEnvelope.Signatures);
        TestSeq.AreEqual(new byte[] { 7, 8, 9 }, bundle.DsseEnvelope.Signatures[0].Sig.ToArray());
    }

    [TestMethod]
    public void Deserialize_Stream_ParsesCorrectly()
    {
        using var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(V01BundleJson));
        var bundle = SigstoreBundle.Deserialize(stream);

        Assert.AreEqual("application/vnd.dev.sigstore.bundle+json;version=0.1", bundle.MediaType);
        Assert.IsNotNull(bundle.VerificationMaterial);
        TestSeq.Single(bundle.VerificationMaterial.TlogEntries);
    }

    [TestMethod]
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

    [TestMethod]
    public void Serialize_NumericFieldsAsStrings()
    {
        var bundle = SigstoreBundle.Deserialize(V01BundleJson);
        var json = bundle.Serialize();

        // logIndex, integratedTime, treeSize should be strings
        Assert.Contains("\"27246492\"", json);
        Assert.Contains("\"1689177396\"", json);
        Assert.Contains("\"23083062\"", json);
    }

    [TestMethod]
    public void Serialize_Base64EncodesBytes()
    {
        var bundle = SigstoreBundle.Deserialize(V01BundleJson);
        var json = bundle.Serialize();

        // Certificate rawBytes should be base64 encoded
        Assert.Contains("AQID", json);  // base64 of [1,2,3]
    }

    [TestMethod]
    public void RoundTrip_V01Bundle_PreservesData()
    {
        var bundle1 = SigstoreBundle.Deserialize(V01BundleJson);
        var json = bundle1.Serialize();
        var bundle2 = SigstoreBundle.Deserialize(json);

        Assert.AreEqual(bundle1.MediaType, bundle2.MediaType);

        // Verification material
        Assert.IsNotNull(bundle2.VerificationMaterial);
        TestSeq.AreEqual(
            bundle1.VerificationMaterial!.CertificateChain![0].ToArray(),
            bundle2.VerificationMaterial.CertificateChain![0].ToArray());

        // Tlog entry
        var e1 = bundle1.VerificationMaterial.TlogEntries[0];
        var e2 = bundle2.VerificationMaterial.TlogEntries[0];
        Assert.AreEqual(e1.LogIndex, e2.LogIndex);
        TestSeq.AreEqual(e1.LogId.ToArray(), e2.LogId.ToArray());
        Assert.AreEqual(e1.IntegratedTime, e2.IntegratedTime);
        Assert.AreEqual(e1.Body, e2.Body);
        TestSeq.AreEqual(e1.InclusionPromise!.Value.ToArray(), e2.InclusionPromise!.Value.ToArray());

        // Inclusion proof
        Assert.AreEqual(e1.InclusionProof!.LogIndex, e2.InclusionProof!.LogIndex);
        Assert.AreEqual(e1.InclusionProof.TreeSize, e2.InclusionProof.TreeSize);
        TestSeq.AreEqual(e1.InclusionProof.RootHash.ToArray(), e2.InclusionProof.RootHash.ToArray());
        TestSeq.AreEqual(e1.InclusionProof.Hashes[0].ToArray(), e2.InclusionProof.Hashes[0].ToArray());
        Assert.AreEqual(e1.InclusionProof.Checkpoint, e2.InclusionProof.Checkpoint);

        // Message signature
        TestSeq.AreEqual(bundle1.MessageSignature!.Signature.ToArray(), bundle2.MessageSignature!.Signature.ToArray());
        Assert.AreEqual(
            bundle1.MessageSignature.MessageDigest!.Algorithm,
            bundle2.MessageSignature.MessageDigest!.Algorithm);
        TestSeq.AreEqual(
            bundle1.MessageSignature.MessageDigest.Digest.ToArray(),
            bundle2.MessageSignature.MessageDigest.Digest.ToArray());
    }

    [TestMethod]
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

        Assert.IsNotNull(bundle2.DsseEnvelope);
        Assert.AreEqual(bundle1.DsseEnvelope!.PayloadType, bundle2.DsseEnvelope.PayloadType);
        TestSeq.AreEqual(bundle1.DsseEnvelope.Payload.ToArray(), bundle2.DsseEnvelope.Payload.ToArray());
        Assert.AreEqual(bundle1.DsseEnvelope.Signatures[0].KeyId, bundle2.DsseEnvelope.Signatures[0].KeyId);
        TestSeq.AreEqual(bundle1.DsseEnvelope.Signatures[0].Sig.ToArray(), bundle2.DsseEnvelope.Signatures[0].Sig.ToArray());
    }

    [TestMethod]
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

        Assert.IsNotNull(bundle.VerificationMaterial);
        Assert.IsNull(bundle.VerificationMaterial.Certificate);
        Assert.IsNull(bundle.VerificationMaterial.CertificateChain);
        Assert.IsNull(bundle.VerificationMaterial.PublicKeyHint);
        Assert.IsEmpty(bundle.VerificationMaterial.TlogEntries);
        Assert.IsEmpty(bundle.VerificationMaterial.Rfc3161Timestamps);
        Assert.IsNull(bundle.MessageSignature!.MessageDigest);
    }

    [TestMethod]
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

        Assert.IsEmpty(bundle.VerificationMaterial!.TlogEntries);
        Assert.IsEmpty(bundle.VerificationMaterial.Rfc3161Timestamps);
    }

    [TestMethod]
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

    [TestMethod]
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

        Assert.AreEqual("my-key-id", bundle.VerificationMaterial!.PublicKeyHint);
    }

    [TestMethod]
    public void Deserialize_InvalidJson_Throws()
    {
        Assert.ThrowsExactly<JsonException>(() => SigstoreBundle.Deserialize("not json"));
    }

    [TestMethod]
    public void Serialize_HashAlgorithms_UseStringValues()
    {
        var bundle = new SigstoreBundle
        {
            MessageSignature = new MessageSignature
            {
                MessageDigest = new HashOutput
                {
                    Algorithm = HashAlgorithmType.Sha384,
                    Digest = new byte[] { 1, 2, 3 }
                },
                Signature = new byte[] { 4, 5, 6 }
            }
        };

        var json = bundle.Serialize();

        Assert.Contains("SHA2_384", json);
    }

    [TestMethod]
    public async Task LoadAsync_DeserializesFromFile()
    {
        var original = new SigstoreBundle
        {
            MediaType = "application/vnd.dev.sigstore.bundle.v0.3+json",
            MessageSignature = new MessageSignature
            {
                Signature = new byte[] { 1, 2, 3 },
                MessageDigest = new HashOutput
                {
                    Algorithm = HashAlgorithmType.Sha256,
                    Digest = new byte[] { 4, 5, 6 }
                }
            }
        };

        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, original.Serialize());

            var loaded = await SigstoreBundle.LoadAsync(new FileInfo(path));

            Assert.AreEqual(original.MediaType, loaded.MediaType);
            Assert.IsNotNull(loaded.MessageSignature);
            TestSeq.AreEqual(original.MessageSignature.Signature.ToArray(), loaded.MessageSignature!.Signature.ToArray());
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task SaveAsync_WritesToFile()
    {
        var bundle = new SigstoreBundle
        {
            MediaType = "application/vnd.dev.sigstore.bundle.v0.3+json",
            MessageSignature = new MessageSignature
            {
                Signature = new byte[] { 10, 20, 30 }
            }
        };

        var path = Path.GetTempFileName();
        try
        {
            await bundle.SaveAsync(new FileInfo(path));

            var json = await File.ReadAllTextAsync(path);
            var loaded = SigstoreBundle.Deserialize(json);

            Assert.AreEqual(bundle.MediaType, loaded.MediaType);
            Assert.IsNotNull(loaded.MessageSignature);
            TestSeq.AreEqual(bundle.MessageSignature.Signature.ToArray(), loaded.MessageSignature!.Signature.ToArray());
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public void Serialize_Stream_WritesJson()
    {
        var bundle = new SigstoreBundle
        {
            MediaType = "application/vnd.dev.sigstore.bundle.v0.3+json",
            MessageSignature = new MessageSignature
            {
                Signature = new byte[] { 7, 8, 9 }
            }
        };

        using var stream = new MemoryStream();
        bundle.Serialize(stream);

        stream.Position = 0;
        var loaded = SigstoreBundle.Deserialize(stream);

        Assert.AreEqual(bundle.MediaType, loaded.MediaType);
        Assert.IsNotNull(loaded.MessageSignature);
        TestSeq.AreEqual(bundle.MessageSignature.Signature.ToArray(), loaded.MessageSignature!.Signature.ToArray());
    }
}
