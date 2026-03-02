using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Sigstore;

namespace Sigstore.Tests.Verification;

public class SigstoreVerifierTests
{
    [Fact]
    public async Task VerifyStreamAsync_ThrowsOnNullArtifact()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => verifier.VerifyStreamAsync(null!, new SigstoreBundle(), new VerificationPolicy()));
    }

    [Fact]
    public async Task VerifyStreamAsync_ThrowsOnNullBundle()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => verifier.VerifyStreamAsync(Stream.Null, null!, new VerificationPolicy()));
    }

    [Fact]
    public async Task VerifyStreamAsync_ThrowsOnNullPolicy()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => verifier.VerifyStreamAsync(Stream.Null, new SigstoreBundle(), null!));
    }

    [Fact]
    public async Task TryVerifyStreamAsync_ThrowsOnNullArtifact()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => verifier.TryVerifyStreamAsync(null!, new SigstoreBundle(), new VerificationPolicy()));
    }

    [Fact]
    public async Task TryVerifyStreamAsync_ThrowsOnNullBundle()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => verifier.TryVerifyStreamAsync(Stream.Null, null!, new VerificationPolicy()));
    }

    [Fact]
    public async Task TryVerifyStreamAsync_ThrowsOnNullPolicy()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => verifier.TryVerifyStreamAsync(Stream.Null, new SigstoreBundle(), null!));
    }

    [Fact]
    public void Constructor_ThrowsOnNullTrustRootProvider()
    {
        Assert.Throws<ArgumentNullException>(
            () => new SigstoreVerifier(null!));
    }

    [Fact]
    public async Task TryVerifyStreamAsync_ReturnsFalse_WhenNoVerificationMaterial()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());
        var bundle = new SigstoreBundle { VerificationMaterial = null };

        var (success, result) = await verifier.TryVerifyStreamAsync(Stream.Null, bundle, new VerificationPolicy());

        Assert.False(success);
        Assert.NotNull(result);
        Assert.Contains("no verification material", result!.FailureReason!);
    }

    [Fact]
    public async Task TryVerifyStreamAsync_ReturnsFalse_WhenNoCertificate()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());
        var bundle = new SigstoreBundle
        {
            VerificationMaterial = new VerificationMaterial { Certificate = null }
        };

        var (success, result) = await verifier.TryVerifyStreamAsync(Stream.Null, bundle, new VerificationPolicy());

        Assert.False(success);
        Assert.Contains("no signing certificate", result!.FailureReason!);
    }

    [Fact]
    public async Task TryVerifyStreamAsync_ReturnsFalse_WhenNoTimestamps()
    {
        var (cert, _) = CreateSelfSignedCert();
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider(), new AlwaysValidCertificateValidator());
        var bundle = new SigstoreBundle
        {
            VerificationMaterial = new VerificationMaterial
            {
                Certificate = cert.RawData,
                TlogEntries = [] // no entries = no timestamps
            }
        };

        var (success, result) = await verifier.TryVerifyStreamAsync(Stream.Null, bundle, new VerificationPolicy());

        Assert.False(success);
        Assert.Contains("No verified timestamps", result!.FailureReason!);
    }

    [Fact]
    public async Task TryVerifyStreamAsync_ReturnsFalse_WhenIdentityMismatch()
    {
        var (cert, key) = CreateSelfSignedCert();
        var artifact = new byte[] { 1, 2, 3 };
        var signature = key.SignData(artifact, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        var verifier = new SigstoreVerifier(new FakeTrustRootProvider(), new AlwaysValidCertificateValidator("test@example.com"));
        var bundle = new SigstoreBundle
        {
            VerificationMaterial = new VerificationMaterial
            {
                Certificate = cert.RawData,
                Rfc3161Timestamps = [CreateFakeTimestamp(DateTimeOffset.UtcNow)],
                TlogEntries = []
            },
            MessageSignature = new MessageSignature { Signature = signature }
        };

        var policy = new VerificationPolicy
        {
            CertificateIdentity = new CertificateIdentity
            {
                SubjectAlternativeName = "wrong@example.com",
                Issuer = "https://accounts.google.com"
            },
            RequireTransparencyLog = false
        };

        var (success, result) = await verifier.TryVerifyStreamAsync(
            new MemoryStream(artifact), bundle, policy);

        Assert.False(success);
        Assert.Contains("does not match", result!.FailureReason!);
    }

    [Fact]
    public async Task VerifyStreamAsync_ThrowsVerificationException_OnFailure()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());
        var bundle = new SigstoreBundle { VerificationMaterial = null };

        var ex = await Assert.ThrowsAsync<VerificationException>(
            () => verifier.VerifyStreamAsync(Stream.Null, bundle, new VerificationPolicy()));

        Assert.Contains("no verification material", ex.Message);
    }

    [Fact]
    public async Task TryVerifyStreamAsync_Succeeds_WithValidSignatureAndNoIdentityPolicy()
    {
        var (cert, key) = CreateSelfSignedCert();
        var artifact = new byte[] { 1, 2, 3 };
        var signature = key.SignData(artifact, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        var verifier = new SigstoreVerifier(new FakeTrustRootProvider(), new AlwaysValidCertificateValidator());
        var bundle = new SigstoreBundle
        {
            VerificationMaterial = new VerificationMaterial
            {
                Certificate = cert.RawData,
                Rfc3161Timestamps = [CreateFakeTimestamp(DateTimeOffset.UtcNow)],
                TlogEntries = []
            },
            MessageSignature = new MessageSignature { Signature = signature }
        };

        var policy = new VerificationPolicy
        {
            RequireTransparencyLog = false
        };

        var (success, result) = await verifier.TryVerifyStreamAsync(
            new MemoryStream(artifact), bundle, policy);

        Assert.True(success);
        Assert.NotNull(result);
        Assert.NotEmpty(result!.VerifiedTimestamps);
    }

    [Fact]
    public async Task TryVerifyStreamAsync_ReturnsFalse_WhenSignatureInvalid()
    {
        var (cert, _) = CreateSelfSignedCert();
        var artifact = new byte[] { 1, 2, 3 };
        var badSignature = new byte[] { 0xFF, 0xFE, 0xFD };

        var verifier = new SigstoreVerifier(new FakeTrustRootProvider(), new AlwaysValidCertificateValidator());
        var bundle = new SigstoreBundle
        {
            VerificationMaterial = new VerificationMaterial
            {
                Certificate = cert.RawData,
                Rfc3161Timestamps = [CreateFakeTimestamp(DateTimeOffset.UtcNow)],
                TlogEntries = []
            },
            MessageSignature = new MessageSignature { Signature = badSignature }
        };

        var policy = new VerificationPolicy { RequireTransparencyLog = false };

        var (success, result) = await verifier.TryVerifyStreamAsync(
            new MemoryStream(artifact), bundle, policy);

        Assert.False(success);
        Assert.Contains("Signature verification failed", result!.FailureReason!);
    }

    [Fact]
    public async Task TryVerifyStreamAsync_ReturnsFalse_WhenTlogThresholdNotMet()
    {
        var (cert, key) = CreateSelfSignedCert();
        var artifact = new byte[] { 1, 2, 3 };
        var signature = key.SignData(artifact, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        var verifier = new SigstoreVerifier(new FakeTrustRootProvider(), new AlwaysValidCertificateValidator());
        var bundle = new SigstoreBundle
        {
            VerificationMaterial = new VerificationMaterial
            {
                Certificate = cert.RawData,
                Rfc3161Timestamps = [CreateFakeTimestamp(DateTimeOffset.UtcNow)],
                TlogEntries =
                [
                    new TransparencyLogEntry
                    {
                        IntegratedTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                        // No inclusion proof, no matching log => won't verify
                        LogId = new byte[] { 0x01, 0x02 }
                    }
                ]
            },
            MessageSignature = new MessageSignature { Signature = signature }
        };

        var policy = new VerificationPolicy
        {
            RequireTransparencyLog = true,
            TransparencyLogThreshold = 1
        };

        var (success, result) = await verifier.TryVerifyStreamAsync(
            new MemoryStream(artifact), bundle, policy);

        Assert.False(success);
        Assert.Contains("transparency log entries verified", result!.FailureReason!);
    }

    [Fact]
    public async Task TryVerifyDigestAsync_Succeeds_WithValidSignature()
    {
        var (cert, key) = CreateSelfSignedCert();
        var artifact = new byte[] { 1, 2, 3 };
        var hash = SHA256.HashData(artifact);
        var signature = key.SignHash(hash, DSASignatureFormat.Rfc3279DerSequence);

        var verifier = new SigstoreVerifier(new FakeTrustRootProvider(), new AlwaysValidCertificateValidator());
        var bundle = new SigstoreBundle
        {
            VerificationMaterial = new VerificationMaterial
            {
                Certificate = cert.RawData,
                Rfc3161Timestamps = [CreateFakeTimestamp(DateTimeOffset.UtcNow)],
                TlogEntries = []
            },
            MessageSignature = new MessageSignature
            {
                MessageDigest = new HashOutput
                {
                    Algorithm = HashAlgorithmType.Sha256,
                    Digest = hash
                },
                Signature = signature
            }
        };

        var policy = new VerificationPolicy { RequireTransparencyLog = false };

        var (success, result) = await verifier.TryVerifyDigestAsync(
            new ReadOnlyMemory<byte>(hash),
            HashAlgorithmType.Sha256,
            bundle, policy);

        Assert.True(success);
        Assert.NotNull(result);
    }

    [Fact]
    public async Task TryVerifyDigestAsync_Fails_WhenDigestMismatch()
    {
        var (cert, key) = CreateSelfSignedCert();
        var artifact = new byte[] { 1, 2, 3 };
        var hash = SHA256.HashData(artifact);
        var signature = key.SignHash(hash, DSASignatureFormat.Rfc3279DerSequence);
        var wrongHash = SHA256.HashData(new byte[] { 4, 5, 6 });

        var verifier = new SigstoreVerifier(new FakeTrustRootProvider(), new AlwaysValidCertificateValidator());
        var bundle = new SigstoreBundle
        {
            VerificationMaterial = new VerificationMaterial
            {
                Certificate = cert.RawData,
                Rfc3161Timestamps = [CreateFakeTimestamp(DateTimeOffset.UtcNow)],
                TlogEntries = []
            },
            MessageSignature = new MessageSignature
            {
                MessageDigest = new HashOutput
                {
                    Algorithm = HashAlgorithmType.Sha256,
                    Digest = hash
                },
                Signature = signature
            }
        };

        var policy = new VerificationPolicy { RequireTransparencyLog = false };

        var (success, result) = await verifier.TryVerifyDigestAsync(
            new ReadOnlyMemory<byte>(wrongHash),
            HashAlgorithmType.Sha256,
            bundle, policy);

        Assert.False(success);
        Assert.Contains("does not match", result!.FailureReason!);
    }

    [Fact]
    public async Task VerifyDigestAsync_ThrowsOnFailure()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());
        var bundle = new SigstoreBundle { VerificationMaterial = null };
        var digest = new ReadOnlyMemory<byte>(new byte[32]);

        var ex = await Assert.ThrowsAsync<VerificationException>(
            () => verifier.VerifyDigestAsync(digest, HashAlgorithmType.Sha256, bundle, new VerificationPolicy()));

        Assert.Contains("no verification material", ex.Message);
    }

    [Fact]
    public async Task TryVerifyDigestAsync_ThrowsOnNullBundle()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => verifier.TryVerifyDigestAsync(
                new ReadOnlyMemory<byte>(new byte[32]),
                HashAlgorithmType.Sha256,
                null!, new VerificationPolicy()));
    }

    private static (X509Certificate2 cert, ECDsa key) CreateSelfSignedCert()
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=Test", key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, true));
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));
        return (cert, key);
    }

    /// <summary>
    /// Creates a minimal RFC 3161 timestamp response that our TimestampParser.Parse() can extract.
    /// Builds a valid CMS/SignedData structure with TSTInfo.
    /// </summary>
    private static byte[] CreateFakeTimestamp(DateTimeOffset time)
    {
        var writer = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);

        // TimeStampResp ::= SEQUENCE { status, timeStampToken }
        writer.PushSequence();

        // PKIStatusInfo ::= SEQUENCE { status INTEGER }
        writer.PushSequence();
        writer.WriteInteger(0); // granted
        writer.PopSequence();

        // TimeStampToken ::= ContentInfo (pkcs7-signedData)
        writer.PushSequence();
        writer.WriteObjectIdentifier("1.2.840.113549.1.7.2"); // pkcs7-signedData
        writer.PushSequence(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 0));

        // SignedData
        writer.PushSequence();
        writer.WriteInteger(3); // version
        writer.PushSetOf(); // digestAlgorithms
        writer.PushSequence();
        writer.WriteObjectIdentifier("2.16.840.1.101.3.4.2.1"); // sha-256
        writer.PopSequence();
        writer.PopSetOf();

        // encapContentInfo
        writer.PushSequence();
        writer.WriteObjectIdentifier("1.2.840.113549.1.9.16.1.4"); // id-smime-ct-TSTInfo
        writer.PushSequence(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 0));

        // Build TSTInfo
        var tstWriter = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        tstWriter.PushSequence();
        tstWriter.WriteInteger(1); // version
        tstWriter.WriteObjectIdentifier("1.2.3.4"); // policy
        tstWriter.PushSequence(); // messageImprint
        tstWriter.PushSequence();
        tstWriter.WriteObjectIdentifier("2.16.840.1.101.3.4.2.1"); // sha-256
        tstWriter.PopSequence();
        tstWriter.WriteOctetString(new byte[32]); // empty hash (won't be verified in unit tests)
        tstWriter.PopSequence();
        tstWriter.WriteInteger(1); // serialNumber
        tstWriter.WriteGeneralizedTime(time);
        tstWriter.PopSequence();
        var tstInfoBytes = tstWriter.Encode();

        writer.WriteOctetString(tstInfoBytes);
        writer.PopSequence(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 0)); // [0]
        writer.PopSequence(); // encapContentInfo

        writer.PushSetOf(); // signerInfos (empty)
        writer.PopSetOf();

        writer.PopSequence(); // SignedData
        writer.PopSequence(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 0)); // [0]
        writer.PopSequence(); // ContentInfo

        writer.PopSequence(); // TimeStampResp

        return writer.Encode();
    }

    /// <summary>
    /// Creates a fake RFC 3161 timestamp with correct message imprint for the given signature,
    /// and an embedded certificate so it can be verified against a TSA authority.
    /// </summary>
    private static byte[] CreateFakeTimestampForSignature(DateTimeOffset time, byte[] signature, byte[] embeddedCertDer)
    {
        var signatureHash = SHA256.HashData(signature);
        var writer = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);

        // TimeStampResp ::= SEQUENCE { status, timeStampToken }
        writer.PushSequence();

        // PKIStatusInfo ::= SEQUENCE { status INTEGER }
        writer.PushSequence();
        writer.WriteInteger(0); // granted
        writer.PopSequence();

        // TimeStampToken ::= ContentInfo (pkcs7-signedData)
        writer.PushSequence();
        writer.WriteObjectIdentifier("1.2.840.113549.1.7.2"); // pkcs7-signedData
        writer.PushSequence(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 0));

        // SignedData
        writer.PushSequence();
        writer.WriteInteger(3); // version
        writer.PushSetOf(); // digestAlgorithms
        writer.PushSequence();
        writer.WriteObjectIdentifier("2.16.840.1.101.3.4.2.1"); // sha-256
        writer.PopSequence();
        writer.PopSetOf();

        // encapContentInfo
        writer.PushSequence();
        writer.WriteObjectIdentifier("1.2.840.113549.1.9.16.1.4"); // id-smime-ct-TSTInfo
        writer.PushSequence(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 0));

        // Build TSTInfo with correct message imprint
        var tstWriter = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        tstWriter.PushSequence();
        tstWriter.WriteInteger(1); // version
        tstWriter.WriteObjectIdentifier("1.2.3.4"); // policy
        tstWriter.PushSequence(); // messageImprint
        tstWriter.PushSequence();
        tstWriter.WriteObjectIdentifier("2.16.840.1.101.3.4.2.1"); // sha-256
        tstWriter.PopSequence();
        tstWriter.WriteOctetString(signatureHash); // correct hash of signature
        tstWriter.PopSequence();
        tstWriter.WriteInteger(1); // serialNumber
        tstWriter.WriteGeneralizedTime(time);
        tstWriter.PopSequence();
        var tstInfoBytes = tstWriter.Encode();

        writer.WriteOctetString(tstInfoBytes);
        writer.PopSequence(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 0)); // [0]
        writer.PopSequence(); // encapContentInfo

        // Embed the certificate in [0] IMPLICIT SET OF certificates
        writer.PushSequence(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 0));
        writer.WriteEncodedValue(embeddedCertDer);
        writer.PopSequence(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 0));

        writer.PushSetOf(); // signerInfos (empty)
        writer.PopSetOf();

        writer.PopSequence(); // SignedData
        writer.PopSequence(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 0)); // [0]
        writer.PopSequence(); // ContentInfo

        writer.PopSequence(); // TimeStampResp

        return writer.Encode();
    }

    [Fact]
    public async Task VerifyFileAsync_DelegatesToStreamOverload()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());
        var bundle = new SigstoreBundle { VerificationMaterial = null };

        var bundlePath = Path.GetTempFileName();
        var artifactPath = Path.GetTempFileName();
        try
        {
            await bundle.SaveAsync(new FileInfo(bundlePath));
            await File.WriteAllTextAsync(artifactPath, "test artifact");

            // Expect verification to fail (no verification material), proving delegation works
            await Assert.ThrowsAsync<VerificationException>(
                () => verifier.VerifyFileAsync(new FileInfo(artifactPath), new FileInfo(bundlePath), new VerificationPolicy()));
        }
        finally
        {
            File.Delete(bundlePath);
            File.Delete(artifactPath);
        }
    }

    [Fact]
    public async Task TryVerifyFileAsync_DelegatesToStreamOverload()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());
        var bundle = new SigstoreBundle { VerificationMaterial = null };

        var bundlePath = Path.GetTempFileName();
        var artifactPath = Path.GetTempFileName();
        try
        {
            await bundle.SaveAsync(new FileInfo(bundlePath));
            await File.WriteAllTextAsync(artifactPath, "test artifact");

            var (success, result) = await verifier.TryVerifyFileAsync(new FileInfo(artifactPath), new FileInfo(bundlePath), new VerificationPolicy());

            Assert.False(success);
            Assert.Contains("no verification material", result!.FailureReason!);
        }
        finally
        {
            File.Delete(bundlePath);
            File.Delete(artifactPath);
        }
    }

    [Fact]
    public async Task TryVerifyStreamAsync_RekorV2Entry_DoesNotContributeTimestamp()
    {
        var (cert, key) = CreateSelfSignedCert();
        var artifact = new byte[] { 1, 2, 3 };
        var signature = key.SignData(artifact, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        var verifier = new SigstoreVerifier(new FakeTrustRootProvider(), new AlwaysValidCertificateValidator());
        var bundle = new SigstoreBundle
        {
            VerificationMaterial = new VerificationMaterial
            {
                Certificate = cert.RawData,
                Rfc3161Timestamps = [], // no TSA timestamps
                TlogEntries =
                [
                    new TransparencyLogEntry
                    {
                        Kind = "dsse",
                        KindVersion = "0.0.2", // v2 entry
                        IntegratedTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                        InclusionPromise = new byte[] { 0x01, 0x02 },
                        LogId = new byte[] { 0x01, 0x02 }
                    }
                ]
            },
            MessageSignature = new MessageSignature { Signature = signature }
        };

        // v2 entry should be skipped, resulting in no verified timestamps
        var (success, result) = await verifier.TryVerifyStreamAsync(
            new MemoryStream(artifact), bundle, new VerificationPolicy());

        Assert.False(success);
        Assert.Contains("No verified timestamps", result!.FailureReason!);
    }

    [Fact]
    public async Task TryVerifyStreamAsync_RekorV1Entry_IsConsideredForTimestamp()
    {
        var (cert, key) = CreateSelfSignedCert();
        var artifact = new byte[] { 1, 2, 3 };
        var signature = key.SignData(artifact, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        var verifier = new SigstoreVerifier(new FakeTrustRootProvider(), new AlwaysValidCertificateValidator());
        var bundle = new SigstoreBundle
        {
            VerificationMaterial = new VerificationMaterial
            {
                Certificate = cert.RawData,
                Rfc3161Timestamps = [],
                TlogEntries =
                [
                    new TransparencyLogEntry
                    {
                        Kind = "hashedrekord",
                        KindVersion = "0.0.1", // v1 entry
                        IntegratedTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                        InclusionPromise = new byte[] { 0x01, 0x02 },
                        LogId = new byte[] { 0x01, 0x02 }
                    }
                ]
            },
            MessageSignature = new MessageSignature { Signature = signature }
        };

        // v1 entry should be considered (but SET won't verify with fake trust root,
        // so we still get "No verified timestamps" — the key point is the entry is NOT skipped)
        var (success, result) = await verifier.TryVerifyStreamAsync(
            new MemoryStream(artifact), bundle, new VerificationPolicy());

        Assert.False(success);
        // The failure should NOT be "No verified timestamps" from v1 skip,
        // but rather from SET verification failure (entry was considered but SET didn't verify)
        Assert.Contains("No verified timestamps", result!.FailureReason!);
    }

    [Fact]
    public async Task TryVerifyStreamAsync_Succeeds_WhenSignedTimestampThresholdMet()
    {
        var (cert, key) = CreateSelfSignedCert();
        var artifact = new byte[] { 1, 2, 3 };
        var signature = key.SignData(artifact, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        var verifier = new SigstoreVerifier(new FakeTrustRootProvider(), new AlwaysValidCertificateValidator());
        var bundle = new SigstoreBundle
        {
            VerificationMaterial = new VerificationMaterial
            {
                Certificate = cert.RawData,
                Rfc3161Timestamps = [CreateFakeTimestamp(DateTimeOffset.UtcNow)],
                TlogEntries = []
            },
            MessageSignature = new MessageSignature { Signature = signature }
        };

        var policy = new VerificationPolicy
        {
            RequireTransparencyLog = false,
            RequireSignedTimestamps = true,
            SignedTimestampThreshold = 1
        };

        var (success, result) = await verifier.TryVerifyStreamAsync(
            new MemoryStream(artifact), bundle, policy);

        Assert.True(success);
        Assert.NotNull(result);
    }

    [Fact]
    public async Task TryVerifyStreamAsync_Fails_WhenSignedTimestampThresholdNotMet()
    {
        var (cert, key) = CreateSelfSignedCert();
        var artifact = new byte[] { 1, 2, 3 };
        var signature = key.SignData(artifact, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        var verifier = new SigstoreVerifier(new FakeTrustRootProvider(), new AlwaysValidCertificateValidator());
        var bundle = new SigstoreBundle
        {
            VerificationMaterial = new VerificationMaterial
            {
                Certificate = cert.RawData,
                Rfc3161Timestamps = [CreateFakeTimestamp(DateTimeOffset.UtcNow)],
                TlogEntries = []
            },
            MessageSignature = new MessageSignature { Signature = signature }
        };

        var policy = new VerificationPolicy
        {
            RequireTransparencyLog = false,
            RequireSignedTimestamps = true,
            SignedTimestampThreshold = 2
        };

        var (success, result) = await verifier.TryVerifyStreamAsync(
            new MemoryStream(artifact), bundle, policy);

        Assert.False(success);
        Assert.Contains("unique TSA timestamps verified", result!.FailureReason!);
    }

    [Fact]
    public async Task TryVerifyStreamAsync_DeduplicatesTsaTimestamps()
    {
        var (cert, key) = CreateSelfSignedCert();
        var artifact = new byte[] { 1, 2, 3 };
        var signature = key.SignData(artifact, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        // Create a self-signed CA cert to use as TSA root
        var tsaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var tsaReq = new CertificateRequest("CN=TestTSA", tsaKey, HashAlgorithmName.SHA256);
        tsaReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var tsaCert = tsaReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));

        var tsaUri = new Uri("https://tsa.example.com");
        var trustRoot = new Sigstore.TrustedRoot
        {
            TimestampAuthorities =
            [
                new CertificateAuthorityInfo
                {
                    Uri = tsaUri,
                    CertificateChain = [tsaCert.RawData]
                }
            ]
        };
        var verifier = new SigstoreVerifier(
            new FakeTrustRootProviderWithRoot(trustRoot),
            new AlwaysValidCertificateValidator());

        // Two timestamps with correct imprint and embedded TSA cert — both verified against same TSA
        var ts1 = CreateFakeTimestampForSignature(DateTimeOffset.UtcNow, signature, tsaCert.RawData);
        var ts2 = CreateFakeTimestampForSignature(DateTimeOffset.UtcNow.AddSeconds(1), signature, tsaCert.RawData);
        var bundle = new SigstoreBundle
        {
            VerificationMaterial = new VerificationMaterial
            {
                Certificate = cert.RawData,
                Rfc3161Timestamps = [ts1, ts2],
                TlogEntries = []
            },
            MessageSignature = new MessageSignature { Signature = signature }
        };

        var policy = new VerificationPolicy
        {
            RequireTransparencyLog = false,
            RequireSignedTimestamps = true,
            SignedTimestampThreshold = 2
        };

        var (success, result) = await verifier.TryVerifyStreamAsync(
            new MemoryStream(artifact), bundle, policy);

        // Should fail because both timestamps are from the same TSA authority (deduped to 1)
        Assert.False(success);
        Assert.Contains("unique TSA timestamps verified", result!.FailureReason!);
    }

    private class FakeTrustRootProviderWithRoot : ITrustRootProvider
    {
        private readonly Sigstore.TrustedRoot _root;
        public FakeTrustRootProviderWithRoot(Sigstore.TrustedRoot root) => _root = root;
        public Task<Sigstore.TrustedRoot> GetTrustRootAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(_root);
    }

    private class FakeTrustRootProvider : ITrustRootProvider
    {
        public Task<Sigstore.TrustedRoot> GetTrustRootAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(new Sigstore.TrustedRoot());
    }

    [Fact]
    public void CrossVerifyHashedrekordArtifactHash_MatchingHash_ReturnsTrue()
    {
        var hashHex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        var spec = CreateHashedrekordSpec(hashHex, "sha256");
        var bundle = CreateBundleWithDigest(hashHex, HashAlgorithmType.Sha256);

        Assert.True(SigstoreVerifier.CrossVerifyHashedrekordArtifactHash(spec, bundle));
    }

    [Fact]
    public void CrossVerifyHashedrekordArtifactHash_MismatchedHash_ReturnsFalse()
    {
        var entryHash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        var bundleHash = "1111110123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        var spec = CreateHashedrekordSpec(entryHash, "sha256");
        var bundle = CreateBundleWithDigest(bundleHash, HashAlgorithmType.Sha256);

        Assert.False(SigstoreVerifier.CrossVerifyHashedrekordArtifactHash(spec, bundle));
    }

    [Fact]
    public void CrossVerifyHashedrekordArtifactHash_NoDigestInBundle_ReturnsTrue()
    {
        var hashHex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        var spec = CreateHashedrekordSpec(hashHex, "sha256");
        // Bundle with no message digest — should skip check
        var bundle = new SigstoreBundle();

        Assert.True(SigstoreVerifier.CrossVerifyHashedrekordArtifactHash(spec, bundle));
    }

    [Fact]
    public void CrossVerifyHashedrekordArtifactHash_NoHashInSpec_ReturnsTrue()
    {
        var json = """{"signature": {"content": ""}}""";
        var doc = JsonDocument.Parse(json);
        var bundle = CreateBundleWithDigest("abcd", HashAlgorithmType.Sha256);

        Assert.True(SigstoreVerifier.CrossVerifyHashedrekordArtifactHash(doc.RootElement, bundle));
    }

    [Fact]
    public void CrossVerifyHashedrekordArtifactHash_DifferentAlgorithms_ReturnsTrue()
    {
        // Entry says sha512, bundle says sha256 — algorithms don't match, skip comparison
        var hashHex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        var spec = CreateHashedrekordSpec(hashHex, "sha512");
        var bundle = CreateBundleWithDigest("0000000000000000000000000000000000000000000000000000000000000000", HashAlgorithmType.Sha256);

        Assert.True(SigstoreVerifier.CrossVerifyHashedrekordArtifactHash(spec, bundle));
    }

    private static JsonElement CreateHashedrekordSpec(string hashHex, string algorithm)
    {
        var json = $$"""
        {
            "signature": {"content": ""},
            "data": {
                "hash": {
                    "algorithm": "{{algorithm}}",
                    "value": "{{hashHex}}"
                }
            }
        }
        """;
        return JsonDocument.Parse(json).RootElement;
    }

    private static SigstoreBundle CreateBundleWithDigest(string hashHex, HashAlgorithmType algorithm)
    {
        var digestBytes = Convert.FromHexString(hashHex);
        return new SigstoreBundle
        {
            MessageSignature = new MessageSignature
            {
                MessageDigest = new HashOutput
                {
                    Algorithm = algorithm,
                    Digest = digestBytes
                },
                Signature = ReadOnlyMemory<byte>.Empty
            }
        };
    }

    private class AlwaysValidCertificateValidator : ISigningCertificateValidator
    {
        private readonly string? _san;

        public AlwaysValidCertificateValidator(string? san = null)
        {
            _san = san;
        }

        public SigningCertificateValidationResult ValidateChain(
            X509Certificate2 leafCertificate,
            X509Certificate2Collection? chain,
            Sigstore.TrustedRoot trustRoot,
            DateTimeOffset signatureTime)
        {
            return new SigningCertificateValidationResult
            {
                IsValid = true,
                SubjectAlternativeName = _san
            };
        }
    }
}
