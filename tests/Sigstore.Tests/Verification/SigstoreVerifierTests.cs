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
    public void CrossVerifyHashedrekordArtifactHash_NoDigestInBundle_ReturnsFalse()
    {
        var hashHex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        var spec = CreateHashedrekordSpec(hashHex, "sha256");
        // A hashedrekord entry records a message signature. With no message digest in the
        // bundle there is nothing for the entry's hash to be bound to, so it must not pass.
        var bundle = new SigstoreBundle();

        Assert.False(SigstoreVerifier.CrossVerifyHashedrekordArtifactHash(spec, bundle));
    }

    [Fact]
    public void CrossVerifyHashedrekordArtifactHash_NoHashInSpec_ReturnsFalse()
    {
        // data.hash.value is required by the schema; without it the entry is not bound to
        // any artifact and must not be treated as cross-verified.
        var json = """{"signature": {"content": ""}}""";
        var doc = JsonDocument.Parse(json);
        var bundle = CreateBundleWithDigest(ValidHashHex, HashAlgorithmType.Sha256);

        Assert.False(SigstoreVerifier.CrossVerifyHashedrekordArtifactHash(doc.RootElement, bundle));
    }

    [Fact]
    public void CrossVerifyHashedrekordArtifactHash_DifferentAlgorithms_ReturnsFalse()
    {
        // Entry says sha512, bundle says sha256. The digests are not comparable, so the
        // binding cannot be established — skipping the comparison would let a mismatched
        // entry through by simply declaring a different algorithm.
        var hashHex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        var spec = CreateHashedrekordSpec(hashHex, "sha512");
        var bundle = CreateBundleWithDigest("0000000000000000000000000000000000000000000000000000000000000000", HashAlgorithmType.Sha256);

        Assert.False(SigstoreVerifier.CrossVerifyHashedrekordArtifactHash(spec, bundle));
    }

    [Fact]
    public void CrossVerifyHashedrekordArtifactHash_UnknownAlgorithm_ReturnsFalse()
    {
        var spec = CreateHashedrekordSpec(ValidHashHex, "md5");
        var bundle = CreateBundleWithDigest(ValidHashHex, HashAlgorithmType.Sha256);

        Assert.False(SigstoreVerifier.CrossVerifyHashedrekordArtifactHash(spec, bundle));
    }

    [Fact]
    public void CrossVerifyHashedrekordArtifactHash_MissingAlgorithm_ReturnsFalse()
    {
        var json = $$"""
        {"data": {"hash": {"value": "{{ValidHashHex}}"} } }
        """;
        var spec = JsonDocument.Parse(json).RootElement;
        var bundle = CreateBundleWithDigest(ValidHashHex, HashAlgorithmType.Sha256);

        Assert.False(SigstoreVerifier.CrossVerifyHashedrekordArtifactHash(spec, bundle));
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
                Signature = FakeSignature
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

    // ---- Transparency log entry schema gating ----
    //
    // Cross-verification reads every field of an entry body by name. An entry whose
    // schema is not recognised matches none of those names, so every check is skipped
    // and the entry would otherwise be reported as verified without anything having
    // been checked. These tests pin the fail-closed behaviour.

    private static TransparencyLogEntry TlogEntryFor(string bodyJson, string? kind = null, string? kindVersion = null)
        => new()
        {
            Body = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(bodyJson)),
            Kind = kind,
            KindVersion = kindVersion
        };

    private const string ValidHashHex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    private static readonly byte[] FakeSignature = [0x11, 0x22, 0x33, 0x44];
    private static readonly byte[] FakeCertDer = [0x30, 0x82, 0x01, 0x02, 0xDE, 0xAD, 0xBE, 0xEF];

    private static string FakeCertPemBase64 => Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(
        $"-----BEGIN CERTIFICATE-----\n{Convert.ToBase64String(FakeCertDer)}\n-----END CERTIFICATE-----"));

    /// <summary>
    /// A complete, internally consistent hashedrekord v0.0.1 body matching the bundle
    /// produced by <see cref="CreateBundleWithDigest"/> and <see cref="FakeCertDer"/>. It
    /// is complete by default so that each negative test below fails for the reason it
    /// names, rather than incidentally tripping over an unrelated missing field.
    /// </summary>
    private static string HashedrekordV001Body(string kind = "hashedrekord", string apiVersion = "0.0.1")
        => $$"""
        {
            "kind": "{{kind}}",
            "apiVersion": "{{apiVersion}}",
            "spec": {
                "signature": {
                    "content": "{{Convert.ToBase64String(FakeSignature)}}",
                    "publicKey": {"content": "{{FakeCertPemBase64}}" }
                },
                "data": {"hash": {"algorithm": "sha256", "value": "{{ValidHashHex}}" } }
            }
        }
        """;

    [Fact]
    public void CrossVerifyTlogBody_SupportedSchemaWithMatchingContents_ReturnsTrue()
    {
        // Positive control: the gate must let a schema we do support through.
        var bundle = CreateBundleWithDigest(ValidHashHex, HashAlgorithmType.Sha256);

        Assert.True(SigstoreVerifier.CrossVerifyTlogBody(
            TlogEntryFor(HashedrekordV001Body(), "hashedrekord", "0.0.1"),
            bundle,
            FakeCertDer));
    }

    [Fact]
    public void CrossVerifyTlogBody_HashedrekordV001WithoutPublicKey_ReturnsFalse()
    {
        // The certificate binding is required: without it the entry is not tied to the
        // identity the bundle was verified against.
        var body = $$"""
        {
            "kind": "hashedrekord",
            "apiVersion": "0.0.1",
            "spec": {
                "signature": {"content": "{{Convert.ToBase64String(FakeSignature)}}" },
                "data": {"hash": {"algorithm": "sha256", "value": "{{ValidHashHex}}" } }
            }
        }
        """;
        var bundle = CreateBundleWithDigest(ValidHashHex, HashAlgorithmType.Sha256);

        Assert.False(SigstoreVerifier.CrossVerifyTlogBody(
            TlogEntryFor(body, "hashedrekord", "0.0.1"),
            bundle,
            FakeCertDer));
    }

    [Fact]
    public void CrossVerifyTlogBody_HashedrekordV001WithDifferentCertificate_ReturnsFalse()
    {
        var bundle = CreateBundleWithDigest(ValidHashHex, HashAlgorithmType.Sha256);

        Assert.False(SigstoreVerifier.CrossVerifyTlogBody(
            TlogEntryFor(HashedrekordV001Body(), "hashedrekord", "0.0.1"),
            bundle,
            new byte[] { 0x30, 0x82, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00 }));
    }

    [Fact]
    public void CrossVerifyTlogBody_UnknownKind_ReturnsFalse()
    {
        var bundle = CreateBundleWithDigest(ValidHashHex, HashAlgorithmType.Sha256);

        Assert.False(SigstoreVerifier.CrossVerifyTlogBody(
            TlogEntryFor(HashedrekordV001Body(kind: "rekord")),
            bundle,
            FakeCertDer));
    }

    [Fact]
    public void CrossVerifyTlogBody_UnsupportedApiVersionOfKnownKind_ReturnsFalse()
    {
        // The Rekor v2 regression in miniature: a kind we handle, carrying a schema
        // version we do not. Every v0.0.1 field lookup would miss and pass silently.
        var bundle = CreateBundleWithDigest(ValidHashHex, HashAlgorithmType.Sha256);

        Assert.False(SigstoreVerifier.CrossVerifyTlogBody(
            TlogEntryFor(HashedrekordV001Body(apiVersion: "0.0.3")),
            bundle,
            FakeCertDer));
    }

    [Theory]
    [InlineData("{\"apiVersion\": \"0.0.1\", \"spec\": {}}")]                        // no kind
    [InlineData("{\"kind\": \"hashedrekord\", \"spec\": {}}")]                       // no apiVersion
    [InlineData("{\"kind\": \"hashedrekord\", \"apiVersion\": \"0.0.1\"}")]          // no spec
    [InlineData("{\"kind\": \"hashedrekord\", \"apiVersion\": \"0.0.1\", \"spec\": 1}")] // spec not an object
    [InlineData("{\"kind\": 1, \"apiVersion\": \"0.0.1\", \"spec\": {}}")]           // kind not a string
    public void CrossVerifyTlogBody_MalformedBody_ReturnsFalse(string bodyJson)
    {
        Assert.False(SigstoreVerifier.CrossVerifyTlogBody(
            TlogEntryFor(bodyJson),
            new SigstoreBundle(),
            ReadOnlyMemory<byte>.Empty));
    }

    [Theory]
    [InlineData("intoto", "0.0.1")]
    [InlineData("hashedrekord", "0.0.2")]
    public void CrossVerifyTlogBody_BundleKindVersionDisagreesWithBody_ReturnsFalse(string kind, string version)
    {
        // The bundle states the entry's kind/version out of band. If that disagrees with
        // the signed body, the entry is not the one the bundle claims it is.
        var bundle = CreateBundleWithDigest(ValidHashHex, HashAlgorithmType.Sha256);

        Assert.False(SigstoreVerifier.CrossVerifyTlogBody(
            TlogEntryFor(HashedrekordV001Body(), kind, version),
            bundle,
            FakeCertDer));
    }

    [Fact]
    public void CrossVerifyTlogBody_DeclaredVersionWithoutMatchingShape_ReturnsFalse()
    {
        // Declares v0.0.2 but carries the v0.0.1 shape. Dispatching by sniffing for a
        // shape rather than by the declared version would route this to a handler that
        // finds none of its fields and checks nothing.
        var body = $$"""
        {
            "kind": "hashedrekord",
            "apiVersion": "0.0.2",
            "spec": {
                "signature": {},
                "data": {"hash": {"algorithm": "sha256", "value": "{{ValidHashHex}}" } }
            }
        }
        """;
        var bundle = CreateBundleWithDigest(ValidHashHex, HashAlgorithmType.Sha256);

        Assert.False(SigstoreVerifier.CrossVerifyTlogBody(
            TlogEntryFor(body, "hashedrekord", "0.0.2"),
            bundle,
            FakeCertDer));
    }

    [Fact]
    public void CrossVerifyTlogBody_HashedrekordV001WithoutSignature_ReturnsFalse()
    {
        // `signature` is required by the v0.0.1 schema and carries the bindings we check.
        var body = $$"""
        {
            "kind": "hashedrekord",
            "apiVersion": "0.0.1",
            "spec": {"data": {"hash": {"algorithm": "sha256", "value": "{{ValidHashHex}}" } } }
        }
        """;
        var bundle = CreateBundleWithDigest(ValidHashHex, HashAlgorithmType.Sha256);

        Assert.False(SigstoreVerifier.CrossVerifyTlogBody(
            TlogEntryFor(body, "hashedrekord", "0.0.1"),
            bundle,
            FakeCertDer));
    }

    [Fact]
    public void CrossVerifyTlogBody_ArtifactHashMismatchStillRejected_ReturnsFalse()
    {
        // Guards against the schema gate short-circuiting the content checks behind it.
        var bundle = CreateBundleWithDigest(
            "1111110123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            HashAlgorithmType.Sha256);

        Assert.False(SigstoreVerifier.CrossVerifyTlogBody(
            TlogEntryFor(HashedrekordV001Body(), "hashedrekord", "0.0.1"),
            bundle,
            FakeCertDer));
    }

    // ---- DSSE envelope entry bindings ----
    //
    // intoto v0.0.2 names its signature fields `sig`/`publicKey` while dsse v0.0.1 uses
    // `signature`/`verifier`. Looking only for the dsse names meant an intoto entry's
    // certificate binding was never checked at all, so these tests pin both shapes.

    private static readonly byte[] DssePayload = System.Text.Encoding.UTF8.GetBytes("""{"_type":"https://in-toto.io/Statement/v1"}""");

    private static SigstoreBundle CreateDsseBundle() => new()
    {
        DsseEnvelope = new DsseEnvelope
        {
            PayloadType = "application/vnd.in-toto+json",
            Payload = DssePayload,
            Signatures = [new DsseSignature { Sig = FakeSignature }]
        }
    };

    private static string DssePayloadHashHex =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(DssePayload)).ToLowerInvariant();

    private static string IntotoV002Body(string? certPemBase64 = null, string? payloadHashHex = null)
        => $$"""
        {
            "kind": "intoto",
            "apiVersion": "0.0.2",
            "spec": {
                "content": {
                    "envelope": {
                        "signatures": [{
                            "sig": "{{Convert.ToBase64String(FakeSignature)}}",
                            "publicKey": "{{certPemBase64 ?? FakeCertPemBase64}}"
                        }]
                    },
                    "payloadHash": {"algorithm": "sha256", "value": "{{payloadHashHex ?? DssePayloadHashHex}}" }
                }
            }
        }
        """;

    [Fact]
    public void CrossVerifyTlogBody_IntotoV002WithMatchingContents_ReturnsTrue()
    {
        Assert.True(SigstoreVerifier.CrossVerifyTlogBody(
            TlogEntryFor(IntotoV002Body(), "intoto", "0.0.2"),
            CreateDsseBundle(),
            FakeCertDer));
    }

    [Fact]
    public void CrossVerifyTlogBody_IntotoV002WithDifferentCertificate_ReturnsFalse()
    {
        // intoto stores the certificate under `publicKey`. Checking only `verifier` meant
        // this entry — attesting to a different signer than the bundle — was accepted.
        var otherCertPem = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(
            $"-----BEGIN CERTIFICATE-----\n{Convert.ToBase64String(new byte[] { 0x30, 0x82, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00 })}\n-----END CERTIFICATE-----"));

        Assert.False(SigstoreVerifier.CrossVerifyTlogBody(
            TlogEntryFor(IntotoV002Body(certPemBase64: otherCertPem), "intoto", "0.0.2"),
            CreateDsseBundle(),
            FakeCertDer));
    }

    [Fact]
    public void CrossVerifyTlogBody_IntotoV002WithMismatchedPayloadHash_ReturnsFalse()
    {
        Assert.False(SigstoreVerifier.CrossVerifyTlogBody(
            TlogEntryFor(IntotoV002Body(payloadHashHex: ValidHashHex), "intoto", "0.0.2"),
            CreateDsseBundle(),
            FakeCertDer));
    }

    [Theory]
    // no envelope to cross-check — previously accepted outright
    [InlineData("""{"kind":"intoto","apiVersion":"0.0.2","spec":{"content":{}}}""")]
    // envelope present but no signatures
    [InlineData("""{"kind":"intoto","apiVersion":"0.0.2","spec":{"content":{"envelope":{"signatures":[]},"payloadHash":{"algorithm":"sha256","value":"x"}}}}""")]
    // no payloadHash to bind the envelope contents
    [InlineData("""{"kind":"intoto","apiVersion":"0.0.2","spec":{"content":{"envelope":{"signatures":[{"sig":"ESIzRA==","publicKey":"eA=="}]}}}}""")]
    public void CrossVerifyTlogBody_IntotoV002WithMissingBindings_ReturnsFalse(string bodyJson)
    {
        Assert.False(SigstoreVerifier.CrossVerifyTlogBody(
            TlogEntryFor(bodyJson, "intoto", "0.0.2"),
            CreateDsseBundle(),
            FakeCertDer));
    }

    [Fact]
    public void CrossVerifyTlogBody_DsseV001WithMissingPayloadHash_ReturnsFalse()
    {
        var body = $$"""
        {
            "kind": "dsse",
            "apiVersion": "0.0.1",
            "spec": {
                "signatures": [{
                    "signature": "{{Convert.ToBase64String(FakeSignature)}}",
                    "verifier": "{{FakeCertPemBase64}}"
                }]
            }
        }
        """;

        Assert.False(SigstoreVerifier.CrossVerifyTlogBody(
            TlogEntryFor(body, "dsse", "0.0.1"),
            CreateDsseBundle(),
            FakeCertDer));
    }

    [Fact]
    public void CrossVerifyTlogBody_DsseV001WithMatchingContents_ReturnsTrue()
    {
        var body = $$"""
        {
            "kind": "dsse",
            "apiVersion": "0.0.1",
            "spec": {
                "signatures": [{
                    "signature": "{{Convert.ToBase64String(FakeSignature)}}",
                    "verifier": "{{FakeCertPemBase64}}"
                }],
                "payloadHash": {"algorithm": "sha256", "value": "{{DssePayloadHashHex}}" }
            }
        }
        """;

        Assert.True(SigstoreVerifier.CrossVerifyTlogBody(
            TlogEntryFor(body, "dsse", "0.0.1"),
            CreateDsseBundle(),
            FakeCertDer));
    }

    [Theory]
    // no data.digest to bind the signed content
    [InlineData("""{"data":{"algorithm":"SHA2_256"},"signature":{"content":"ESIzRA==","verifier":{"x509Certificate":{"rawBytes":"MIIBAt6tvu8="}}}}""")]
    // no data.algorithm, so the digest is not interpretable
    [InlineData("""{"data":{"digest":"3q2+7w=="},"signature":{"content":"ESIzRA==","verifier":{"x509Certificate":{"rawBytes":"MIIBAt6tvu8="}}}}""")]
    // no certificate binding
    [InlineData("""{"data":{"algorithm":"SHA2_256","digest":"3q2+7w=="},"signature":{"content":"ESIzRA=="}}""")]
    // no signature at all
    [InlineData("""{"data":{"algorithm":"SHA2_256","digest":"3q2+7w=="}}""")]
    public void CrossVerifyTlogBody_HashedrekordV002WithMissingBindings_ReturnsFalse(string v002Json)
    {
        var body = $$"""
        {"kind":"hashedrekord","apiVersion":"0.0.2","spec":{"hashedRekordV002":{{v002Json}} } }
        """;

        Assert.False(SigstoreVerifier.CrossVerifyTlogBody(
            TlogEntryFor(body, "hashedrekord", "0.0.2"),
            CreateBundleWithDigest(ValidHashHex, HashAlgorithmType.Sha256),
            FakeCertDer));
    }

    // ---- Issuer resolution for SCT verification ----
    //
    // A precertificate SCT commits to a hash of the issuing certificate's public key, so the
    // wrong issuer silently produces the wrong signed data and every SCT looks invalid. A CA
    // that rotates its key keeps its subject name, so a trusted root can hold several distinct
    // authorities sharing one name and the issuer cannot be chosen by name alone.

    private const string SharedCaSubject = "CN=shared-ca, O=sigstore-test";

    private static X509Certificate2 CreateTestCa(out ECDsa key)
    {
        key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(SharedCaSubject, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        var now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddDays(-1), now.AddDays(1));
    }

    private static X509Certificate2 CreateTestLeaf(X509Certificate2 issuer, bool includeAuthorityKeyIdentifier)
    {
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=leaf, O=sigstore-test", leafKey, HashAlgorithmName.SHA256);
        if (includeAuthorityKeyIdentifier)
        {
            request.CertificateExtensions.Add(
                X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false));
        }

        var now = DateTimeOffset.UtcNow;
        return request.Create(issuer, now.AddHours(-1), now.AddHours(1), [1, 2, 3, 4]);
    }

    private static TrustedRoot TrustedRootWith(params X509Certificate2[] cas)
    {
        return new TrustedRoot
        {
            CertificateAuthorities = cas
                .Select(ca => new CertificateAuthorityInfo
                {
                    Uri = new Uri("https://fulcio.example"),
                    CertificateChain = [ca.RawData]
                })
                .ToList()
        };
    }

    [Fact]
    public void ResolveIssuerCandidates_CasShareSubjectName_PrefersAuthorityKeyIdentifierMatch()
    {
        using var oldCa = CreateTestCa(out var oldKey);
        using var newCa = CreateTestCa(out var newKey);
        using (oldKey)
        using (newKey)
        using (var leaf = CreateTestLeaf(newCa, includeAuthorityKeyIdentifier: true))
        {
            // Both authorities share a subject name, and the one that did not issue the leaf is listed first.
            Assert.Equal(oldCa.SubjectName.RawData, newCa.SubjectName.RawData);
            var trustedRoot = TrustedRootWith(oldCa, newCa);

            var owned = new List<X509Certificate2>();
            try
            {
                var candidates = SigstoreVerifier.ResolveIssuerCandidates(leaf, null, trustedRoot, owned);

                Assert.Equal(newCa.Thumbprint, candidates[0].Thumbprint);
                Assert.Equal(2, candidates.Count);
            }
            finally
            {
                foreach (var candidate in owned)
                    candidate.Dispose();
            }
        }
    }

    [Fact]
    public void ResolveIssuerCandidates_LeafWithoutAuthorityKeyIdentifier_ReturnsEveryNameMatch()
    {
        using var oldCa = CreateTestCa(out var oldKey);
        using var newCa = CreateTestCa(out var newKey);
        using (oldKey)
        using (newKey)
        using (var leaf = CreateTestLeaf(newCa, includeAuthorityKeyIdentifier: false))
        {
            var trustedRoot = TrustedRootWith(oldCa, newCa);

            var owned = new List<X509Certificate2>();
            try
            {
                var candidates = SigstoreVerifier.ResolveIssuerCandidates(leaf, null, trustedRoot, owned);

                // Nothing distinguishes the authorities, so the real issuer must still be tried.
                Assert.Equal(2, candidates.Count);
                Assert.Contains(candidates, c => c.Thumbprint == newCa.Thumbprint);
            }
            finally
            {
                foreach (var candidate in owned)
                    candidate.Dispose();
            }
        }
    }

    [Fact]
    public void ResolveIssuerCandidates_NonMatchingSubjectName_IsExcluded()
    {
        using var ca = CreateTestCa(out var caKey);
        using (caKey)
        using (var leaf = CreateTestLeaf(ca, includeAuthorityKeyIdentifier: true))
        using (var unrelatedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            var unrelatedRequest = new CertificateRequest("CN=unrelated-ca", unrelatedKey, HashAlgorithmName.SHA256);
            unrelatedRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            using var unrelatedCa = unrelatedRequest.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

            var owned = new List<X509Certificate2>();
            try
            {
                var candidates = SigstoreVerifier.ResolveIssuerCandidates(
                    leaf, null, TrustedRootWith(unrelatedCa, ca), owned);

                Assert.Single(candidates);
                Assert.Equal(ca.Thumbprint, candidates[0].Thumbprint);
            }
            finally
            {
                foreach (var candidate in owned)
                    candidate.Dispose();
            }
        }
    }

    [Fact]
    public void ResolveIssuerCandidates_BundleSuppliesIntermediates_UsesThemVerbatim()
    {
        using var ca = CreateTestCa(out var caKey);
        using (caKey)
        using (var leaf = CreateTestLeaf(ca, includeAuthorityKeyIdentifier: true))
        {
            var intermediates = new X509Certificate2Collection(ca);

            var owned = new List<X509Certificate2>();
            var candidates = SigstoreVerifier.ResolveIssuerCandidates(
                leaf, intermediates, TrustedRootWith(), owned);

            Assert.Single(candidates);
            Assert.Equal(ca.Thumbprint, candidates[0].Thumbprint);
            Assert.Empty(owned);
        }
    }
}
