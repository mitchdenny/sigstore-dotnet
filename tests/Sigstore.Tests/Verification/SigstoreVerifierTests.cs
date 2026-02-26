using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Sigstore.Verification;
using Sigstore.Common;

namespace Sigstore.Tests.Verification;

public class SigstoreVerifierTests
{
    [Fact]
    public async Task VerifyAsync_ThrowsOnNullArtifact()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => verifier.VerifyAsync(null!, new SigstoreBundle(), new VerificationPolicy()));
    }

    [Fact]
    public async Task VerifyAsync_ThrowsOnNullBundle()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => verifier.VerifyAsync(Stream.Null, null!, new VerificationPolicy()));
    }

    [Fact]
    public async Task VerifyAsync_ThrowsOnNullPolicy()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => verifier.VerifyAsync(Stream.Null, new SigstoreBundle(), null!));
    }

    [Fact]
    public async Task TryVerifyAsync_ThrowsOnNullArtifact()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => verifier.TryVerifyAsync(null!, new SigstoreBundle(), new VerificationPolicy()));
    }

    [Fact]
    public async Task TryVerifyAsync_ThrowsOnNullBundle()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => verifier.TryVerifyAsync(Stream.Null, null!, new VerificationPolicy()));
    }

    [Fact]
    public async Task TryVerifyAsync_ThrowsOnNullPolicy()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => verifier.TryVerifyAsync(Stream.Null, new SigstoreBundle(), null!));
    }

    [Fact]
    public void Constructor_ThrowsOnNullTrustRootProvider()
    {
        Assert.Throws<ArgumentNullException>(
            () => new SigstoreVerifier(null!));
    }

    [Fact]
    public async Task TryVerifyAsync_ReturnsFalse_WhenNoVerificationMaterial()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());
        var bundle = new SigstoreBundle { VerificationMaterial = null };

        var (success, result) = await verifier.TryVerifyAsync(Stream.Null, bundle, new VerificationPolicy());

        Assert.False(success);
        Assert.NotNull(result);
        Assert.Contains("no verification material", result!.FailureReason!);
    }

    [Fact]
    public async Task TryVerifyAsync_ReturnsFalse_WhenNoCertificate()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());
        var bundle = new SigstoreBundle
        {
            VerificationMaterial = new VerificationMaterial { Certificate = null }
        };

        var (success, result) = await verifier.TryVerifyAsync(Stream.Null, bundle, new VerificationPolicy());

        Assert.False(success);
        Assert.Contains("no signing certificate", result!.FailureReason!);
    }

    [Fact]
    public async Task TryVerifyAsync_ReturnsFalse_WhenNoTimestamps()
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

        var (success, result) = await verifier.TryVerifyAsync(Stream.Null, bundle, new VerificationPolicy());

        Assert.False(success);
        Assert.Contains("No verified timestamps", result!.FailureReason!);
    }

    [Fact]
    public async Task TryVerifyAsync_ReturnsFalse_WhenIdentityMismatch()
    {
        var (cert, key) = CreateSelfSignedCert();
        var artifact = new byte[] { 1, 2, 3 };
        var signature = key.SignData(artifact, HashAlgorithmName.SHA256);

        var verifier = new SigstoreVerifier(new FakeTrustRootProvider(), new AlwaysValidCertificateValidator("test@example.com"));
        var bundle = new SigstoreBundle
        {
            VerificationMaterial = new VerificationMaterial
            {
                Certificate = cert.RawData,
                TlogEntries =
                [
                    new TransparencyLogEntry { IntegratedTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds() }
                ]
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

        var (success, result) = await verifier.TryVerifyAsync(
            new MemoryStream(artifact), bundle, policy);

        Assert.False(success);
        Assert.Contains("does not match", result!.FailureReason!);
    }

    [Fact]
    public async Task VerifyAsync_ThrowsVerificationException_OnFailure()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());
        var bundle = new SigstoreBundle { VerificationMaterial = null };

        var ex = await Assert.ThrowsAsync<VerificationException>(
            () => verifier.VerifyAsync(Stream.Null, bundle, new VerificationPolicy()));

        Assert.Contains("no verification material", ex.Message);
    }

    [Fact]
    public async Task TryVerifyAsync_Succeeds_WithValidSignatureAndNoIdentityPolicy()
    {
        var (cert, key) = CreateSelfSignedCert();
        var artifact = new byte[] { 1, 2, 3 };
        var signature = key.SignData(artifact, HashAlgorithmName.SHA256);

        var verifier = new SigstoreVerifier(new FakeTrustRootProvider(), new AlwaysValidCertificateValidator());
        var bundle = new SigstoreBundle
        {
            VerificationMaterial = new VerificationMaterial
            {
                Certificate = cert.RawData,
                TlogEntries =
                [
                    new TransparencyLogEntry { IntegratedTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds() }
                ]
            },
            MessageSignature = new MessageSignature { Signature = signature }
        };

        var policy = new VerificationPolicy
        {
            RequireTransparencyLog = false
        };

        var (success, result) = await verifier.TryVerifyAsync(
            new MemoryStream(artifact), bundle, policy);

        Assert.True(success);
        Assert.NotNull(result);
        Assert.NotEmpty(result!.VerifiedTimestamps);
    }

    [Fact]
    public async Task TryVerifyAsync_ReturnsFalse_WhenSignatureInvalid()
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
                TlogEntries =
                [
                    new TransparencyLogEntry { IntegratedTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds() }
                ]
            },
            MessageSignature = new MessageSignature { Signature = badSignature }
        };

        var policy = new VerificationPolicy { RequireTransparencyLog = false };

        var (success, result) = await verifier.TryVerifyAsync(
            new MemoryStream(artifact), bundle, policy);

        Assert.False(success);
        Assert.Contains("Signature verification failed", result!.FailureReason!);
    }

    [Fact]
    public async Task TryVerifyAsync_ReturnsFalse_WhenTlogThresholdNotMet()
    {
        var (cert, key) = CreateSelfSignedCert();
        var artifact = new byte[] { 1, 2, 3 };
        var signature = key.SignData(artifact, HashAlgorithmName.SHA256);

        var verifier = new SigstoreVerifier(new FakeTrustRootProvider(), new AlwaysValidCertificateValidator());
        var bundle = new SigstoreBundle
        {
            VerificationMaterial = new VerificationMaterial
            {
                Certificate = cert.RawData,
                TlogEntries =
                [
                    new TransparencyLogEntry
                    {
                        IntegratedTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                        // No inclusion proof, no matching log => won't verify
                        LogId = [0x01, 0x02]
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

        var (success, result) = await verifier.TryVerifyAsync(
            new MemoryStream(artifact), bundle, policy);

        Assert.False(success);
        Assert.Contains("transparency log entries verified", result!.FailureReason!);
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

    private class FakeTrustRootProvider : ITrustRootProvider
    {
        public Task<Sigstore.TrustRoot.TrustedRoot> GetTrustRootAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(new Sigstore.TrustRoot.TrustedRoot());
    }

    private class AlwaysValidCertificateValidator : ICertificateValidator
    {
        private readonly string? _san;

        public AlwaysValidCertificateValidator(string? san = null)
        {
            _san = san;
        }

        public CertificateValidationResult ValidateChain(
            X509Certificate2 leafCertificate,
            X509Certificate2Collection? chain,
            Sigstore.TrustRoot.TrustedRoot trustRoot,
            DateTimeOffset signatureTime)
        {
            return new CertificateValidationResult
            {
                IsValid = true,
                SubjectAlternativeName = _san
            };
        }
    }
}
