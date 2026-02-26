using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Sigstore.TrustRoot;
using Sigstore.Verification;

namespace Sigstore.Tests.Verification;

public class CertificateValidatorTests
{
    private static (X509Certificate2 root, X509Certificate2 leaf) CreateTestCertificates(
        DateTimeOffset notBefore, DateTimeOffset notAfter, string sanDns = "test.example.com")
    {
        // Create a self-signed root CA
        using var rootKey = RSA.Create(2048);
        var rootReq = new CertificateRequest(
            "CN=Test Root CA",
            rootKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));

        var rootCert = rootReq.CreateSelfSigned(notBefore, notAfter);

        // Create a leaf certificate signed by the root
        using var leafKey = RSA.Create(2048);
        var leafReq = new CertificateRequest(
            "CN=Test Leaf",
            leafKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, false));

        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName(sanDns);
        leafReq.CertificateExtensions.Add(sanBuilder.Build());

        var serialNumber = new byte[16];
        RandomNumberGenerator.Fill(serialNumber);
        var leafCert = leafReq.Create(rootCert, notBefore, notAfter, serialNumber);

        // Export and re-import the root so it's standalone (without private key)
        var rootExported = X509CertificateLoader.LoadCertificate(rootCert.Export(X509ContentType.Cert));

        return (rootExported, leafCert);
    }

    private static TrustedRoot CreateTrustRoot(X509Certificate2 rootCert)
    {
        return new TrustedRoot
        {
            CertificateAuthorities =
            [
                new CertificateAuthorityInfo
                {
                    Uri = "https://test.example.com",
                    CertChain = [rootCert.Export(X509ContentType.Cert)]
                }
            ]
        };
    }

    [Fact]
    public void ValidateChain_ValidCertAtSignatureTime_Succeeds()
    {
        var now = DateTimeOffset.UtcNow;
        var (root, leaf) = CreateTestCertificates(
            now.AddDays(-30), now.AddDays(30));

        var trustRoot = CreateTrustRoot(root);
        var validator = new TestCertificateValidator();

        var result = validator.ValidateChain(leaf, null, trustRoot, now);

        Assert.True(result.IsValid, result.FailureReason);
    }

    [Fact]
    public void ValidateChain_CertNotYetValid_Fails()
    {
        var now = DateTimeOffset.UtcNow;
        var (root, leaf) = CreateTestCertificates(
            now.AddDays(1), now.AddDays(30));

        var trustRoot = CreateTrustRoot(root);
        var validator = new TestCertificateValidator();

        // Signature time is before cert validity period
        var result = validator.ValidateChain(leaf, null, trustRoot, now);

        Assert.False(result.IsValid);
        Assert.NotNull(result.FailureReason);
    }

    [Fact]
    public void ValidateChain_CertExpired_Fails()
    {
        var now = DateTimeOffset.UtcNow;
        var (root, leaf) = CreateTestCertificates(
            now.AddDays(-60), now.AddDays(-1));

        var trustRoot = CreateTrustRoot(root);
        var validator = new TestCertificateValidator();

        // Signature time is after cert has expired
        var result = validator.ValidateChain(leaf, null, trustRoot, now);

        Assert.False(result.IsValid);
    }

    [Fact]
    public void ValidateChain_HybridTimeModel_ValidatesAtSignatureTime()
    {
        var now = DateTimeOffset.UtcNow;
        // Cert that was valid in the past
        var (root, leaf) = CreateTestCertificates(
            now.AddDays(-60), now.AddDays(-10));

        var trustRoot = CreateTrustRoot(root);
        var validator = new TestCertificateValidator();

        // Signature was made during the cert's validity window
        var signatureTime = now.AddDays(-30);
        var result = validator.ValidateChain(leaf, null, trustRoot, signatureTime);

        Assert.True(result.IsValid, result.FailureReason);
    }

    [Fact]
    public void ValidateChain_ExtractsSanFromLeaf()
    {
        var now = DateTimeOffset.UtcNow;
        var (root, leaf) = CreateTestCertificates(
            now.AddDays(-30), now.AddDays(30), "myapp.example.com");

        var trustRoot = CreateTrustRoot(root);
        var validator = new TestCertificateValidator();

        var result = validator.ValidateChain(leaf, null, trustRoot, now);

        Assert.True(result.IsValid, result.FailureReason);
        Assert.Equal("myapp.example.com", result.SubjectAlternativeName);
    }

    [Fact]
    public void ValidateChain_UntrustedRoot_Fails()
    {
        var now = DateTimeOffset.UtcNow;
        var (root, leaf) = CreateTestCertificates(
            now.AddDays(-30), now.AddDays(30));

        // Create a trust root with a DIFFERENT root CA
        using var otherKey = RSA.Create(2048);
        var otherReq = new CertificateRequest(
            "CN=Other Root CA",
            otherKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        otherReq.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true));
        var otherRoot = otherReq.CreateSelfSigned(now.AddDays(-30), now.AddDays(30));

        var trustRoot = CreateTrustRoot(otherRoot);
        var validator = new TestCertificateValidator();

        var result = validator.ValidateChain(leaf, null, trustRoot, now);

        Assert.False(result.IsValid);
    }

    /// <summary>
    /// Wrapper to access the internal DefaultCertificateValidator via the interface.
    /// </summary>
    private class TestCertificateValidator : ICertificateValidator
    {
        private readonly ICertificateValidator _inner;

        public TestCertificateValidator()
        {
            // Use reflection to instantiate the internal DefaultCertificateValidator
            var type = typeof(ICertificateValidator).Assembly.GetType("Sigstore.Verification.DefaultCertificateValidator")!;
            _inner = (ICertificateValidator)Activator.CreateInstance(type)!;
        }

        public CertificateValidationResult ValidateChain(
            X509Certificate2 leafCertificate,
            X509Certificate2Collection? chain,
            TrustedRoot trustRoot,
            DateTimeOffset signatureTime)
            => _inner.ValidateChain(leafCertificate, chain, trustRoot, signatureTime);
    }
}
