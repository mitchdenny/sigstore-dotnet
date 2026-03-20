using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Sigstore.Tests.Verification;

public class SanParserTests
{
    [Fact]
    public void ExtractSan_WithUriSan_ReturnsUri()
    {
        using var cert = CreateCertWithUri("https://github.com/myorg/myrepo/.github/workflows/ci.yml@refs/heads/main");

        var san = SanParser.ExtractSan(cert);

        Assert.Equal("https://github.com/myorg/myrepo/.github/workflows/ci.yml@refs/heads/main", san);
    }

    [Fact]
    public void ExtractSan_WithEmailSan_ReturnsEmail()
    {
        using var cert = CreateCertWithEmail("user@example.com");

        var san = SanParser.ExtractSan(cert);

        Assert.Equal("user@example.com", san);
    }

    [Fact]
    public void ExtractSan_WithDnsSan_ReturnsDns()
    {
        using var cert = CreateCertWithDns("myapp.example.com");

        var san = SanParser.ExtractSan(cert);

        Assert.Equal("myapp.example.com", san);
    }

    [Fact]
    public void ExtractSan_WithNoSanExtension_ReturnsNull()
    {
        using var cert = CreateCertWithoutSan();

        var san = SanParser.ExtractSan(cert);

        Assert.Null(san);
    }

    [Fact]
    public void ExtractSan_WithEmailAndUri_PrefersEmail()
    {
        using var cert = CreateCertWithEmailAndUri("user@example.com", "https://example.com");

        var san = SanParser.ExtractSan(cert);

        Assert.Equal("user@example.com", san);
    }

    [Fact]
    public void ExtractSan_WithUriAndDns_PrefersUri()
    {
        using var cert = CreateCertWithUriAndDns("https://example.com/path", "example.com");

        var san = SanParser.ExtractSan(cert);

        Assert.Equal("https://example.com/path", san);
    }

    [Fact]
    public void ExtractSan_WithGitHubActionsUri_ReturnsFullWorkflowUri()
    {
        var workflowUri = "https://github.com/microsoft/playwright-cli/.github/workflows/publish.yml@refs/tags/v0.1.1";
        using var cert = CreateCertWithUri(workflowUri);

        var san = SanParser.ExtractSan(cert);

        Assert.Equal(workflowUri, san);
    }

    [Fact]
    public void ExtractSan_WithMalformedRawData_Throws()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=Test", key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(
            new X509Extension(new Oid("2.5.29.17"), [0xFF, 0xFE, 0xFD], false));
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));

        Assert.ThrowsAny<AsnContentException>(() => SanParser.ExtractSan(cert));
    }

    [Fact]
    public void ExtractSan_WithTruncatedData_Throws()
    {
        // A SEQUENCE tag (0x30) with length 10 but only 2 bytes of content
        byte[] truncated = [0x30, 0x0A, 0x86, 0x04];
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=Test", key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509Extension(new Oid("2.5.29.17"), truncated, false));
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));

        Assert.ThrowsAny<AsnContentException>(() => SanParser.ExtractSan(cert));
    }

    [Fact]
    public void ExtractSan_WithEmptySequence_ReturnsNull()
    {
        // Valid DER: SEQUENCE with zero content
        byte[] emptySeq = [0x30, 0x00];
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=Test", key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509Extension(new Oid("2.5.29.17"), emptySeq, false));
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));

        var san = SanParser.ExtractSan(cert);

        Assert.Null(san);
    }

    [Fact]
    public void ExtractSan_WithOnlyIpAddress_ReturnsNull()
    {
        // SAN with only an iPAddress [7] entry — not a type we extract
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=Test", key, HashAlgorithmName.SHA256);
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddIpAddress(System.Net.IPAddress.Parse("192.168.1.1"));
        req.CertificateExtensions.Add(sanBuilder.Build());
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));

        var san = SanParser.ExtractSan(cert);

        Assert.Null(san);
    }

    [Fact]
    public void ExtractSan_WithMultipleUris_ReturnsFirst()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=Test", key, HashAlgorithmName.SHA256);
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddUri(new Uri("https://first.example.com/path"));
        sanBuilder.AddUri(new Uri("https://second.example.com/path"));
        req.CertificateExtensions.Add(sanBuilder.Build());
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));

        var san = SanParser.ExtractSan(cert);

        Assert.Equal("https://first.example.com/path", san);
    }

    private static X509Certificate2 CreateCertWithUri(string uri)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=Test", key, HashAlgorithmName.SHA256);
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddUri(new Uri(uri));
        req.CertificateExtensions.Add(sanBuilder.Build());
        return req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));
    }

    private static X509Certificate2 CreateCertWithEmail(string email)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=Test", key, HashAlgorithmName.SHA256);
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddEmailAddress(email);
        req.CertificateExtensions.Add(sanBuilder.Build());
        return req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));
    }

    private static X509Certificate2 CreateCertWithDns(string dns)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=Test", key, HashAlgorithmName.SHA256);
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName(dns);
        req.CertificateExtensions.Add(sanBuilder.Build());
        return req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));
    }

    private static X509Certificate2 CreateCertWithoutSan()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=Test", key, HashAlgorithmName.SHA256);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));
    }

    private static X509Certificate2 CreateCertWithEmailAndUri(string email, string uri)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=Test", key, HashAlgorithmName.SHA256);
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddEmailAddress(email);
        sanBuilder.AddUri(new Uri(uri));
        req.CertificateExtensions.Add(sanBuilder.Build());
        return req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));
    }

    private static X509Certificate2 CreateCertWithUriAndDns(string uri, string dns)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=Test", key, HashAlgorithmName.SHA256);
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddUri(new Uri(uri));
        sanBuilder.AddDnsName(dns);
        req.CertificateExtensions.Add(sanBuilder.Build());
        return req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));
    }
}
