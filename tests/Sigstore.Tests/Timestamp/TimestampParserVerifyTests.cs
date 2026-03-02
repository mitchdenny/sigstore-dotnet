using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Sigstore.Tests.Timestamp;

public class TimestampParserVerifyTests
{
    /// <summary>
    /// Creates a self-signed root CA certificate.
    /// </summary>
    private static X509Certificate2 CreateRootCa(string subjectName = "CN=Test Root CA")
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest(subjectName, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));
    }

    /// <summary>
    /// Creates an intermediate certificate signed by the given issuer.
    /// </summary>
    private static X509Certificate2 CreateIntermediate(X509Certificate2 issuer, string subjectName = "CN=Test Intermediate")
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest(subjectName, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        var serial = new byte[8];
        RandomNumberGenerator.Fill(serial);
        return req.Create(issuer, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5), serial)
            .CopyWithPrivateKey(key);
    }

    [Fact]
    public void Verify_WithChainedIntermediateCert_Succeeds()
    {
        // Arrange: build root CA -> intermediate chain
        using var rootCa = CreateRootCa();
        using var intermediate = CreateIntermediate(rootCa);

        var signature = new byte[] { 1, 2, 3, 4 };
        var messageImprint = SHA256.HashData(signature);

        var tsaAuthority = new CertificateAuthorityInfo
        {
            Uri = new Uri("https://tsa.example.com"),
            CertificateChain = new[] { new ReadOnlyMemory<byte>(rootCa.RawData) },
            ValidFrom = DateTimeOffset.UtcNow.AddDays(-1),
            ValidTo = DateTimeOffset.UtcNow.AddYears(10),
        };

        var info = new TimestampInfo
        {
            Timestamp = DateTimeOffset.UtcNow,
            HashAlgorithm = HashAlgorithmType.Sha256,
            MessageImprint = messageImprint,
            RawToken = ReadOnlyMemory<byte>.Empty,
            EmbeddedCertificates = new[] { new ReadOnlyMemory<byte>(intermediate.RawData) },
        };

        // Act
        var (verified, authorityUri) = TimestampParser.Verify(info, signature, new[] { tsaAuthority });

        // Assert
        Assert.True(verified);
        Assert.Equal(new Uri("https://tsa.example.com"), authorityUri);
    }

    [Fact]
    public void Verify_WithUnrelatedIntermediateCert_Fails()
    {
        // Arrange: root CA and an unrelated intermediate (signed by a different root)
        using var rootCa = CreateRootCa("CN=Trusted Root CA");
        using var unrelatedRoot = CreateRootCa("CN=Unrelated Root CA");
        using var unrelatedIntermediate = CreateIntermediate(unrelatedRoot, "CN=Unrelated Intermediate");

        var signature = new byte[] { 1, 2, 3, 4 };
        var messageImprint = SHA256.HashData(signature);

        var tsaAuthority = new CertificateAuthorityInfo
        {
            Uri = new Uri("https://tsa.example.com"),
            CertificateChain = new[] { new ReadOnlyMemory<byte>(rootCa.RawData) },
            ValidFrom = DateTimeOffset.UtcNow.AddDays(-1),
            ValidTo = DateTimeOffset.UtcNow.AddYears(10),
        };

        var info = new TimestampInfo
        {
            Timestamp = DateTimeOffset.UtcNow,
            HashAlgorithm = HashAlgorithmType.Sha256,
            MessageImprint = messageImprint,
            RawToken = ReadOnlyMemory<byte>.Empty,
            EmbeddedCertificates = new[] { new ReadOnlyMemory<byte>(unrelatedIntermediate.RawData) },
        };

        // Act
        var (verified, authorityUri) = TimestampParser.Verify(info, signature, new[] { tsaAuthority });

        // Assert
        Assert.False(verified);
        Assert.Null(authorityUri);
    }

    [Fact]
    public void Verify_ReturnsMatchedAuthorityUri()
    {
        // Arrange: two TSAs, only the second one matches
        using var rootCa1 = CreateRootCa("CN=Root CA 1");
        using var rootCa2 = CreateRootCa("CN=Root CA 2");
        using var intermediate2 = CreateIntermediate(rootCa2, "CN=Intermediate 2");

        var signature = new byte[] { 5, 6, 7, 8 };
        var messageImprint = SHA256.HashData(signature);

        var tsaAuthorities = new[]
        {
            new CertificateAuthorityInfo
            {
                Uri = new Uri("https://tsa1.example.com"),
                CertificateChain = new[] { new ReadOnlyMemory<byte>(rootCa1.RawData) },
                ValidFrom = DateTimeOffset.UtcNow.AddDays(-1),
                ValidTo = DateTimeOffset.UtcNow.AddYears(10),
            },
            new CertificateAuthorityInfo
            {
                Uri = new Uri("https://tsa2.example.com"),
                CertificateChain = new[] { new ReadOnlyMemory<byte>(rootCa2.RawData) },
                ValidFrom = DateTimeOffset.UtcNow.AddDays(-1),
                ValidTo = DateTimeOffset.UtcNow.AddYears(10),
            },
        };

        var info = new TimestampInfo
        {
            Timestamp = DateTimeOffset.UtcNow,
            HashAlgorithm = HashAlgorithmType.Sha256,
            MessageImprint = messageImprint,
            RawToken = ReadOnlyMemory<byte>.Empty,
            EmbeddedCertificates = new[] { new ReadOnlyMemory<byte>(intermediate2.RawData) },
        };

        // Act
        var (verified, authorityUri) = TimestampParser.Verify(info, signature, tsaAuthorities);

        // Assert
        Assert.True(verified);
        Assert.Equal(new Uri("https://tsa2.example.com"), authorityUri);
    }
}
