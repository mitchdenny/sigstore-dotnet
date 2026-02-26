using Sigstore.TrustRoot;
using Sigstore.Common;

namespace Sigstore.Tests.TrustRoot;

public class TrustedRootTests
{
    [Fact]
    public void DefaultMediaType_IsV02()
    {
        var root = new TrustedRoot();

        Assert.Equal("application/vnd.dev.sigstore.trustedroot.v0.2+json", root.MediaType);
    }

    [Fact]
    public void NewTrustedRoot_HasEmptyCollections()
    {
        var root = new TrustedRoot();

        Assert.Empty(root.TransparencyLogs);
        Assert.Empty(root.CertificateAuthorities);
        Assert.Empty(root.CtLogs);
        Assert.Empty(root.TimestampAuthorities);
    }

    [Fact]
    public void TransparencyLogInfo_SetsProperties()
    {
        var logInfo = new TransparencyLogInfo
        {
            BaseUrl = "https://rekor.sigstore.dev",
            HashAlgorithm = HashAlgorithmType.Sha2_256,
            PublicKeyBytes = [1, 2, 3],
            LogId = [4, 5, 6],
            Operator = "sigstore.dev"
        };

        Assert.Equal("https://rekor.sigstore.dev", logInfo.BaseUrl);
        Assert.Equal(HashAlgorithmType.Sha2_256, logInfo.HashAlgorithm);
        Assert.Equal("sigstore.dev", logInfo.Operator);
    }

    [Fact]
    public void CertificateAuthorityInfo_SetsProperties()
    {
        var caInfo = new CertificateAuthorityInfo
        {
            Uri = "https://fulcio.sigstore.dev",
            CertChain = [[1, 2, 3]],
            Operator = "sigstore.dev",
            ValidFrom = DateTimeOffset.Parse("2022-01-01T00:00:00Z"),
            ValidTo = DateTimeOffset.Parse("2030-01-01T00:00:00Z")
        };

        Assert.Equal("https://fulcio.sigstore.dev", caInfo.Uri);
        Assert.Single(caInfo.CertChain);
        Assert.NotNull(caInfo.ValidFrom);
        Assert.NotNull(caInfo.ValidTo);
    }
}
