using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Sigstore;

namespace Sigstore.Tests.Verification;

public class FulcioCertificateExtensionsTests
{
    /// <summary>
    /// Helper to create a DER-encoded UTF8String for use as an X.509 extension value.
    /// </summary>
    private static byte[] DerUtf8String(string value)
    {
        var utf8Bytes = Encoding.UTF8.GetBytes(value);
        // Tag 0x0C = UTF8String, then length byte, then content
        var result = new byte[2 + utf8Bytes.Length];
        result[0] = 0x0C;
        result[1] = (byte)utf8Bytes.Length;
        utf8Bytes.CopyTo(result, 2);
        return result;
    }

    /// <summary>
    /// Creates a self-signed certificate with custom extensions for testing.
    /// </summary>
    private static X509Certificate2 CreateCertWithExtensions(params (string oid, byte[] value)[] extensions)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=test", key, HashAlgorithmName.SHA256);

        foreach (var (oid, value) in extensions)
        {
            req.CertificateExtensions.Add(new X509Extension(new Oid(oid), value, false));
        }

        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));
        return cert;
    }

    [Fact]
    public void FromCertificate_ParsesIssuerV2()
    {
        var cert = CreateCertWithExtensions(
            (FulcioCertificateExtensions.OidIssuerV2, DerUtf8String("https://token.actions.githubusercontent.com")));

        var ext = FulcioCertificateExtensions.FromCertificate(cert);

        Assert.Equal("https://token.actions.githubusercontent.com", ext.Issuer);
    }

    [Fact]
    public void FromCertificate_ParsesIssuerV1_RawBytes()
    {
        // V1 uses raw bytes, not DER-encoded
        var rawBytes = Encoding.UTF8.GetBytes("https://accounts.google.com");
        var cert = CreateCertWithExtensions(
            (FulcioCertificateExtensions.OidIssuerV1, rawBytes));

        var ext = FulcioCertificateExtensions.FromCertificate(cert);

        Assert.Equal("https://accounts.google.com", ext.Issuer);
    }

    [Fact]
    public void FromCertificate_IssuerV2_TakesPrecedenceOverV1()
    {
        var cert = CreateCertWithExtensions(
            (FulcioCertificateExtensions.OidIssuerV1, Encoding.UTF8.GetBytes("v1-issuer")),
            (FulcioCertificateExtensions.OidIssuerV2, DerUtf8String("v2-issuer")));

        var ext = FulcioCertificateExtensions.FromCertificate(cert);

        Assert.Equal("v2-issuer", ext.Issuer);
    }

    [Fact]
    public void FromCertificate_ParsesSourceRepositoryUri()
    {
        var cert = CreateCertWithExtensions(
            (FulcioCertificateExtensions.OidSourceRepositoryUri, DerUtf8String("https://github.com/myorg/myrepo")));

        var ext = FulcioCertificateExtensions.FromCertificate(cert);

        Assert.Equal("https://github.com/myorg/myrepo", ext.SourceRepositoryUri);
    }

    [Fact]
    public void FromCertificate_ParsesSourceRepositoryDigest()
    {
        var cert = CreateCertWithExtensions(
            (FulcioCertificateExtensions.OidSourceRepositoryDigest, DerUtf8String("abc123def456")));

        var ext = FulcioCertificateExtensions.FromCertificate(cert);

        Assert.Equal("abc123def456", ext.SourceRepositoryDigest);
    }

    [Fact]
    public void FromCertificate_ParsesSourceRepositoryRef()
    {
        var cert = CreateCertWithExtensions(
            (FulcioCertificateExtensions.OidSourceRepositoryRef, DerUtf8String("refs/heads/main")));

        var ext = FulcioCertificateExtensions.FromCertificate(cert);

        Assert.Equal("refs/heads/main", ext.SourceRepositoryRef);
    }

    [Fact]
    public void FromCertificate_ParsesSourceRepositoryIdentifier()
    {
        var cert = CreateCertWithExtensions(
            (FulcioCertificateExtensions.OidSourceRepositoryIdentifier, DerUtf8String("12345")));

        var ext = FulcioCertificateExtensions.FromCertificate(cert);

        Assert.Equal("12345", ext.SourceRepositoryIdentifier);
    }

    [Fact]
    public void FromCertificate_ParsesSourceRepositoryOwnerUri()
    {
        var cert = CreateCertWithExtensions(
            (FulcioCertificateExtensions.OidSourceRepositoryOwnerUri, DerUtf8String("https://github.com/myorg")));

        var ext = FulcioCertificateExtensions.FromCertificate(cert);

        Assert.Equal("https://github.com/myorg", ext.SourceRepositoryOwnerUri);
    }

    [Fact]
    public void FromCertificate_ParsesSourceRepositoryOwnerIdentifier()
    {
        var cert = CreateCertWithExtensions(
            (FulcioCertificateExtensions.OidSourceRepositoryOwnerIdentifier, DerUtf8String("67890")));

        var ext = FulcioCertificateExtensions.FromCertificate(cert);

        Assert.Equal("67890", ext.SourceRepositoryOwnerIdentifier);
    }

    [Fact]
    public void FromCertificate_ParsesBuildSignerUri()
    {
        var cert = CreateCertWithExtensions(
            (FulcioCertificateExtensions.OidBuildSignerUri, DerUtf8String("https://github.com/myorg/myrepo/.github/workflows/release.yml@refs/heads/main")));

        var ext = FulcioCertificateExtensions.FromCertificate(cert);

        Assert.Equal("https://github.com/myorg/myrepo/.github/workflows/release.yml@refs/heads/main", ext.BuildSignerUri);
    }

    [Fact]
    public void FromCertificate_ParsesBuildSignerDigest()
    {
        var cert = CreateCertWithExtensions(
            (FulcioCertificateExtensions.OidBuildSignerDigest, DerUtf8String("sha256:abcdef")));

        var ext = FulcioCertificateExtensions.FromCertificate(cert);

        Assert.Equal("sha256:abcdef", ext.BuildSignerDigest);
    }

    [Fact]
    public void FromCertificate_ParsesRunnerEnvironment()
    {
        var cert = CreateCertWithExtensions(
            (FulcioCertificateExtensions.OidRunnerEnvironment, DerUtf8String("github-hosted")));

        var ext = FulcioCertificateExtensions.FromCertificate(cert);

        Assert.Equal("github-hosted", ext.RunnerEnvironment);
    }

    [Fact]
    public void FromCertificate_ParsesBuildConfigUri()
    {
        var cert = CreateCertWithExtensions(
            (FulcioCertificateExtensions.OidBuildConfigUri, DerUtf8String("https://github.com/myorg/myrepo/.github/workflows/build.yml@refs/tags/v1.0")));

        var ext = FulcioCertificateExtensions.FromCertificate(cert);

        Assert.Equal("https://github.com/myorg/myrepo/.github/workflows/build.yml@refs/tags/v1.0", ext.BuildConfigUri);
    }

    [Fact]
    public void FromCertificate_ParsesBuildConfigDigest()
    {
        var cert = CreateCertWithExtensions(
            (FulcioCertificateExtensions.OidBuildConfigDigest, DerUtf8String("digest123")));

        var ext = FulcioCertificateExtensions.FromCertificate(cert);

        Assert.Equal("digest123", ext.BuildConfigDigest);
    }

    [Fact]
    public void FromCertificate_ParsesBuildTrigger()
    {
        var cert = CreateCertWithExtensions(
            (FulcioCertificateExtensions.OidBuildTrigger, DerUtf8String("push")));

        var ext = FulcioCertificateExtensions.FromCertificate(cert);

        Assert.Equal("push", ext.BuildTrigger);
    }

    [Fact]
    public void FromCertificate_ParsesRunInvocationUri()
    {
        var cert = CreateCertWithExtensions(
            (FulcioCertificateExtensions.OidRunInvocationUri, DerUtf8String("https://github.com/myorg/myrepo/actions/runs/123456")));

        var ext = FulcioCertificateExtensions.FromCertificate(cert);

        Assert.Equal("https://github.com/myorg/myrepo/actions/runs/123456", ext.RunInvocationUri);
    }

    [Fact]
    public void FromCertificate_ParsesSourceRepositoryVisibilityAtSigning()
    {
        var cert = CreateCertWithExtensions(
            (FulcioCertificateExtensions.OidSourceRepositoryVisibilityAtSigning, DerUtf8String("public")));

        var ext = FulcioCertificateExtensions.FromCertificate(cert);

        Assert.Equal("public", ext.SourceRepositoryVisibilityAtSigning);
    }

    [Fact]
    public void FromCertificate_ParsesDeprecatedGithubWorkflowTrigger()
    {
        var cert = CreateCertWithExtensions(
            (FulcioCertificateExtensions.OidGithubWorkflowTrigger, Encoding.UTF8.GetBytes("push")));

        var ext = FulcioCertificateExtensions.FromCertificate(cert);

        Assert.Equal("push", ext.GithubWorkflowTrigger);
    }

    [Fact]
    public void FromCertificate_ParsesDeprecatedGithubWorkflowSha()
    {
        var cert = CreateCertWithExtensions(
            (FulcioCertificateExtensions.OidGithubWorkflowSha, Encoding.UTF8.GetBytes("abc123")));

        var ext = FulcioCertificateExtensions.FromCertificate(cert);

        Assert.Equal("abc123", ext.GithubWorkflowSha);
    }

    [Fact]
    public void FromCertificate_ParsesDeprecatedGithubWorkflowName()
    {
        var cert = CreateCertWithExtensions(
            (FulcioCertificateExtensions.OidGithubWorkflowName, Encoding.UTF8.GetBytes("release")));

        var ext = FulcioCertificateExtensions.FromCertificate(cert);

        Assert.Equal("release", ext.GithubWorkflowName);
    }

    [Fact]
    public void FromCertificate_ParsesDeprecatedGithubWorkflowRepository()
    {
        var cert = CreateCertWithExtensions(
            (FulcioCertificateExtensions.OidGithubWorkflowRepository, Encoding.UTF8.GetBytes("myorg/myrepo")));

        var ext = FulcioCertificateExtensions.FromCertificate(cert);

        Assert.Equal("myorg/myrepo", ext.GithubWorkflowRepository);
    }

    [Fact]
    public void FromCertificate_ParsesDeprecatedGithubWorkflowRef()
    {
        var cert = CreateCertWithExtensions(
            (FulcioCertificateExtensions.OidGithubWorkflowRef, Encoding.UTF8.GetBytes("refs/heads/main")));

        var ext = FulcioCertificateExtensions.FromCertificate(cert);

        Assert.Equal("refs/heads/main", ext.GithubWorkflowRef);
    }

    [Fact]
    public void FromCertificate_HandlesNoFulcioExtensions()
    {
        // Certificate with no Fulcio extensions at all
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=test", key, HashAlgorithmName.SHA256);
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));

        var ext = FulcioCertificateExtensions.FromCertificate(cert);

        Assert.Null(ext.Issuer);
        Assert.Null(ext.SourceRepositoryUri);
        Assert.Null(ext.BuildSignerUri);
        Assert.Null(ext.RunnerEnvironment);
        Assert.Null(ext.BuildTrigger);
    }

    [Fact]
    public void FromCertificate_ParsesAllExtensionsTogether()
    {
        var cert = CreateCertWithExtensions(
            (FulcioCertificateExtensions.OidIssuerV2, DerUtf8String("https://token.actions.githubusercontent.com")),
            (FulcioCertificateExtensions.OidSourceRepositoryUri, DerUtf8String("https://github.com/sigstore/sigstore-dotnet")),
            (FulcioCertificateExtensions.OidSourceRepositoryRef, DerUtf8String("refs/tags/v1.0.0")),
            (FulcioCertificateExtensions.OidBuildSignerUri, DerUtf8String("https://github.com/sigstore/sigstore-dotnet/.github/workflows/release.yml@refs/tags/v1.0.0")),
            (FulcioCertificateExtensions.OidRunnerEnvironment, DerUtf8String("github-hosted")),
            (FulcioCertificateExtensions.OidBuildTrigger, DerUtf8String("push")),
            (FulcioCertificateExtensions.OidSourceRepositoryVisibilityAtSigning, DerUtf8String("public")));

        var ext = FulcioCertificateExtensions.FromCertificate(cert);

        Assert.Equal("https://token.actions.githubusercontent.com", ext.Issuer);
        Assert.Equal("https://github.com/sigstore/sigstore-dotnet", ext.SourceRepositoryUri);
        Assert.Equal("refs/tags/v1.0.0", ext.SourceRepositoryRef);
        Assert.Equal("https://github.com/sigstore/sigstore-dotnet/.github/workflows/release.yml@refs/tags/v1.0.0", ext.BuildSignerUri);
        Assert.Equal("github-hosted", ext.RunnerEnvironment);
        Assert.Equal("push", ext.BuildTrigger);
        Assert.Equal("public", ext.SourceRepositoryVisibilityAtSigning);
    }

    [Fact]
    public void ReadDerString_ParsesUtf8String()
    {
        var value = FulcioCertificateExtensions.ReadDerString(DerUtf8String("hello world"));
        Assert.Equal("hello world", value);
    }

    [Fact]
    public void ReadDerString_ParsesIA5String()
    {
        var utf8Bytes = Encoding.UTF8.GetBytes("test-value");
        var result = new byte[2 + utf8Bytes.Length];
        result[0] = 0x16; // IA5String tag
        result[1] = (byte)utf8Bytes.Length;
        utf8Bytes.CopyTo(result, 2);

        var value = FulcioCertificateExtensions.ReadDerString(result);
        Assert.Equal("test-value", value);
    }

    [Fact]
    public void ReadDerString_FallsBackToRawUtf8()
    {
        // Not a recognized DER tag — falls back to raw UTF-8
        var rawBytes = Encoding.UTF8.GetBytes("raw-value");
        var value = FulcioCertificateExtensions.ReadDerString(rawBytes);
        Assert.Equal("raw-value", value);
    }

    [Fact]
    public void ReadDerString_ReturnsNullForEmptyInput()
    {
        var value = FulcioCertificateExtensions.ReadDerString([]);
        Assert.Null(value);
    }

    [Fact]
    public void ReadDerString_ReturnsNullForSingleByte()
    {
        var value = FulcioCertificateExtensions.ReadDerString([0x0C]);
        Assert.Null(value);
    }
}
