using Sigstore.Verification;

namespace Sigstore.Tests.Verification;

public class VerificationPolicyTests
{
    [Fact]
    public void DefaultPolicy_RequiresTransparencyLog()
    {
        var policy = new VerificationPolicy();

        Assert.True(policy.RequireTransparencyLog);
        Assert.Equal(1, policy.TransparencyLogThreshold);
    }

    [Fact]
    public void DefaultPolicy_RequiresSignedCertificateTimestamps()
    {
        var policy = new VerificationPolicy();

        Assert.True(policy.RequireSignedCertificateTimestamps);
    }

    [Fact]
    public void DefaultPolicy_DoesNotRequireSignedTimestamps()
    {
        var policy = new VerificationPolicy();

        Assert.False(policy.RequireSignedTimestamps);
    }

    [Fact]
    public void DefaultPolicy_IsNotOffline()
    {
        var policy = new VerificationPolicy();

        Assert.False(policy.OfflineVerification);
    }

    [Fact]
    public void Policy_CanSetCertificateIdentity()
    {
        var policy = new VerificationPolicy
        {
            CertificateIdentity = new CertificateIdentity
            {
                SubjectAlternativeName = "user@example.com",
                Issuer = "https://accounts.google.com"
            }
        };

        Assert.Equal("user@example.com", policy.CertificateIdentity.SubjectAlternativeName);
        Assert.Equal("https://accounts.google.com", policy.CertificateIdentity.Issuer);
    }
}
