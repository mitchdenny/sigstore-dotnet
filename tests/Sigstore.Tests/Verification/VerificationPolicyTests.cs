using Sigstore;

namespace Sigstore.Tests.Verification;

[TestClass]
public class VerificationPolicyTests
{
    [TestMethod]
    public void DefaultPolicy_RequiresTransparencyLog()
    {
        var policy = new VerificationPolicy();

        Assert.IsTrue(policy.RequireTransparencyLog);
        Assert.AreEqual(1, policy.TransparencyLogThreshold);
    }

    [TestMethod]
    public void DefaultPolicy_RequiresSignedCertificateTimestamps()
    {
        var policy = new VerificationPolicy();

        Assert.IsTrue(policy.RequireSignedCertificateTimestamps);
    }

    [TestMethod]
    public void DefaultPolicy_DoesNotRequireSignedTimestamps()
    {
        var policy = new VerificationPolicy();

        Assert.IsFalse(policy.RequireSignedTimestamps);
    }

    [TestMethod]
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

        Assert.AreEqual("user@example.com", policy.CertificateIdentity.SubjectAlternativeName);
        Assert.AreEqual("https://accounts.google.com", policy.CertificateIdentity.Issuer);
    }
}
