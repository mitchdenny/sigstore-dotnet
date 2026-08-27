using Sigstore;

namespace Sigstore.Tests.Verification;

[TestClass]
public class CertificateIdentityTests
{
    [TestMethod]
    public void ForGitHubActions_SetsDefaultIssuer()
    {
        var identity = CertificateIdentity.ForGitHubActions("owner", "repo");

        Assert.AreEqual("https://token.actions.githubusercontent.com", identity.Issuer);
    }

    [TestMethod]
    public void ForGitHubActions_SetsRepositoryPattern()
    {
        var identity = CertificateIdentity.ForGitHubActions("sigstore", "sigstore-dotnet");

        Assert.IsNotNull(identity.SubjectAlternativeNamePattern);
        Assert.Contains("sigstore/sigstore-dotnet", identity.SubjectAlternativeNamePattern);
    }

    [TestMethod]
    public void ForGitHubActions_WithCustomIssuer()
    {
        var identity = CertificateIdentity.ForGitHubActions(
            "owner", "repo",
            issuer: "https://custom-issuer.example.com");

        Assert.AreEqual("https://custom-issuer.example.com", identity.Issuer);
    }

    [TestMethod]
    public void ForGitHubActions_WithWorkflowRef_IncludesRefInPattern()
    {
        var identity = CertificateIdentity.ForGitHubActions(
            "owner", "repo",
            workflowRef: "refs/heads/main");

        Assert.IsNotNull(identity.SubjectAlternativeNamePattern);
        Assert.Contains("refs/heads/main", identity.SubjectAlternativeNamePattern);
    }

    [TestMethod]
    public void ForGitHubActions_WithoutWorkflowRef_UsesWildcardPattern()
    {
        var identity = CertificateIdentity.ForGitHubActions("owner", "repo");

        Assert.IsNotNull(identity.SubjectAlternativeNamePattern);
        Assert.IsNull(identity.SubjectAlternativeName);
    }

    [TestMethod]
    public void ExactMatch_SetsSubjectAlternativeName()
    {
        var identity = new CertificateIdentity
        {
            SubjectAlternativeName = "user@example.com",
            Issuer = "https://accounts.google.com"
        };

        Assert.AreEqual("user@example.com", identity.SubjectAlternativeName);
        Assert.IsNull(identity.SubjectAlternativeNamePattern);
    }

    [TestMethod]
    public void RegexMatch_SetsPattern()
    {
        var identity = new CertificateIdentity
        {
            SubjectAlternativeNamePattern = @".*@example\.com",
            Issuer = "https://accounts.google.com"
        };

        Assert.IsNull(identity.SubjectAlternativeName);
        Assert.IsNotNull(identity.SubjectAlternativeNamePattern);
    }
}
