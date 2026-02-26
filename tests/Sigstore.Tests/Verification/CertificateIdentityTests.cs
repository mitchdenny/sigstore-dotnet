using Sigstore.Verification;

namespace Sigstore.Tests.Verification;

public class CertificateIdentityTests
{
    [Fact]
    public void ForGitHubActions_SetsDefaultIssuer()
    {
        var identity = CertificateIdentity.ForGitHubActions("owner/repo");

        Assert.Equal("https://token.actions.githubusercontent.com", identity.Issuer);
    }

    [Fact]
    public void ForGitHubActions_SetsRepositoryPattern()
    {
        var identity = CertificateIdentity.ForGitHubActions("sigstore/sigstore-dotnet");

        Assert.NotNull(identity.SubjectAlternativeNamePattern);
        Assert.Contains("sigstore/sigstore-dotnet", identity.SubjectAlternativeNamePattern);
    }

    [Fact]
    public void ForGitHubActions_WithCustomIssuer()
    {
        var identity = CertificateIdentity.ForGitHubActions(
            "owner/repo",
            issuer: "https://custom-issuer.example.com");

        Assert.Equal("https://custom-issuer.example.com", identity.Issuer);
    }

    [Fact]
    public void ForGitHubActions_WithWorkflowRef_IncludesRefInPattern()
    {
        var identity = CertificateIdentity.ForGitHubActions(
            "owner/repo",
            workflowRef: "refs/heads/main");

        Assert.NotNull(identity.SubjectAlternativeNamePattern);
        Assert.Contains("refs/heads/main", identity.SubjectAlternativeNamePattern);
    }

    [Fact]
    public void ForGitHubActions_WithoutWorkflowRef_UsesWildcardPattern()
    {
        var identity = CertificateIdentity.ForGitHubActions("owner/repo");

        Assert.NotNull(identity.SubjectAlternativeNamePattern);
        Assert.Null(identity.SubjectAlternativeName);
    }

    [Fact]
    public void ExactMatch_SetsSubjectAlternativeName()
    {
        var identity = new CertificateIdentity
        {
            SubjectAlternativeName = "user@example.com",
            Issuer = "https://accounts.google.com"
        };

        Assert.Equal("user@example.com", identity.SubjectAlternativeName);
        Assert.Null(identity.SubjectAlternativeNamePattern);
    }

    [Fact]
    public void RegexMatch_SetsPattern()
    {
        var identity = new CertificateIdentity
        {
            SubjectAlternativeNamePattern = @".*@example\.com",
            Issuer = "https://accounts.google.com"
        };

        Assert.Null(identity.SubjectAlternativeName);
        Assert.NotNull(identity.SubjectAlternativeNamePattern);
    }
}
