using System.Text;
using System.Text.Json;
using Sigstore;

namespace Sigstore.Tests.Verification;

[TestClass]
public class VerificationResultTests
{
    [TestMethod]
    public void VerificationResult_CanRepresentSuccess()
    {
        var result = new VerificationResult
        {
            SignerIdentity = new VerifiedIdentity
            {
                SubjectAlternativeName = "user@example.com",
                Issuer = "https://accounts.google.com"
            },
            VerifiedTimestamps =
            [
                new VerifiedTimestamp
                {
                    Source = TimestampSource.TransparencyLog,
                    Timestamp = DateTimeOffset.UtcNow,
                    AuthorityUri = new Uri("https://rekor.sigstore.dev")
                }
            ]
        };

        Assert.IsNotNull(result.SignerIdentity);
        Assert.IsNull(result.FailureReason);
        TestSeq.Single(result.VerifiedTimestamps);
    }

    [TestMethod]
    public void VerificationResult_CanRepresentFailure()
    {
        var result = new VerificationResult
        {
            FailureReason = "Certificate chain validation failed: expired certificate"
        };

        Assert.IsNull(result.SignerIdentity);
        Assert.IsNotNull(result.FailureReason);
    }

    [TestMethod]
    public void VerificationException_ContainsMessage()
    {
        var exception = new VerificationException("Certificate expired");

        Assert.AreEqual("Certificate expired", exception.Message);
    }

    [TestMethod]
    public void VerificationException_CanWrapInnerException()
    {
        var inner = new InvalidOperationException("inner");
        var exception = new VerificationException("Verification failed", inner);

        Assert.AreSame(inner, exception.InnerException);
    }

    [TestMethod]
    public void TimestampSource_HasExpectedValues()
    {
        Assert.AreEqual(0, (int)TimestampSource.TimestampAuthority);
        Assert.AreEqual(1, (int)TimestampSource.TransparencyLog);
    }

    [TestMethod]
    public void VerificationResult_Statement_IsNullByDefault()
    {
        var result = new VerificationResult();
        Assert.IsNull(result.Statement);
    }

    [TestMethod]
    public void VerificationResult_Statement_CanBePopulated()
    {
        var statement = InTotoStatement.Parse("""
        {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{ "name": "test", "digest": { "sha256": "abc" } }],
            "predicate": {}
        }
        """);

        var result = new VerificationResult
        {
            Statement = statement
        };

        Assert.IsNotNull(result.Statement);
        Assert.AreEqual("https://slsa.dev/provenance/v1", result.Statement!.PredicateType);
    }

    [TestMethod]
    public void VerifiedIdentity_Extensions_IsNullByDefault()
    {
        var identity = new VerifiedIdentity
        {
            SubjectAlternativeName = "user@example.com",
            Issuer = "https://accounts.google.com"
        };

        Assert.IsNull(identity.Extensions);
    }

    [TestMethod]
    public void VerifiedIdentity_Extensions_CanBePopulated()
    {
        var identity = new VerifiedIdentity
        {
            SubjectAlternativeName = "https://github.com/myorg/myrepo/.github/workflows/release.yml@refs/heads/main",
            Issuer = "https://token.actions.githubusercontent.com",
            Extensions = new FulcioCertificateExtensions
            {
                Issuer = "https://token.actions.githubusercontent.com",
                SourceRepositoryUri = "https://github.com/myorg/myrepo",
                RunnerEnvironment = "github-hosted",
                BuildTrigger = "push"
            }
        };

        Assert.IsNotNull(identity.Extensions);
        Assert.AreEqual("https://github.com/myorg/myrepo", identity.Extensions!.SourceRepositoryUri);
        Assert.AreEqual("github-hosted", identity.Extensions.RunnerEnvironment);
        Assert.AreEqual("push", identity.Extensions.BuildTrigger);
    }
}
