using System.Text;
using System.Text.Json;
using Sigstore;

namespace Sigstore.Tests.Verification;

public class VerificationResultTests
{
    [Fact]
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

        Assert.NotNull(result.SignerIdentity);
        Assert.Null(result.FailureReason);
        Assert.Single(result.VerifiedTimestamps);
    }

    [Fact]
    public void VerificationResult_CanRepresentFailure()
    {
        var result = new VerificationResult
        {
            FailureReason = "Certificate chain validation failed: expired certificate"
        };

        Assert.Null(result.SignerIdentity);
        Assert.NotNull(result.FailureReason);
    }

    [Fact]
    public void VerificationException_ContainsMessage()
    {
        var exception = new VerificationException("Certificate expired");

        Assert.Equal("Certificate expired", exception.Message);
    }

    [Fact]
    public void VerificationException_CanWrapInnerException()
    {
        var inner = new InvalidOperationException("inner");
        var exception = new VerificationException("Verification failed", inner);

        Assert.Same(inner, exception.InnerException);
    }

    [Fact]
    public void TimestampSource_HasExpectedValues()
    {
        Assert.Equal(0, (int)TimestampSource.TimestampAuthority);
        Assert.Equal(1, (int)TimestampSource.TransparencyLog);
    }

    [Fact]
    public void VerificationResult_Statement_IsNullByDefault()
    {
        var result = new VerificationResult();
        Assert.Null(result.Statement);
    }

    [Fact]
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

        Assert.NotNull(result.Statement);
        Assert.Equal("https://slsa.dev/provenance/v1", result.Statement!.PredicateType);
    }

    [Fact]
    public void VerifiedIdentity_Extensions_IsNullByDefault()
    {
        var identity = new VerifiedIdentity
        {
            SubjectAlternativeName = "user@example.com",
            Issuer = "https://accounts.google.com"
        };

        Assert.Null(identity.Extensions);
    }

    [Fact]
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

        Assert.NotNull(identity.Extensions);
        Assert.Equal("https://github.com/myorg/myrepo", identity.Extensions!.SourceRepositoryUri);
        Assert.Equal("github-hosted", identity.Extensions.RunnerEnvironment);
        Assert.Equal("push", identity.Extensions.BuildTrigger);
    }
}
