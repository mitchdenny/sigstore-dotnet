using Sigstore.Verification;

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
                    AuthorityUri = "https://rekor.sigstore.dev"
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
}
