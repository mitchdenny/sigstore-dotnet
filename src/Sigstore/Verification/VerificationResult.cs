namespace Sigstore.Verification;

/// <summary>
/// The result of a successful Sigstore bundle verification.
/// </summary>
public class VerificationResult
{
    /// <summary>
    /// The verified signer identity from the certificate.
    /// </summary>
    public VerifiedIdentity? SignerIdentity { get; init; }

    /// <summary>
    /// The verified timestamps (from TSA and/or transparency log).
    /// </summary>
    public IReadOnlyList<VerifiedTimestamp> VerifiedTimestamps { get; init; } = [];

    /// <summary>
    /// The failure reason, if verification failed. Null on success.
    /// </summary>
    public string? FailureReason { get; init; }
}

/// <summary>
/// The verified identity extracted from a Sigstore signing certificate.
/// </summary>
public class VerifiedIdentity
{
    /// <summary>
    /// The Subject Alternative Name from the certificate.
    /// </summary>
    public required string SubjectAlternativeName { get; init; }

    /// <summary>
    /// The OIDC issuer from the certificate extension.
    /// </summary>
    public required string Issuer { get; init; }
}

/// <summary>
/// A verified timestamp from a trusted source.
/// </summary>
public class VerifiedTimestamp
{
    /// <summary>
    /// The source of the timestamp.
    /// </summary>
    public required TimestampSource Source { get; init; }

    /// <summary>
    /// The verified timestamp value.
    /// </summary>
    public required DateTimeOffset Timestamp { get; init; }

    /// <summary>
    /// The URI of the timestamp authority or transparency log.
    /// </summary>
    public string? AuthorityUri { get; init; }
}

/// <summary>
/// The source of a verified timestamp.
/// </summary>
public enum TimestampSource
{
    /// <summary>
    /// Timestamp from an RFC 3161 Timestamp Authority.
    /// </summary>
    TimestampAuthority,

    /// <summary>
    /// Integrated timestamp from a Rekor transparency log entry.
    /// </summary>
    TransparencyLog
}

/// <summary>
/// Exception thrown when Sigstore bundle verification fails.
/// </summary>
public class VerificationException : Exception
{
    public VerificationException(string message) : base(message) { }
    public VerificationException(string message, Exception innerException) : base(message, innerException) { }
}
