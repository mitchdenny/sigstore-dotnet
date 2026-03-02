namespace Sigstore;

/// <summary>
/// Specifies the policy for verifying a Sigstore bundle.
/// Defines what identity the signer must have and trust requirements.
/// </summary>
public sealed class VerificationPolicy
{
    /// <summary>
    /// The expected certificate identity of the signer.
    /// </summary>
    public CertificateIdentity? CertificateIdentity { get; set; }

    /// <summary>
    /// Whether to require a transparency log entry. Default: true.
    /// </summary>
    public bool RequireTransparencyLog { get; set; } = true;

    /// <summary>
    /// The minimum number of verified transparency log entries. Default: 1.
    /// </summary>
    public int TransparencyLogThreshold { get; set; } = 1;

    /// <summary>
    /// Whether to require signed timestamps from a Timestamp Authority. Default: false.
    /// When false, timestamps from Rekor integrated timestamps are accepted.
    /// </summary>
    public bool RequireSignedTimestamps { get; set; }

    /// <summary>
    /// The minimum number of verified signed timestamps. Default: 1 (when required).
    /// </summary>
    public int SignedTimestampThreshold { get; set; } = 1;

    /// <summary>
    /// Whether to require Signed Certificate Timestamps. Default: true.
    /// </summary>
    public bool RequireSignedCertificateTimestamps { get; set; } = true;

    /// <summary>
    /// A DER-encoded SubjectPublicKeyInfo (SPKI) public key for managed-key verification.
    /// When set, verification uses this key directly instead of certificate-based identity.
    /// Certificate chain validation, SCT checks, and identity checks are skipped.
    /// </summary>
    public ReadOnlyMemory<byte>? PublicKey { get; set; }
}

/// <summary>
/// Describes the expected identity in a Sigstore signing certificate.
/// </summary>
public sealed class CertificateIdentity
{
    /// <summary>
    /// The expected Subject Alternative Name value (e.g., email address or URI).
    /// </summary>
    public string? SubjectAlternativeName { get; set; }

    /// <summary>
    /// A regex pattern to match the Subject Alternative Name.
    /// Cannot be used together with <see cref="SubjectAlternativeName"/>.
    /// </summary>
    public string? SubjectAlternativeNamePattern { get; set; }

    /// <summary>
    /// The expected OIDC issuer URL (Fulcio OID 1.3.6.1.4.1.57264.1.8).
    /// </summary>
    public string? Issuer { get; set; }

    /// <summary>
    /// Creates a CertificateIdentity for verifying artifacts signed by GitHub Actions.
    /// </summary>
    /// <param name="owner">The GitHub organization or user (e.g., "myorg").</param>
    /// <param name="repository">The GitHub repository name (e.g., "myapp").</param>
    /// <param name="issuer">The OIDC issuer. Defaults to GitHub Actions token issuer.</param>
    /// <param name="workflowRef">Optional workflow ref to match (e.g., "refs/heads/main").</param>
    public static CertificateIdentity ForGitHubActions(
        string owner,
        string repository,
        string issuer = "https://token.actions.githubusercontent.com",
        string? workflowRef = null)
    {
        var sanPattern = workflowRef is not null
            ? $"https://github.com/{owner}/{repository}/.github/workflows/.*@{workflowRef}"
            : $"https://github.com/{owner}/{repository}/.*";

        return new CertificateIdentity
        {
            SubjectAlternativeNamePattern = sanPattern,
            Issuer = issuer
        };
    }
}
