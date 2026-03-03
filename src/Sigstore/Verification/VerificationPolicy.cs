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
    /// Optional expected Fulcio certificate extensions to match.
    /// When set, the signing certificate must contain extensions matching all non-null fields.
    /// This enables asserting that an artifact was built from a specific repository, workflow, etc.
    /// </summary>
    /// <example>
    /// <code>
    /// // Require the artifact to be built from a specific GitHub repository
    /// var policy = new VerificationPolicy
    /// {
    ///     CertificateIdentity = new CertificateIdentity
    ///     {
    ///         Issuer = "https://token.actions.githubusercontent.com",
    ///         SubjectAlternativeNamePattern = "https://github.com/myorg/myrepo/.*",
    ///         Extensions = new CertificateExtensionPolicy
    ///         {
    ///             SourceRepositoryUri = "https://github.com/myorg/myrepo",
    ///             RunnerEnvironment = "github-hosted"
    ///         }
    ///     }
    /// };
    /// </code>
    /// </example>
    public CertificateExtensionPolicy? Extensions { get; set; }

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
            Issuer = issuer,
            Extensions = new CertificateExtensionPolicy
            {
                SourceRepositoryUri = $"https://github.com/{owner}/{repository}"
            }
        };
    }
}

/// <summary>
/// Specifies expected values for Fulcio certificate extensions in a verification policy.
/// Only non-null fields are checked — null fields are ignored during matching.
/// </summary>
public sealed class CertificateExtensionPolicy
{
    /// <summary>Expected source repository URI (e.g., "https://github.com/myorg/myrepo").</summary>
    public string? SourceRepositoryUri { get; set; }

    /// <summary>Expected source repository digest.</summary>
    public string? SourceRepositoryDigest { get; set; }

    /// <summary>Expected source repository ref (e.g., "refs/heads/main").</summary>
    public string? SourceRepositoryRef { get; set; }

    /// <summary>Expected source repository identifier.</summary>
    public string? SourceRepositoryIdentifier { get; set; }

    /// <summary>Expected source repository owner URI.</summary>
    public string? SourceRepositoryOwnerUri { get; set; }

    /// <summary>Expected source repository owner identifier.</summary>
    public string? SourceRepositoryOwnerIdentifier { get; set; }

    /// <summary>Expected build signer URI.</summary>
    public string? BuildSignerUri { get; set; }

    /// <summary>Expected build signer digest.</summary>
    public string? BuildSignerDigest { get; set; }

    /// <summary>Expected build config URI.</summary>
    public string? BuildConfigUri { get; set; }

    /// <summary>Expected build config digest.</summary>
    public string? BuildConfigDigest { get; set; }

    /// <summary>Expected build trigger (e.g., "push").</summary>
    public string? BuildTrigger { get; set; }

    /// <summary>Expected runner environment (e.g., "github-hosted").</summary>
    public string? RunnerEnvironment { get; set; }

    /// <summary>Expected source repository visibility at signing ("public" or "private").</summary>
    public string? SourceRepositoryVisibilityAtSigning { get; set; }

    /// <summary>
    /// Checks whether the given Fulcio certificate extensions match this policy.
    /// Only non-null fields on the policy are compared.
    /// </summary>
    /// <param name="actual">The actual extensions parsed from the certificate.</param>
    /// <returns>A tuple indicating success and an optional failure reason.</returns>
    internal (bool IsMatch, string? FailureReason) Matches(FulcioCertificateExtensions actual)
    {
        if (SourceRepositoryUri is not null &&
            !string.Equals(actual.SourceRepositoryUri, SourceRepositoryUri, StringComparison.Ordinal))
            return (false, $"Certificate extension SourceRepositoryUri '{actual.SourceRepositoryUri}' does not match expected '{SourceRepositoryUri}'.");

        if (SourceRepositoryDigest is not null &&
            !string.Equals(actual.SourceRepositoryDigest, SourceRepositoryDigest, StringComparison.Ordinal))
            return (false, $"Certificate extension SourceRepositoryDigest '{actual.SourceRepositoryDigest}' does not match expected '{SourceRepositoryDigest}'.");

        if (SourceRepositoryRef is not null &&
            !string.Equals(actual.SourceRepositoryRef, SourceRepositoryRef, StringComparison.Ordinal))
            return (false, $"Certificate extension SourceRepositoryRef '{actual.SourceRepositoryRef}' does not match expected '{SourceRepositoryRef}'.");

        if (SourceRepositoryIdentifier is not null &&
            !string.Equals(actual.SourceRepositoryIdentifier, SourceRepositoryIdentifier, StringComparison.Ordinal))
            return (false, $"Certificate extension SourceRepositoryIdentifier '{actual.SourceRepositoryIdentifier}' does not match expected '{SourceRepositoryIdentifier}'.");

        if (SourceRepositoryOwnerUri is not null &&
            !string.Equals(actual.SourceRepositoryOwnerUri, SourceRepositoryOwnerUri, StringComparison.Ordinal))
            return (false, $"Certificate extension SourceRepositoryOwnerUri '{actual.SourceRepositoryOwnerUri}' does not match expected '{SourceRepositoryOwnerUri}'.");

        if (SourceRepositoryOwnerIdentifier is not null &&
            !string.Equals(actual.SourceRepositoryOwnerIdentifier, SourceRepositoryOwnerIdentifier, StringComparison.Ordinal))
            return (false, $"Certificate extension SourceRepositoryOwnerIdentifier '{actual.SourceRepositoryOwnerIdentifier}' does not match expected '{SourceRepositoryOwnerIdentifier}'.");

        if (BuildSignerUri is not null &&
            !string.Equals(actual.BuildSignerUri, BuildSignerUri, StringComparison.Ordinal))
            return (false, $"Certificate extension BuildSignerUri '{actual.BuildSignerUri}' does not match expected '{BuildSignerUri}'.");

        if (BuildSignerDigest is not null &&
            !string.Equals(actual.BuildSignerDigest, BuildSignerDigest, StringComparison.Ordinal))
            return (false, $"Certificate extension BuildSignerDigest '{actual.BuildSignerDigest}' does not match expected '{BuildSignerDigest}'.");

        if (BuildConfigUri is not null &&
            !string.Equals(actual.BuildConfigUri, BuildConfigUri, StringComparison.Ordinal))
            return (false, $"Certificate extension BuildConfigUri '{actual.BuildConfigUri}' does not match expected '{BuildConfigUri}'.");

        if (BuildConfigDigest is not null &&
            !string.Equals(actual.BuildConfigDigest, BuildConfigDigest, StringComparison.Ordinal))
            return (false, $"Certificate extension BuildConfigDigest '{actual.BuildConfigDigest}' does not match expected '{BuildConfigDigest}'.");

        if (BuildTrigger is not null &&
            !string.Equals(actual.BuildTrigger, BuildTrigger, StringComparison.Ordinal))
            return (false, $"Certificate extension BuildTrigger '{actual.BuildTrigger}' does not match expected '{BuildTrigger}'.");

        if (RunnerEnvironment is not null &&
            !string.Equals(actual.RunnerEnvironment, RunnerEnvironment, StringComparison.Ordinal))
            return (false, $"Certificate extension RunnerEnvironment '{actual.RunnerEnvironment}' does not match expected '{RunnerEnvironment}'.");

        if (SourceRepositoryVisibilityAtSigning is not null &&
            !string.Equals(actual.SourceRepositoryVisibilityAtSigning, SourceRepositoryVisibilityAtSigning, StringComparison.Ordinal))
            return (false, $"Certificate extension SourceRepositoryVisibilityAtSigning '{actual.SourceRepositoryVisibilityAtSigning}' does not match expected '{SourceRepositoryVisibilityAtSigning}'.");

        return (true, null);
    }
}
