using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Sigstore;

/// <summary>
/// Parsed Fulcio certificate extensions that describe the CI/CD identity and build provenance.
/// These extensions are embedded in signing certificates by the Fulcio CA based on the
/// OIDC token claims presented during certificate issuance.
/// </summary>
/// <remarks>
/// The extensions follow the OID arc 1.3.6.1.4.1.57264.1.* defined by the Sigstore project.
/// See https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md for details.
/// </remarks>
public sealed record FulcioCertificateExtensions
{
    // OID constants for Fulcio certificate extensions
    internal const string OidIssuerV1 = "1.3.6.1.4.1.57264.1.1";
    internal const string OidGithubWorkflowTrigger = "1.3.6.1.4.1.57264.1.2";
    internal const string OidGithubWorkflowSha = "1.3.6.1.4.1.57264.1.3";
    internal const string OidGithubWorkflowName = "1.3.6.1.4.1.57264.1.4";
    internal const string OidGithubWorkflowRepository = "1.3.6.1.4.1.57264.1.5";
    internal const string OidGithubWorkflowRef = "1.3.6.1.4.1.57264.1.6";
    internal const string OidIssuerV2 = "1.3.6.1.4.1.57264.1.8";
    internal const string OidBuildSignerUri = "1.3.6.1.4.1.57264.1.9";
    internal const string OidBuildSignerDigest = "1.3.6.1.4.1.57264.1.10";
    internal const string OidRunnerEnvironment = "1.3.6.1.4.1.57264.1.11";
    internal const string OidSourceRepositoryUri = "1.3.6.1.4.1.57264.1.12";
    internal const string OidSourceRepositoryDigest = "1.3.6.1.4.1.57264.1.13";
    internal const string OidSourceRepositoryRef = "1.3.6.1.4.1.57264.1.14";
    internal const string OidSourceRepositoryIdentifier = "1.3.6.1.4.1.57264.1.15";
    internal const string OidSourceRepositoryOwnerUri = "1.3.6.1.4.1.57264.1.16";
    internal const string OidSourceRepositoryOwnerIdentifier = "1.3.6.1.4.1.57264.1.17";
    internal const string OidBuildConfigUri = "1.3.6.1.4.1.57264.1.18";
    internal const string OidBuildConfigDigest = "1.3.6.1.4.1.57264.1.19";
    internal const string OidBuildTrigger = "1.3.6.1.4.1.57264.1.20";
    internal const string OidRunInvocationUri = "1.3.6.1.4.1.57264.1.21";
    internal const string OidSourceRepositoryVisibilityAtSigning = "1.3.6.1.4.1.57264.1.22";

    /// <summary>
    /// The OIDC issuer. Matches the <c>iss</c> claim of the ID token.
    /// OID 1.3.6.1.4.1.57264.1.8 (v2) or 1.3.6.1.4.1.57264.1.1 (v1, deprecated).
    /// </summary>
    public string? Issuer { get; init; }

    /// <summary>
    /// Reference to specific build instructions that are responsible for signing.
    /// OID 1.3.6.1.4.1.57264.1.9.
    /// </summary>
    public string? BuildSignerUri { get; init; }

    /// <summary>
    /// Immutable reference to the specific version of the build instructions.
    /// OID 1.3.6.1.4.1.57264.1.10.
    /// </summary>
    public string? BuildSignerDigest { get; init; }

    /// <summary>
    /// Whether the build took place in platform-hosted or self-hosted infrastructure.
    /// OID 1.3.6.1.4.1.57264.1.11.
    /// </summary>
    public string? RunnerEnvironment { get; init; }

    /// <summary>
    /// Source repository URL that the build was based on.
    /// OID 1.3.6.1.4.1.57264.1.12.
    /// </summary>
    public string? SourceRepositoryUri { get; init; }

    /// <summary>
    /// Immutable reference to a specific version of the source code that the build was based upon.
    /// OID 1.3.6.1.4.1.57264.1.13.
    /// </summary>
    public string? SourceRepositoryDigest { get; init; }

    /// <summary>
    /// Source repository ref that the build run was based upon.
    /// OID 1.3.6.1.4.1.57264.1.14.
    /// </summary>
    public string? SourceRepositoryRef { get; init; }

    /// <summary>
    /// Immutable identifier for the source repository (e.g., numeric repo ID).
    /// OID 1.3.6.1.4.1.57264.1.15.
    /// </summary>
    public string? SourceRepositoryIdentifier { get; init; }

    /// <summary>
    /// Source repository owner URL.
    /// OID 1.3.6.1.4.1.57264.1.16.
    /// </summary>
    public string? SourceRepositoryOwnerUri { get; init; }

    /// <summary>
    /// Immutable identifier for the source repository owner (e.g., numeric org ID).
    /// OID 1.3.6.1.4.1.57264.1.17.
    /// </summary>
    public string? SourceRepositoryOwnerIdentifier { get; init; }

    /// <summary>
    /// Build configuration URL (e.g., workflow file path).
    /// OID 1.3.6.1.4.1.57264.1.18.
    /// </summary>
    public string? BuildConfigUri { get; init; }

    /// <summary>
    /// Immutable reference to the specific version of the build configuration.
    /// OID 1.3.6.1.4.1.57264.1.19.
    /// </summary>
    public string? BuildConfigDigest { get; init; }

    /// <summary>
    /// Event or action that initiated the build (e.g., "push", "pull_request").
    /// OID 1.3.6.1.4.1.57264.1.20.
    /// </summary>
    public string? BuildTrigger { get; init; }

    /// <summary>
    /// Run invocation URL to uniquely identify the build execution.
    /// OID 1.3.6.1.4.1.57264.1.21.
    /// </summary>
    public string? RunInvocationUri { get; init; }

    /// <summary>
    /// Source repository visibility at the time of signing ("public" or "private").
    /// OID 1.3.6.1.4.1.57264.1.22.
    /// </summary>
    public string? SourceRepositoryVisibilityAtSigning { get; init; }

    // Deprecated GitHub-specific extensions (v1)

    /// <summary>
    /// Deprecated. Triggering event of the GitHub workflow.
    /// OID 1.3.6.1.4.1.57264.1.2.
    /// </summary>
    public string? GithubWorkflowTrigger { get; init; }

    /// <summary>
    /// Deprecated. SHA of git commit being built in GitHub Actions.
    /// OID 1.3.6.1.4.1.57264.1.3.
    /// </summary>
    public string? GithubWorkflowSha { get; init; }

    /// <summary>
    /// Deprecated. Name of GitHub Actions workflow.
    /// OID 1.3.6.1.4.1.57264.1.4.
    /// </summary>
    public string? GithubWorkflowName { get; init; }

    /// <summary>
    /// Deprecated. Repository of the GitHub Actions workflow.
    /// OID 1.3.6.1.4.1.57264.1.5.
    /// </summary>
    public string? GithubWorkflowRepository { get; init; }

    /// <summary>
    /// Deprecated. Git ref of the GitHub Actions workflow.
    /// OID 1.3.6.1.4.1.57264.1.6.
    /// </summary>
    public string? GithubWorkflowRef { get; init; }

    /// <summary>
    /// Parses Fulcio certificate extensions from an X.509 certificate.
    /// </summary>
    /// <param name="certificate">The X.509 certificate to extract extensions from.</param>
    /// <returns>A <see cref="FulcioCertificateExtensions"/> with all recognized extensions populated.</returns>
    public static FulcioCertificateExtensions FromCertificate(X509Certificate2 certificate)
    {
        string? issuer = null;
        string? buildSignerUri = null;
        string? buildSignerDigest = null;
        string? runnerEnvironment = null;
        string? sourceRepositoryUri = null;
        string? sourceRepositoryDigest = null;
        string? sourceRepositoryRef = null;
        string? sourceRepositoryIdentifier = null;
        string? sourceRepositoryOwnerUri = null;
        string? sourceRepositoryOwnerIdentifier = null;
        string? buildConfigUri = null;
        string? buildConfigDigest = null;
        string? buildTrigger = null;
        string? runInvocationUri = null;
        string? sourceRepositoryVisibilityAtSigning = null;
        string? githubWorkflowTrigger = null;
        string? githubWorkflowSha = null;
        string? githubWorkflowName = null;
        string? githubWorkflowRepository = null;
        string? githubWorkflowRef = null;

        foreach (var ext in certificate.Extensions)
        {
            var oid = ext.Oid?.Value;
            if (oid == null)
                continue;

            switch (oid)
            {
                // V1 deprecated extensions use raw bytes
                case OidIssuerV1:
                    issuer ??= ReadExtensionValue(ext.RawData);
                    break;
                case OidGithubWorkflowTrigger:
                    githubWorkflowTrigger = ReadExtensionValue(ext.RawData);
                    break;
                case OidGithubWorkflowSha:
                    githubWorkflowSha = ReadExtensionValue(ext.RawData);
                    break;
                case OidGithubWorkflowName:
                    githubWorkflowName = ReadExtensionValue(ext.RawData);
                    break;
                case OidGithubWorkflowRepository:
                    githubWorkflowRepository = ReadExtensionValue(ext.RawData);
                    break;
                case OidGithubWorkflowRef:
                    githubWorkflowRef = ReadExtensionValue(ext.RawData);
                    break;
                // V2 extensions use DER-encoded UTF8String
                case OidIssuerV2:
                    issuer = ReadDerString(ext.RawData);
                    break;
                case OidBuildSignerUri:
                    buildSignerUri = ReadDerString(ext.RawData);
                    break;
                case OidBuildSignerDigest:
                    buildSignerDigest = ReadDerString(ext.RawData);
                    break;
                case OidRunnerEnvironment:
                    runnerEnvironment = ReadDerString(ext.RawData);
                    break;
                case OidSourceRepositoryUri:
                    sourceRepositoryUri = ReadDerString(ext.RawData);
                    break;
                case OidSourceRepositoryDigest:
                    sourceRepositoryDigest = ReadDerString(ext.RawData);
                    break;
                case OidSourceRepositoryRef:
                    sourceRepositoryRef = ReadDerString(ext.RawData);
                    break;
                case OidSourceRepositoryIdentifier:
                    sourceRepositoryIdentifier = ReadDerString(ext.RawData);
                    break;
                case OidSourceRepositoryOwnerUri:
                    sourceRepositoryOwnerUri = ReadDerString(ext.RawData);
                    break;
                case OidSourceRepositoryOwnerIdentifier:
                    sourceRepositoryOwnerIdentifier = ReadDerString(ext.RawData);
                    break;
                case OidBuildConfigUri:
                    buildConfigUri = ReadDerString(ext.RawData);
                    break;
                case OidBuildConfigDigest:
                    buildConfigDigest = ReadDerString(ext.RawData);
                    break;
                case OidBuildTrigger:
                    buildTrigger = ReadDerString(ext.RawData);
                    break;
                case OidRunInvocationUri:
                    runInvocationUri = ReadDerString(ext.RawData);
                    break;
                case OidSourceRepositoryVisibilityAtSigning:
                    sourceRepositoryVisibilityAtSigning = ReadDerString(ext.RawData);
                    break;
            }
        }

        return new FulcioCertificateExtensions
        {
            Issuer = issuer,
            BuildSignerUri = buildSignerUri,
            BuildSignerDigest = buildSignerDigest,
            RunnerEnvironment = runnerEnvironment,
            SourceRepositoryUri = sourceRepositoryUri,
            SourceRepositoryDigest = sourceRepositoryDigest,
            SourceRepositoryRef = sourceRepositoryRef,
            SourceRepositoryIdentifier = sourceRepositoryIdentifier,
            SourceRepositoryOwnerUri = sourceRepositoryOwnerUri,
            SourceRepositoryOwnerIdentifier = sourceRepositoryOwnerIdentifier,
            BuildConfigUri = buildConfigUri,
            BuildConfigDigest = buildConfigDigest,
            BuildTrigger = buildTrigger,
            RunInvocationUri = runInvocationUri,
            SourceRepositoryVisibilityAtSigning = sourceRepositoryVisibilityAtSigning,
            GithubWorkflowTrigger = githubWorkflowTrigger,
            GithubWorkflowSha = githubWorkflowSha,
            GithubWorkflowName = githubWorkflowName,
            GithubWorkflowRepository = githubWorkflowRepository,
            GithubWorkflowRef = githubWorkflowRef
        };
    }

    /// <summary>
    /// Reads a DER-encoded string value (UTF8String or IA5String) from an extension's raw data.
    /// </summary>
    internal static string? ReadDerString(byte[] rawData)
    {
        if (rawData.Length < 2)
            return null;

        byte tag = rawData[0];
        int length = rawData[1];

        // tag 0x0C = UTF8String, 0x16 = IA5String
        if ((tag == 0x0C || tag == 0x16) && rawData.Length >= 2 + length)
            return Encoding.UTF8.GetString(rawData, 2, length);

        // Fallback: treat entire value as raw UTF-8
        return Encoding.UTF8.GetString(rawData);
    }

    /// <summary>
    /// Reads a raw extension value as UTF-8 string (for v1 deprecated extensions).
    /// </summary>
    internal static string? ReadExtensionValue(byte[] rawData)
    {
        if (rawData.Length == 0)
            return null;

        // V1 deprecated extensions may use raw bytes or DER encoding
        // Try DER first, then fall back to raw
        if (rawData.Length >= 2)
        {
            byte tag = rawData[0];
            int length = rawData[1];
            if ((tag == 0x0C || tag == 0x16) && rawData.Length >= 2 + length)
                return Encoding.UTF8.GetString(rawData, 2, length);
        }

        return Encoding.UTF8.GetString(rawData);
    }
}
