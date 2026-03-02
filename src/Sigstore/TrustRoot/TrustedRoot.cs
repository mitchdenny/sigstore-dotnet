using System.Security.Cryptography.X509Certificates;

namespace Sigstore;

/// <summary>
/// Represents the complete set of trusted entities for Sigstore verification.
/// Includes certificate authorities, transparency logs, CT logs, and timestamp authorities.
/// </summary>
public class TrustedRoot
{
    /// <summary>
    /// The media type of the trusted root.
    /// </summary>
    public string MediaType { get; init; } = "application/vnd.dev.sigstore.trustedroot.v0.2+json";

    /// <summary>
    /// Trusted Rekor transparency log instances.
    /// </summary>
    public IReadOnlyList<TransparencyLogInfo> TransparencyLogs { get; init; } = [];

    /// <summary>
    /// Trusted certificate authorities (e.g., Fulcio).
    /// </summary>
    public IReadOnlyList<CertificateAuthorityInfo> CertificateAuthorities { get; init; } = [];

    /// <summary>
    /// Trusted certificate transparency log instances.
    /// </summary>
    public IReadOnlyList<TransparencyLogInfo> CtLogs { get; init; } = [];

    /// <summary>
    /// Trusted timestamp authorities.
    /// </summary>
    public IReadOnlyList<CertificateAuthorityInfo> TimestampAuthorities { get; init; } = [];

    /// <summary>
    /// Deserializes a TrustedRoot from JSON.
    /// </summary>
    public static TrustedRoot Deserialize(string json)
    {
        return TrustedRootSerializer.Deserialize(json);
    }
}

/// <summary>
/// Describes an instance of a transparency log.
/// </summary>
public class TransparencyLogInfo
{
    /// <summary>The base URL of the transparency log.</summary>
    public string BaseUrl { get; init; } = "";
    /// <summary>The hash algorithm used by the log.</summary>
    public HashAlgorithmType HashAlgorithm { get; init; }
    /// <summary>The DER-encoded public key bytes of the log.</summary>
    public byte[] PublicKeyBytes { get; init; } = [];
    /// <summary>The algorithm and encoding details of the public key.</summary>
    public PublicKeyDetails KeyDetails { get; init; }
    /// <summary>The log ID (SHA-256 hash of the public key).</summary>
    public byte[] LogId { get; init; } = [];
    /// <summary>The checkpoint key ID for Rekor v2 verification.</summary>
    public byte[]? CheckpointKeyId { get; init; }
    /// <summary>The operator of the transparency log.</summary>
    public string? Operator { get; init; }
    /// <summary>The start of the log's validity period.</summary>
    public DateTimeOffset? ValidFrom { get; init; }
    /// <summary>The end of the log's validity period.</summary>
    public DateTimeOffset? ValidTo { get; init; }
}

/// <summary>
/// Describes a trusted certificate authority.
/// </summary>
public class CertificateAuthorityInfo
{
    /// <summary>The URI of the certificate authority.</summary>
    public string Uri { get; init; } = "";
    /// <summary>The certificate chain (DER-encoded, leaf to root).</summary>
    public IReadOnlyList<byte[]> CertChain { get; init; } = [];
    /// <summary>The operator of the certificate authority.</summary>
    public string? Operator { get; init; }
    /// <summary>The start of the CA's validity period.</summary>
    public DateTimeOffset? ValidFrom { get; init; }
    /// <summary>The end of the CA's validity period.</summary>
    public DateTimeOffset? ValidTo { get; init; }
}
