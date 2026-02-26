using System.Security.Cryptography.X509Certificates;

namespace Sigstore.TrustRoot;

/// <summary>
/// Represents the complete set of trusted entities for Sigstore verification.
/// Includes certificate authorities, transparency logs, CT logs, and timestamp authorities.
/// </summary>
public class TrustedRoot
{
    /// <summary>
    /// The media type of the trusted root.
    /// </summary>
    public string MediaType { get; set; } = "application/vnd.dev.sigstore.trustedroot.v0.2+json";

    /// <summary>
    /// Trusted Rekor transparency log instances.
    /// </summary>
    public List<TransparencyLogInfo> TransparencyLogs { get; set; } = [];

    /// <summary>
    /// Trusted certificate authorities (e.g., Fulcio).
    /// </summary>
    public List<CertificateAuthorityInfo> CertificateAuthorities { get; set; } = [];

    /// <summary>
    /// Trusted certificate transparency log instances.
    /// </summary>
    public List<TransparencyLogInfo> CtLogs { get; set; } = [];

    /// <summary>
    /// Trusted timestamp authorities.
    /// </summary>
    public List<CertificateAuthorityInfo> TimestampAuthorities { get; set; } = [];

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
    public string BaseUrl { get; set; } = "";
    /// <summary>The hash algorithm used by the log.</summary>
    public Common.HashAlgorithmType HashAlgorithm { get; set; }
    /// <summary>The DER-encoded public key bytes of the log.</summary>
    public byte[] PublicKeyBytes { get; set; } = [];
    /// <summary>The algorithm and encoding details of the public key.</summary>
    public Common.PublicKeyDetails KeyDetails { get; set; }
    /// <summary>The log ID (SHA-256 hash of the public key).</summary>
    public byte[] LogId { get; set; } = [];
    /// <summary>The checkpoint key ID for Rekor v2 verification.</summary>
    public byte[]? CheckpointKeyId { get; set; }
    /// <summary>The operator of the transparency log.</summary>
    public string? Operator { get; set; }
    /// <summary>The start of the log's validity period.</summary>
    public DateTimeOffset? ValidFrom { get; set; }
    /// <summary>The end of the log's validity period.</summary>
    public DateTimeOffset? ValidTo { get; set; }
}

/// <summary>
/// Describes a trusted certificate authority.
/// </summary>
public class CertificateAuthorityInfo
{
    /// <summary>The URI of the certificate authority.</summary>
    public string Uri { get; set; } = "";
    /// <summary>The certificate chain (DER-encoded, leaf to root).</summary>
    public List<byte[]> CertChain { get; set; } = [];
    /// <summary>The operator of the certificate authority.</summary>
    public string? Operator { get; set; }
    /// <summary>The start of the CA's validity period.</summary>
    public DateTimeOffset? ValidFrom { get; set; }
    /// <summary>The end of the CA's validity period.</summary>
    public DateTimeOffset? ValidTo { get; set; }
}
