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
        throw new NotImplementedException();
    }
}

/// <summary>
/// Describes an instance of a transparency log.
/// </summary>
public class TransparencyLogInfo
{
    public string BaseUrl { get; set; } = "";
    public Common.HashAlgorithmType HashAlgorithm { get; set; }
    public byte[] PublicKeyBytes { get; set; } = [];
    public Common.PublicKeyDetails KeyDetails { get; set; }
    public byte[] LogId { get; set; } = [];
    public byte[]? CheckpointKeyId { get; set; }
    public string? Operator { get; set; }
    public DateTimeOffset? ValidFrom { get; set; }
    public DateTimeOffset? ValidTo { get; set; }
}

/// <summary>
/// Describes a trusted certificate authority.
/// </summary>
public class CertificateAuthorityInfo
{
    public string Uri { get; set; } = "";
    public List<byte[]> CertChain { get; set; } = [];
    public string? Operator { get; set; }
    public DateTimeOffset? ValidFrom { get; set; }
    public DateTimeOffset? ValidTo { get; set; }
}
