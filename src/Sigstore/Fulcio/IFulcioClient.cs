using System.Security.Cryptography.X509Certificates;

namespace Sigstore;

/// <summary>
/// Client for interacting with a Fulcio certificate authority instance.
/// </summary>
public interface IFulcioClient
{
    /// <summary>
    /// Requests a short-lived signing certificate from Fulcio.
    /// </summary>
    /// <param name="request">The certificate signing request details.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The issued certificate chain.</returns>
    Task<FulcioCertificateResponse> GetSigningCertificateAsync(
        FulcioCertificateRequest request,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// A request to Fulcio for a signing certificate.
/// </summary>
public sealed class FulcioCertificateRequest
{
    /// <summary>
    /// The PEM-encoded PKCS#10 certificate signing request.
    /// </summary>
    public required string CertificateSigningRequest { get; init; }

    /// <summary>
    /// The OIDC identity token proving the signer's identity.
    /// </summary>
    public required string IdentityToken { get; init; }
}

/// <summary>
/// Response from Fulcio containing the issued certificate.
/// </summary>
public sealed class FulcioCertificateResponse
{
    /// <summary>
    /// The certificate chain, ordered leaf-to-root. Each element is DER-encoded.
    /// </summary>
    public required IReadOnlyList<byte[]> CertificateChain { get; init; }

    /// <summary>
    /// The leaf signing certificate.
    /// </summary>
    public X509Certificate2 LeafCertificate =>
        X509CertificateLoader.LoadCertificate(CertificateChain[0]);
}
