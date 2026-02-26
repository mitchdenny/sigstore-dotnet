using System.Security.Cryptography.X509Certificates;
using Sigstore.TrustRoot;

namespace Sigstore.Verification;

/// <summary>
/// Validates X.509 certificate chains against a trusted root using the Sigstore
/// "hybrid model" — where certificates are validated at the time the signature was created,
/// not at the current time.
/// </summary>
public interface ICertificateValidator
{
    /// <summary>
    /// Validates a certificate chain against the trusted root at the given signature time.
    /// </summary>
    /// <param name="leafCertificate">The leaf signing certificate.</param>
    /// <param name="chain">Additional intermediate certificates.</param>
    /// <param name="trustRoot">The trusted root containing CAs.</param>
    /// <param name="signatureTime">The time at which the signature was created.</param>
    /// <returns>The validation result.</returns>
    CertificateValidationResult ValidateChain(
        X509Certificate2 leafCertificate,
        X509Certificate2Collection? chain,
        TrustedRoot trustRoot,
        DateTimeOffset signatureTime);
}

/// <summary>
/// Result of certificate chain validation.
/// </summary>
public class CertificateValidationResult
{
    public bool IsValid { get; init; }
    public string? FailureReason { get; init; }
}

/// <summary>
/// Default certificate validator using .NET X509Chain with hybrid time model.
/// </summary>
internal class DefaultCertificateValidator : ICertificateValidator
{
    public CertificateValidationResult ValidateChain(
        X509Certificate2 leafCertificate,
        X509Certificate2Collection? chain,
        TrustedRoot trustRoot,
        DateTimeOffset signatureTime)
    {
        // TODO: Implement certificate path validation per RFC 5280 §6
        // using the signature time as the "current time" (hybrid model)
        throw new NotImplementedException();
    }
}
