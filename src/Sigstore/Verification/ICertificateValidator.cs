using System.Security.Cryptography;
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
    /// <summary>Whether the certificate chain is valid.</summary>
    public bool IsValid { get; init; }
    /// <summary>The reason validation failed, or null on success.</summary>
    public string? FailureReason { get; init; }
    /// <summary>The Subject Alternative Name extracted from the leaf certificate.</summary>
    public string? SubjectAlternativeName { get; init; }
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
        using var x509Chain = new X509Chain();
        x509Chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        x509Chain.ChainPolicy.VerificationTime = signatureTime.UtcDateTime;
        x509Chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;

        // Add CA certificates from the trusted root
        foreach (var ca in trustRoot.CertificateAuthorities)
        {
            foreach (var certBytes in ca.CertChain)
            {
                var cert = X509CertificateLoader.LoadCertificate(certBytes);
                if (cert.SubjectName.RawData.SequenceEqual(cert.IssuerName.RawData))
                {
                    x509Chain.ChainPolicy.CustomTrustStore.Add(cert);
                }
                else
                {
                    x509Chain.ChainPolicy.ExtraStore.Add(cert);
                }
            }
        }

        // Add any provided intermediate certificates
        if (chain != null)
        {
            x509Chain.ChainPolicy.ExtraStore.AddRange(chain);
        }

        if (!x509Chain.Build(leafCertificate))
        {
            var errors = string.Join("; ",
                x509Chain.ChainStatus.Select(s => s.StatusInformation));
            return new CertificateValidationResult
            {
                IsValid = false,
                FailureReason = $"Certificate chain validation failed: {errors}"
            };
        }

        // Hybrid time model: verify every cert in the chain was valid at signature time
        foreach (var element in x509Chain.ChainElements)
        {
            var cert = element.Certificate;
            if (signatureTime < cert.NotBefore || signatureTime > cert.NotAfter)
            {
                return new CertificateValidationResult
                {
                    IsValid = false,
                    FailureReason = $"Certificate '{cert.Subject}' was not valid at signature time {signatureTime}. " +
                                    $"Valid from {cert.NotBefore} to {cert.NotAfter}."
                };
            }
        }

        // Extract SAN from the leaf certificate
        string? san = null;
        foreach (var ext in leafCertificate.Extensions)
        {
            if (ext.Oid?.Value == "2.5.29.17") // Subject Alternative Name
            {
                // Parse the SAN extension formatted string
                var formatted = ext.Format(false);
                // Try to extract email, URI, or DNS from the formatted string
                // Format varies by platform but typically: "RFC822 Name=user@example.com" or "email:user@example.com"
                // or "URI:https://..." or "DNS Name=host"
                foreach (var part in formatted.Split(',', StringSplitOptions.TrimEntries))
                {
                    if (part.Contains("RFC822", StringComparison.OrdinalIgnoreCase) ||
                        part.Contains("email", StringComparison.OrdinalIgnoreCase))
                    {
                        san = part.Split('=', ':').Last().Trim();
                        break;
                    }
                    if (part.Contains("URI", StringComparison.OrdinalIgnoreCase))
                    {
                        // URI might be formatted as "URI:https://..." or "Uniform Resource Identifier=https://..."
                        var idx = part.IndexOf("URI:", StringComparison.OrdinalIgnoreCase);
                        if (idx >= 0)
                            san = part.Substring(idx + 4).Trim();
                        else
                            san = part.Split('=').Last().Trim();
                        break;
                    }
                }
                if (san == null)
                {
                    // Fall back to DNS names
                    var sanExt = (X509SubjectAlternativeNameExtension)ext;
                    foreach (var dns in sanExt.EnumerateDnsNames())
                    {
                        san = dns;
                        break;
                    }
                }
                break;
            }
        }

        return new CertificateValidationResult
        {
            IsValid = true,
            SubjectAlternativeName = san
        };
    }
}
