using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Sigstore.Common;
using Sigstore.Crypto;
using Sigstore.Fulcio;
using Sigstore.Oidc;
using Sigstore.Rekor;
using Sigstore.Timestamp;
using FulcioCertificateRequest = Sigstore.Fulcio.CertificateRequest;

namespace Sigstore.Signing;

/// <summary>
/// High-level Sigstore signer. Orchestrates the full keyless signing workflow
/// per the Sigstore Client Specification.
///
/// <para>
/// The default constructor wires up all dependencies for the Sigstore public good instance.
/// For custom deployments or testing, inject your own implementations via the constructor.
/// </para>
///
/// <example>
/// <code>
/// var signer = new SigstoreSigner();
/// SigstoreBundle bundle = await signer.SignAsync(artifactStream);
/// string json = bundle.Serialize();
/// </code>
/// </example>
/// </summary>
public class SigstoreSigner
{
    private readonly IFulcioClient _fulcioClient;
    private readonly IRekorClient _rekorClient;
    private readonly ITimestampAuthority _timestampAuthority;
    private readonly IOidcTokenProvider _tokenProvider;
    private readonly ITrustRootProvider _trustRootProvider;

    /// <summary>
    /// Creates a signer with default implementations for the Sigstore public good instance.
    /// </summary>
    public SigstoreSigner()
    {
        // TODO: Wire up default implementations
        _fulcioClient = null!;
        _rekorClient = null!;
        _timestampAuthority = null!;
        _tokenProvider = null!;
        _trustRootProvider = null!;
    }

    /// <summary>
    /// Creates a signer with custom dependencies.
    /// </summary>
    public SigstoreSigner(
        IFulcioClient fulcioClient,
        IRekorClient rekorClient,
        ITimestampAuthority timestampAuthority,
        IOidcTokenProvider tokenProvider,
        ITrustRootProvider? trustRootProvider = null)
    {
        _fulcioClient = fulcioClient ?? throw new ArgumentNullException(nameof(fulcioClient));
        _rekorClient = rekorClient ?? throw new ArgumentNullException(nameof(rekorClient));
        _timestampAuthority = timestampAuthority ?? throw new ArgumentNullException(nameof(timestampAuthority));
        _tokenProvider = tokenProvider ?? throw new ArgumentNullException(nameof(tokenProvider));
        _trustRootProvider = trustRootProvider!;
    }

    /// <summary>
    /// Signs an artifact and returns a Sigstore bundle containing the signature
    /// and all verification material.
    /// </summary>
    /// <param name="artifact">The artifact to sign.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A Sigstore bundle containing the signature and verification material.</returns>
    public async Task<SigstoreBundle> SignAsync(
        Stream artifact,
        CancellationToken cancellationToken = default)
    {
        _ = artifact ?? throw new ArgumentNullException(nameof(artifact));

        // 1. Get OIDC token
        var oidcToken = await _tokenProvider.GetTokenAsync(cancellationToken);

        using var keyPair = new EphemeralKeyPair();

        // 2-3. Create CSR and get signing certificate from Fulcio
        var csr = keyPair.CreateCsr(oidcToken.Subject);
        var certResponse = await _fulcioClient.GetSigningCertificateAsync(
            new FulcioCertificateRequest
            {
                CertificateSigningRequest = csr,
                IdentityToken = oidcToken.RawToken
            },
            cancellationToken);

        // 4. Hash the artifact
        var hash = await SHA256.HashDataAsync(artifact, cancellationToken);

        // 5. Sign the hash
        var signature = keyPair.SignHash(hash);

        // 6. Get timestamp
        var timestampResponse = await _timestampAuthority.GetTimestampAsync(signature, cancellationToken);

        // 7. Submit to Rekor
        var leafCertPem = ExportCertificatePem(certResponse.CertificateChain[0]);
        var tlogEntry = await _rekorClient.SubmitEntryAsync(
            new RekorEntry
            {
                Signature = signature,
                ArtifactDigest = hash,
                DigestAlgorithm = HashAlgorithmType.Sha2_256,
                VerificationMaterial = leafCertPem
            },
            cancellationToken);

        // 8. Assemble bundle
        return new SigstoreBundle
        {
            MediaType = "application/vnd.dev.sigstore.bundle.v0.3+json",
            VerificationMaterial = new VerificationMaterial
            {
                Certificate = certResponse.CertificateChain[0],
                TlogEntries = [tlogEntry],
                Rfc3161Timestamps = timestampResponse.RawBytes.Length > 0
                    ? [timestampResponse.RawBytes]
                    : []
            },
            MessageSignature = new MessageSignature
            {
                MessageDigest = new HashOutput
                {
                    Algorithm = HashAlgorithmType.Sha2_256,
                    Digest = hash
                },
                Signature = signature
            }
        };
    }

    /// <summary>
    /// Signs an artifact file and returns a Sigstore bundle.
    /// </summary>
    /// <param name="filePath">Path to the artifact file.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A Sigstore bundle containing the signature and verification material.</returns>
    public async Task<SigstoreBundle> SignAsync(
        string filePath,
        CancellationToken cancellationToken = default)
    {
        await using var stream = File.OpenRead(filePath);
        return await SignAsync(stream, cancellationToken);
    }

    /// <summary>
    /// Signs an in-toto statement using a DSSE envelope and returns a Sigstore bundle.
    /// </summary>
    /// <param name="inTotoStatement">The in-toto statement JSON.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A Sigstore bundle containing the DSSE envelope and verification material.</returns>
    public async Task<SigstoreBundle> AttestAsync(
        string inTotoStatement,
        CancellationToken cancellationToken = default)
    {
        _ = inTotoStatement ?? throw new ArgumentNullException(nameof(inTotoStatement));

        const string payloadType = "application/vnd.in-toto+json";
        var payloadBytes = Encoding.UTF8.GetBytes(inTotoStatement);

        // 1. Get OIDC token
        var oidcToken = await _tokenProvider.GetTokenAsync(cancellationToken);

        using var keyPair = new EphemeralKeyPair();

        // 2-3. Create CSR and get signing certificate from Fulcio
        var csr = keyPair.CreateCsr(oidcToken.Subject);
        var certResponse = await _fulcioClient.GetSigningCertificateAsync(
            new FulcioCertificateRequest
            {
                CertificateSigningRequest = csr,
                IdentityToken = oidcToken.RawToken
            },
            cancellationToken);

        // 4. Compute PAE (Pre-Authentication Encoding) for DSSE
        var pae = ComputePae(payloadType, payloadBytes);

        // 5. Sign the PAE
        var signature = keyPair.Sign(pae);

        // 6. Get timestamp
        var timestampResponse = await _timestampAuthority.GetTimestampAsync(signature, cancellationToken);

        // 7. Submit to Rekor — hash the PAE for the artifact digest
        var paeHash = SHA256.HashData(pae);
        var leafCertPem = ExportCertificatePem(certResponse.CertificateChain[0]);
        var tlogEntry = await _rekorClient.SubmitEntryAsync(
            new RekorEntry
            {
                Signature = signature,
                ArtifactDigest = paeHash,
                DigestAlgorithm = HashAlgorithmType.Sha2_256,
                VerificationMaterial = leafCertPem
            },
            cancellationToken);

        // 8. Assemble bundle with DSSE envelope
        return new SigstoreBundle
        {
            MediaType = "application/vnd.dev.sigstore.bundle.v0.3+json",
            VerificationMaterial = new VerificationMaterial
            {
                Certificate = certResponse.CertificateChain[0],
                TlogEntries = [tlogEntry],
                Rfc3161Timestamps = timestampResponse.RawBytes.Length > 0
                    ? [timestampResponse.RawBytes]
                    : []
            },
            DsseEnvelope = new DsseEnvelope
            {
                PayloadType = payloadType,
                Payload = payloadBytes,
                Signatures =
                [
                    new DsseSignature
                    {
                        KeyId = "",
                        Sig = signature
                    }
                ]
            }
        };
    }

    /// <summary>
    /// Computes the DSSE Pre-Authentication Encoding (PAE).
    /// PAE = "DSSEv1" + SP + len(type) + SP + type + SP + len(body) + SP + body
    /// </summary>
    internal static byte[] ComputePae(string payloadType, byte[] payload)
    {
        var typeBytes = Encoding.UTF8.GetBytes(payloadType);
        var prefix = Encoding.UTF8.GetBytes(
            $"DSSEv1 {typeBytes.Length} {payloadType} {payload.Length} ");
        var result = new byte[prefix.Length + payload.Length];
        prefix.CopyTo(result, 0);
        payload.CopyTo(result, prefix.Length);
        return result;
    }

    private static string ExportCertificatePem(byte[] derBytes)
    {
        using var cert = X509CertificateLoader.LoadCertificate(derBytes);
        return cert.ExportCertificatePem();
    }
}
