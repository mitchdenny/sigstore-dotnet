using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Sigstore.Common;
using Sigstore.Timestamp;
using Sigstore.Transparency;

namespace Sigstore.Verification;

/// <summary>
/// High-level Sigstore bundle verifier. Orchestrates the full verification workflow
/// per the Sigstore Client Specification.
///
/// <para>
/// The default constructor wires up all dependencies for the Sigstore public good instance.
/// For custom deployments or testing, inject your own implementations via the constructor.
/// </para>
///
/// <example>
/// <code>
/// // Simple usage with defaults (Sigstore public good instance)
/// var verifier = new SigstoreVerifier();
///
/// var policy = new VerificationPolicy
/// {
///     CertificateIdentity = new CertificateIdentity
///     {
///         SubjectAlternativeName = "user@example.com",
///         Issuer = "https://accounts.google.com"
///     }
/// };
///
/// var result = await verifier.VerifyAsync(artifactStream, bundle, policy);
/// </code>
/// </example>
/// </summary>
public class SigstoreVerifier
{
    // Fulcio OIDC issuer (V2) extension OID
    private const string OidcIssuerV2Oid = "1.3.6.1.4.1.57264.1.8";
    // Fulcio OIDC issuer (V1) extension OID (fallback)
    private const string OidcIssuerV1Oid = "1.3.6.1.4.1.57264.1.1";

    private readonly ITrustRootProvider _trustRootProvider;
    private readonly ICertificateValidator _certificateValidator;

    /// <summary>
    /// Creates a verifier with default implementations for the Sigstore public good instance.
    /// </summary>
    public SigstoreVerifier()
    {
        // TODO: Wire up default implementations
        _trustRootProvider = null!;
        _certificateValidator = null!;
    }

    /// <summary>
    /// Creates a verifier with custom dependencies.
    /// </summary>
    /// <param name="trustRootProvider">Provider for trusted root material.</param>
    /// <param name="certificateValidator">Certificate chain validator.</param>
    public SigstoreVerifier(
        ITrustRootProvider trustRootProvider,
        ICertificateValidator? certificateValidator = null)
    {
        _trustRootProvider = trustRootProvider ?? throw new ArgumentNullException(nameof(trustRootProvider));
        _certificateValidator = certificateValidator ?? new DefaultCertificateValidator();
    }

    /// <summary>
    /// Verifies a Sigstore bundle against an artifact.
    /// Throws <see cref="VerificationException"/> on failure with detailed reason.
    /// </summary>
    public async Task<VerificationResult> VerifyAsync(
        Stream artifact,
        SigstoreBundle bundle,
        VerificationPolicy policy,
        CancellationToken cancellationToken = default)
    {
        var (success, result) = await TryVerifyAsync(artifact, bundle, policy, cancellationToken);
        if (success)
        {
            return result!;
        }
        throw new VerificationException(result?.FailureReason ?? "Verification failed.");
    }

    /// <summary>
    /// Attempts to verify a Sigstore bundle against an artifact without throwing on failure.
    /// </summary>
    public async Task<(bool Success, VerificationResult? Result)> TryVerifyAsync(
        Stream artifact,
        SigstoreBundle bundle,
        VerificationPolicy policy,
        CancellationToken cancellationToken = default)
    {
        _ = artifact ?? throw new ArgumentNullException(nameof(artifact));
        _ = bundle ?? throw new ArgumentNullException(nameof(bundle));
        _ = policy ?? throw new ArgumentNullException(nameof(policy));

        try
        {
            // Step 1: Load trusted root
            var trustRoot = await _trustRootProvider.GetTrustRootAsync(cancellationToken);

            // Step 2: Parse the bundle — extract certificate
            var verificationMaterial = bundle.VerificationMaterial;
            if (verificationMaterial == null)
                return Fail("Bundle has no verification material.");

            byte[]? leafCertBytes = verificationMaterial.Certificate;
            // Fallback to first cert in chain for v0.1/v0.2 bundles
            if (leafCertBytes == null && verificationMaterial.CertificateChain is { Count: > 0 })
                leafCertBytes = verificationMaterial.CertificateChain[0];

            if (leafCertBytes == null)
                return Fail("Bundle has no signing certificate.");

            using var leafCert = X509CertificateLoader.LoadCertificate(leafCertBytes);

            // Build intermediate chain
            X509Certificate2Collection? intermediates = null;
            if (verificationMaterial.CertificateChain is { Count: > 1 })
            {
                intermediates = new X509Certificate2Collection();
                for (int i = 1; i < verificationMaterial.CertificateChain.Count; i++)
                    intermediates.Add(X509CertificateLoader.LoadCertificate(verificationMaterial.CertificateChain[i]));
            }

            // Step 3: Establish signature time
            var verifiedTimestamps = new List<VerifiedTimestamp>();

            // 3a: Try RFC 3161 timestamps
            foreach (var tsBytes in verificationMaterial.Rfc3161Timestamps)
            {
                try
                {
                    var tsInfo = TimestampParser.Parse(tsBytes);

                    // Verify against TSA certs from trust root
                    var tsaCerts = trustRoot.TimestampAuthorities
                        .SelectMany(tsa => tsa.CertChain)
                        .ToList();

                    byte[] signatureToTimestamp = GetSignatureBytes(bundle);
                    if (tsaCerts.Count == 0 || TimestampParser.Verify(tsInfo, signatureToTimestamp, tsaCerts))
                    {
                        verifiedTimestamps.Add(new VerifiedTimestamp
                        {
                            Source = TimestampSource.TimestampAuthority,
                            Timestamp = tsInfo.Timestamp
                        });
                    }
                }
                catch
                {
                    // Skip unparseable timestamps
                }
            }

            // 3b: Use integrated time from tlog entries
            foreach (var entry in verificationMaterial.TlogEntries)
            {
                if (entry.IntegratedTime > 0)
                {
                    verifiedTimestamps.Add(new VerifiedTimestamp
                    {
                        Source = TimestampSource.TransparencyLog,
                        Timestamp = DateTimeOffset.FromUnixTimeSeconds(entry.IntegratedTime)
                    });
                }
            }

            if (verifiedTimestamps.Count == 0)
                return Fail("No verified timestamps found. Need at least one timestamp from TSA or transparency log.");

            var signatureTime = verifiedTimestamps[0].Timestamp;

            // Step 4: Validate certificate chain
            var chainResult = _certificateValidator.ValidateChain(leafCert, intermediates, trustRoot, signatureTime);
            if (!chainResult.IsValid)
                return Fail($"Certificate chain validation failed: {chainResult.FailureReason}");

            // Step 5: Check certificate identity against policy
            if (policy.CertificateIdentity != null)
            {
                var san = ExtractSan(leafCert) ?? chainResult.SubjectAlternativeName;
                var issuer = ExtractOidcIssuer(leafCert);

                if (san == null)
                    return Fail("Could not extract Subject Alternative Name from certificate.");

                // Match SAN
                if (policy.CertificateIdentity.SubjectAlternativeName != null)
                {
                    if (!string.Equals(san, policy.CertificateIdentity.SubjectAlternativeName, StringComparison.Ordinal))
                        return Fail($"Certificate SAN '{san}' does not match expected '{policy.CertificateIdentity.SubjectAlternativeName}'.");
                }
                else if (policy.CertificateIdentity.SubjectAlternativeNamePattern != null)
                {
                    if (!Regex.IsMatch(san, policy.CertificateIdentity.SubjectAlternativeNamePattern))
                        return Fail($"Certificate SAN '{san}' does not match pattern '{policy.CertificateIdentity.SubjectAlternativeNamePattern}'.");
                }

                // Match issuer
                if (policy.CertificateIdentity.Issuer != null)
                {
                    if (issuer == null)
                        return Fail("Could not extract OIDC issuer from certificate.");
                    if (!string.Equals(issuer, policy.CertificateIdentity.Issuer, StringComparison.Ordinal))
                        return Fail($"Certificate issuer '{issuer}' does not match expected '{policy.CertificateIdentity.Issuer}'.");
                }

                // Step 6: Verify transparency log entries
                if (policy.RequireTransparencyLog)
                {
                    int verifiedEntries = 0;
                    foreach (var entry in verificationMaterial.TlogEntries)
                    {
                        if (VerifyTlogEntry(entry, trustRoot, bundle, leafCertBytes))
                            verifiedEntries++;
                    }

                    if (verifiedEntries < policy.TransparencyLogThreshold)
                        return Fail($"Only {verifiedEntries} transparency log entries verified, need {policy.TransparencyLogThreshold}.");
                }

                // Step 7: Verify the artifact signature
                var sigVerifyResult = VerifyArtifactSignature(artifact, bundle, leafCert);
                if (!sigVerifyResult.IsValid)
                    return Fail($"Signature verification failed: {sigVerifyResult.Reason}");

                return (true, new VerificationResult
                {
                    SignerIdentity = new VerifiedIdentity
                    {
                        SubjectAlternativeName = san,
                        Issuer = issuer ?? ""
                    },
                    VerifiedTimestamps = verifiedTimestamps
                });
            }

            // No identity policy — still verify signature
            if (policy.RequireTransparencyLog)
            {
                int verifiedEntries = 0;
                foreach (var entry in verificationMaterial.TlogEntries)
                {
                    if (VerifyTlogEntry(entry, trustRoot, bundle, leafCertBytes))
                        verifiedEntries++;
                }

                if (verifiedEntries < policy.TransparencyLogThreshold)
                    return Fail($"Only {verifiedEntries} transparency log entries verified, need {policy.TransparencyLogThreshold}.");
            }

            var sigResult = VerifyArtifactSignature(artifact, bundle, leafCert);
            if (!sigResult.IsValid)
                return Fail($"Signature verification failed: {sigResult.Reason}");

            return (true, new VerificationResult
            {
                SignerIdentity = null,
                VerifiedTimestamps = verifiedTimestamps
            });
        }
        catch (ArgumentNullException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return Fail($"Verification error: {ex.Message}");
        }
    }

    private static (bool Success, VerificationResult? Result) Fail(string reason)
    {
        return (false, new VerificationResult { FailureReason = reason });
    }

    private static byte[] GetSignatureBytes(SigstoreBundle bundle)
    {
        if (bundle.MessageSignature?.Signature is { Length: > 0 } sig)
            return sig;
        if (bundle.DsseEnvelope?.Signatures is { Count: > 0 } sigs)
            return sigs[0].Sig;
        return [];
    }

    private static string? ExtractSan(X509Certificate2 cert)
    {
        foreach (var ext in cert.Extensions)
        {
            if (ext.Oid?.Value != "2.5.29.17")
                continue;

            var formatted = ext.Format(false);
            foreach (var part in formatted.Split(',', StringSplitOptions.TrimEntries))
            {
                if (part.Contains("RFC822", StringComparison.OrdinalIgnoreCase) ||
                    part.Contains("email", StringComparison.OrdinalIgnoreCase))
                {
                    return part.Split('=', ':').Last().Trim();
                }
                if (part.Contains("URI", StringComparison.OrdinalIgnoreCase))
                {
                    var idx = part.IndexOf("URI:", StringComparison.OrdinalIgnoreCase);
                    if (idx >= 0)
                        return part.Substring(idx + 4).Trim();
                    return part.Split('=').Last().Trim();
                }
            }

            // Fall back to DNS names
            var sanExt = (X509SubjectAlternativeNameExtension)ext;
            foreach (var dns in sanExt.EnumerateDnsNames())
                return dns;
        }
        return null;
    }

    private static string? ExtractOidcIssuer(X509Certificate2 cert)
    {
        foreach (var ext in cert.Extensions)
        {
            if (ext.Oid?.Value == OidcIssuerV2Oid || ext.Oid?.Value == OidcIssuerV1Oid)
            {
                // The extension value is a DER-encoded UTF8String or IA5String
                var rawData = ext.RawData;
                if (rawData.Length >= 2)
                {
                    byte tag = rawData[0];
                    int length = rawData[1];
                    // tag 0x0C = UTF8String, 0x16 = IA5String
                    if ((tag == 0x0C || tag == 0x16) && rawData.Length >= 2 + length)
                        return Encoding.UTF8.GetString(rawData, 2, length);
                }
                // Fallback: try to read the whole thing as UTF-8
                return Encoding.UTF8.GetString(rawData);
            }
        }
        return null;
    }

    private static bool VerifyTlogEntry(
        TransparencyLogEntry entry,
        TrustRoot.TrustedRoot trustRoot,
        SigstoreBundle bundle,
        byte[] leafCertBytes)
    {
        if (entry.InclusionProof == null)
            return false;

        // Find matching log by logId
        var logInfo = trustRoot.TransparencyLogs
            .FirstOrDefault(l => l.LogId.SequenceEqual(entry.LogId));

        if (logInfo == null)
            return false;

        // Verify checkpoint signature
        if (entry.InclusionProof.Checkpoint != null)
        {
            var checkpointKeyId = logInfo.CheckpointKeyId ?? ComputeCheckpointKeyId(logInfo.PublicKeyBytes);
            var checkpointData = CheckpointVerifier.VerifyCheckpoint(
                entry.InclusionProof.Checkpoint,
                logInfo.PublicKeyBytes,
                checkpointKeyId);

            if (checkpointData == null)
            {
                // Fall back to parsing without verification
                checkpointData = CheckpointVerifier.ParseCheckpoint(entry.InclusionProof.Checkpoint);
            }

            if (checkpointData != null)
            {
                // Verify inclusion proof against the checkpoint root hash
                var body = entry.Body != null ? Convert.FromBase64String(entry.Body) : [];
                var leafHash = MerkleVerifier.HashLeaf(body);

                if (!MerkleVerifier.VerifyInclusionProof(
                    leafHash,
                    entry.InclusionProof.LogIndex,
                    checkpointData.TreeSize,
                    entry.InclusionProof.Hashes,
                    checkpointData.RootHash))
                {
                    return false;
                }
            }
        }
        else if (entry.InclusionProof.RootHash.Length > 0)
        {
            // Verify inclusion proof against the provided root hash
            var body = entry.Body != null ? Convert.FromBase64String(entry.Body) : [];
            var leafHash = MerkleVerifier.HashLeaf(body);

            if (!MerkleVerifier.VerifyInclusionProof(
                leafHash,
                entry.InclusionProof.LogIndex,
                entry.InclusionProof.TreeSize,
                entry.InclusionProof.Hashes,
                entry.InclusionProof.RootHash))
            {
                return false;
            }
        }

        return true;
    }

    private static byte[] ComputeCheckpointKeyId(byte[] publicKeyBytes)
    {
        var hash = SHA256.HashData(publicKeyBytes);
        return hash.AsSpan(0, 4).ToArray();
    }

    private static (bool IsValid, string? Reason) VerifyArtifactSignature(
        Stream artifact,
        SigstoreBundle bundle,
        X509Certificate2 leafCert)
    {
        if (bundle.MessageSignature != null)
        {
            return VerifyMessageSignature(artifact, bundle.MessageSignature, leafCert);
        }

        if (bundle.DsseEnvelope != null)
        {
            return VerifyDsseSignature(bundle.DsseEnvelope, leafCert);
        }

        return (false, "Bundle contains neither a message signature nor a DSSE envelope.");
    }

    private static (bool IsValid, string? Reason) VerifyMessageSignature(
        Stream artifact,
        MessageSignature messageSig,
        X509Certificate2 leafCert)
    {
        if (messageSig.Signature.Length == 0)
            return (false, "Message signature is empty.");

        // Read artifact bytes
        byte[] artifactBytes;
        if (artifact is MemoryStream ms && ms.TryGetBuffer(out var buffer))
        {
            artifactBytes = buffer.ToArray();
        }
        else
        {
            using var memStream = new MemoryStream();
            artifact.Position = 0;
            artifact.CopyTo(memStream);
            artifactBytes = memStream.ToArray();
        }

        return VerifySignatureWithCert(artifactBytes, messageSig.Signature, leafCert);
    }

    private static (bool IsValid, string? Reason) VerifyDsseSignature(
        DsseEnvelope envelope,
        X509Certificate2 leafCert)
    {
        if (envelope.Signatures.Count == 0)
            return (false, "DSSE envelope has no signatures.");

        // Compute PAE (Pre-Authentication Encoding)
        // PAE = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
        var payloadType = envelope.PayloadType;
        var payload = envelope.Payload;
        var pae = Encoding.UTF8.GetBytes(
            $"DSSEv1 {payloadType.Length} {payloadType} {payload.Length} ");
        var paeBytes = new byte[pae.Length + payload.Length];
        pae.CopyTo(paeBytes, 0);
        payload.CopyTo(paeBytes, pae.Length);

        var sig = envelope.Signatures[0].Sig;
        return VerifySignatureWithCert(paeBytes, sig, leafCert);
    }

    private static (bool IsValid, string? Reason) VerifySignatureWithCert(
        byte[] data,
        byte[] signature,
        X509Certificate2 leafCert)
    {
        // Try ECDSA
        using var ecdsa = leafCert.GetECDsaPublicKey();
        if (ecdsa != null)
        {
            bool valid = ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
            return valid
                ? (true, null)
                : (false, "ECDSA signature verification failed.");
        }

        // Try RSA
        using var rsa = leafCert.GetRSAPublicKey();
        if (rsa != null)
        {
            bool valid = rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return valid
                ? (true, null)
                : (false, "RSA signature verification failed.");
        }

        return (false, "Unsupported public key algorithm in certificate.");
    }
}
