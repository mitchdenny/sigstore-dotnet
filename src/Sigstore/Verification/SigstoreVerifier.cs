using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Sigstore;

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
/// var result = await verifier.VerifyStreamAsync(artifactStream, bundle, policy);
/// </code>
/// </example>
/// </summary>
public sealed class SigstoreVerifier
{
    // Fulcio OIDC issuer (V2) extension OID
    private const string OidcIssuerV2Oid = "1.3.6.1.4.1.57264.1.8";
    // Fulcio OIDC issuer (V1) extension OID (fallback)
    private const string OidcIssuerV1Oid = "1.3.6.1.4.1.57264.1.1";

    private readonly ITrustRootProvider _trustRootProvider;
    private readonly ISigningCertificateValidator _certificateValidator;

    /// <summary>
    /// Creates a verifier with default implementations for the Sigstore public good instance.
    /// Downloads the trusted root from the Sigstore public-good TUF target on first use.
    /// </summary>
    public SigstoreVerifier()
    {
        _trustRootProvider = new TufTrustRootProvider(TufTrustRootProvider.ProductionUrl);
        _certificateValidator = new DefaultSigningCertificateValidator();
    }

    /// <summary>
    /// Creates a verifier with custom dependencies.
    /// </summary>
    /// <param name="trustRootProvider">Provider for trusted root material.</param>
    /// <param name="certificateValidator">Certificate chain validator.</param>
    public SigstoreVerifier(
        ITrustRootProvider trustRootProvider,
        ISigningCertificateValidator? certificateValidator = null)
    {
        _trustRootProvider = trustRootProvider ?? throw new ArgumentNullException(nameof(trustRootProvider));
        _certificateValidator = certificateValidator ?? new DefaultSigningCertificateValidator();
    }

    /// <summary>
    /// Verifies a Sigstore bundle against an artifact stream.
    /// Throws <see cref="VerificationException"/> on failure with detailed reason.
    /// </summary>
    public async Task<VerificationResult> VerifyStreamAsync(
        Stream artifact,
        SigstoreBundle bundle,
        VerificationPolicy policy,
        CancellationToken cancellationToken = default)
    {
        var (success, result) = await TryVerifyStreamAsync(artifact, bundle, policy, cancellationToken);
        if (success)
        {
            return result!;
        }
        throw new VerificationException(result?.FailureReason ?? "Verification failed.", result);
    }

    /// <summary>
    /// Verifies a Sigstore bundle using a pre-computed artifact digest.
    /// Used when the original artifact is not available but its hash is known.
    /// Throws <see cref="VerificationException"/> on failure with detailed reason.
    /// </summary>
    /// <param name="artifactDigest">The pre-computed digest of the artifact.</param>
    /// <param name="digestAlgorithm">The hash algorithm used to compute the digest.</param>
    /// <param name="bundle">The Sigstore bundle to verify.</param>
    /// <param name="policy">The verification policy to enforce.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<VerificationResult> VerifyDigestAsync(
        ReadOnlyMemory<byte> artifactDigest,
        HashAlgorithmType digestAlgorithm,
        SigstoreBundle bundle,
        VerificationPolicy policy,
        CancellationToken cancellationToken = default)
    {
        var (success, result) = await TryVerifyDigestAsync(artifactDigest, digestAlgorithm, bundle, policy, cancellationToken);
        if (success)
        {
            return result!;
        }
        throw new VerificationException(result?.FailureReason ?? "Verification failed.", result);
    }

    /// <summary>
    /// Verifies a Sigstore bundle against artifact bytes.
    /// Throws <see cref="VerificationException"/> on failure with detailed reason.
    /// </summary>
    public async Task<VerificationResult> VerifyAsync(
        ReadOnlyMemory<byte> artifact,
        SigstoreBundle bundle,
        VerificationPolicy policy,
        CancellationToken cancellationToken = default)
    {
        using var stream = new MemoryStream(artifact.ToArray());
        return await VerifyStreamAsync(stream, bundle, policy, cancellationToken);
    }

    /// <summary>
    /// Attempts to verify a Sigstore bundle against an artifact stream without throwing on failure.
    /// </summary>
    public Task<(bool Success, VerificationResult? Result)> TryVerifyStreamAsync(
        Stream artifact,
        SigstoreBundle bundle,
        VerificationPolicy policy,
        CancellationToken cancellationToken = default)
    {
        _ = artifact ?? throw new ArgumentNullException(nameof(artifact));
        return TryVerifyCoreAsync(ArtifactInput.FromStream(artifact), bundle, policy, cancellationToken);
    }

    /// <summary>
    /// Attempts to verify a Sigstore bundle using a pre-computed artifact digest without throwing on failure.
    /// </summary>
    public Task<(bool Success, VerificationResult? Result)> TryVerifyDigestAsync(
        ReadOnlyMemory<byte> artifactDigest,
        HashAlgorithmType digestAlgorithm,
        SigstoreBundle bundle,
        VerificationPolicy policy,
        CancellationToken cancellationToken = default)
    {
        return TryVerifyCoreAsync(ArtifactInput.FromDigest(artifactDigest, digestAlgorithm), bundle, policy, cancellationToken);
    }

    /// <summary>
    /// Attempts to verify a Sigstore bundle against artifact bytes without throwing on failure.
    /// </summary>
    public async Task<(bool Success, VerificationResult? Result)> TryVerifyAsync(
        ReadOnlyMemory<byte> artifact,
        SigstoreBundle bundle,
        VerificationPolicy policy,
        CancellationToken cancellationToken = default)
    {
        using var stream = new MemoryStream(artifact.ToArray());
        return await TryVerifyStreamAsync(stream, bundle, policy, cancellationToken);
    }

    /// <summary>
    /// Verifies an artifact file against a Sigstore bundle file.
    /// Throws <see cref="VerificationException"/> on failure with detailed reason.
    /// </summary>
    /// <param name="artifact">The artifact file.</param>
    /// <param name="bundle">The Sigstore bundle file.</param>
    /// <param name="policy">The verification policy to enforce.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<VerificationResult> VerifyFileAsync(
        FileInfo artifact,
        FileInfo bundle,
        VerificationPolicy policy,
        CancellationToken cancellationToken = default)
    {
        var sigstoreBundle = await SigstoreBundle.LoadAsync(bundle, cancellationToken);
        await using var stream = artifact.OpenRead();
        return await VerifyStreamAsync(stream, sigstoreBundle, policy, cancellationToken);
    }

    /// <summary>
    /// Attempts to verify an artifact file against a Sigstore bundle file without throwing on failure.
    /// </summary>
    /// <param name="artifact">The artifact file.</param>
    /// <param name="bundle">The Sigstore bundle file.</param>
    /// <param name="policy">The verification policy to enforce.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<(bool Success, VerificationResult? Result)> TryVerifyFileAsync(
        FileInfo artifact,
        FileInfo bundle,
        VerificationPolicy policy,
        CancellationToken cancellationToken = default)
    {
        var sigstoreBundle = await SigstoreBundle.LoadAsync(bundle, cancellationToken);
        await using var stream = artifact.OpenRead();
        return await TryVerifyStreamAsync(stream, sigstoreBundle, policy, cancellationToken);
    }

    private async Task<(bool Success, VerificationResult? Result)> TryVerifyCoreAsync(
        ArtifactInput artifactInput,
        SigstoreBundle bundle,
        VerificationPolicy policy,
        CancellationToken cancellationToken)
    {
        _ = bundle ?? throw new ArgumentNullException(nameof(bundle));
        _ = policy ?? throw new ArgumentNullException(nameof(policy));

        try
        {
            // Step 1: Load trusted root
            var trustRoot = await _trustRootProvider.GetTrustRootAsync(cancellationToken);

            // Managed-key verification path: skip all certificate-based logic
            if (policy.PublicKey != null)
            {
                return VerifyWithPublicKey(artifactInput, bundle, policy, trustRoot);
            }

            // Step 2: Parse the bundle — extract certificate
            var verificationMaterial = bundle.VerificationMaterial;
            if (verificationMaterial == null)
                return Fail("Bundle has no verification material.");

            ReadOnlyMemory<byte>? leafCertBytes = verificationMaterial.Certificate;
            // Fallback to first cert in chain for v0.1/v0.2 bundles
            if (leafCertBytes == null && verificationMaterial.CertificateChain is { Count: > 0 })
                leafCertBytes = verificationMaterial.CertificateChain[0];

            if (leafCertBytes == null)
                return Fail("Bundle has no signing certificate.");

            using var leafCert = X509CertificateLoader.LoadCertificate(leafCertBytes.Value.Span);

            // Reject bundles where the chain contains a root (self-signed) certificate
            if (verificationMaterial.CertificateChain is { Count: > 0 })
            {
                foreach (var certBytes in verificationMaterial.CertificateChain)
                {
                    using var cert = X509CertificateLoader.LoadCertificate(certBytes.Span);
                    if (cert.SubjectName.RawData.AsSpan().SequenceEqual(cert.IssuerName.RawData))
                        return Fail("Bundle certificate chain contains a root certificate. Root certificates must come from the trusted root, not the bundle.");
                }
            }

            // Build intermediate chain
            X509Certificate2Collection? intermediates = null;
            if (verificationMaterial.CertificateChain is { Count: > 1 })
            {
                intermediates = new X509Certificate2Collection();
                for (int i = 1; i < verificationMaterial.CertificateChain.Count; i++)
                    intermediates.Add(X509CertificateLoader.LoadCertificate(verificationMaterial.CertificateChain[i].Span));
            }

            // Step 2b: Verify SCTs if CT logs are configured
            if (trustRoot.CtLogs.Count > 0)
            {
                // Find the issuer cert from intermediates, cert chain, or trusted root CAs
                X509Certificate2? issuerCert = null;
                if (intermediates is { Count: > 0 })
                {
                    issuerCert = intermediates[0];
                }
                else
                {
                    // Try to find issuer in trusted root certificate authorities
                    foreach (var ca in trustRoot.CertificateAuthorities)
                    {
                        foreach (var caCertBytes in ca.CertificateChain)
                        {
                            try
                            {
                                using var caCert = X509CertificateLoader.LoadCertificate(caCertBytes.Span);
                                if (leafCert.IssuerName.RawData.AsSpan().SequenceEqual(caCert.SubjectName.RawData))
                                {
                                    issuerCert = X509CertificateLoader.LoadCertificate(caCertBytes.Span);
                                    break;
                                }
                            }
                            catch { }
                        }
                        if (issuerCert != null) break;
                    }
                }

                if (!SctVerifier.VerifyScts(leafCert, issuerCert, trustRoot.CtLogs))
                    return Fail("No valid Signed Certificate Timestamp (SCT) found for any configured CT log.");
            }

            // Step 3: Establish signature time
            var verifiedTimestamps = new List<VerifiedTimestamp>();

            // 3a: Try RFC 3161 timestamps
            foreach (var tsBytes in verificationMaterial.Rfc3161Timestamps)
            {
                try
                {
                    var tsInfo = TimestampParser.Parse(tsBytes);

                    ReadOnlyMemory<byte> signatureToTimestamp = GetSignatureBytes(bundle);
                    if (trustRoot.TimestampAuthorities.Count > 0)
                    {
                        if (TimestampParser.Verify(tsInfo, signatureToTimestamp, trustRoot.TimestampAuthorities))
                        {
                            verifiedTimestamps.Add(new VerifiedTimestamp
                            {
                                Source = TimestampSource.TimestampAuthority,
                                Timestamp = tsInfo.Timestamp
                            });
                        }
                    }
                    else
                    {
                        // No TSA authorities configured — accept timestamp without TSA verification
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

            // 3b: Use integrated time from tlog entries (only if SET verifies)
            foreach (var entry in verificationMaterial.TlogEntries)
            {
                if (entry.IntegratedTime > 0 && entry.InclusionPromise != null)
                {
                    // Verify the Signed Entry Timestamp (SET) before trusting integratedTime
                    if (VerifySignedEntryTimestamp(entry, trustRoot))
                    {
                        verifiedTimestamps.Add(new VerifiedTimestamp
                        {
                            Source = TimestampSource.TransparencyLog,
                            Timestamp = DateTimeOffset.FromUnixTimeSeconds(entry.IntegratedTime)
                        });
                    }
                }
            }

            if (verifiedTimestamps.Count == 0)
                return Fail("No verified timestamps found. Need at least one timestamp from TSA or transparency log.");

            // Step 3c: Verify ALL timestamps fall within signing cert validity
            foreach (var ts in verifiedTimestamps)
            {
                if (ts.Timestamp < leafCert.NotBefore || ts.Timestamp > leafCert.NotAfter)
                    return Fail($"Verified timestamp {ts.Timestamp:O} ({ts.Source}) is outside signing certificate validity ({leafCert.NotBefore:O} to {leafCert.NotAfter:O}).");
            }
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
                        if (VerifyTlogEntry(entry, trustRoot, bundle, leafCertBytes.Value))
                            verifiedEntries++;
                    }

                    if (verifiedEntries < policy.TransparencyLogThreshold)
                        return Fail($"Only {verifiedEntries} transparency log entries verified, need {policy.TransparencyLogThreshold}.");
                }

                // Step 7: Verify the artifact signature
                var sigVerifyResult = VerifyArtifactSignature(artifactInput, bundle, leafCert);
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
                    if (VerifyTlogEntry(entry, trustRoot, bundle, leafCertBytes.Value))
                        verifiedEntries++;
                }

                if (verifiedEntries < policy.TransparencyLogThreshold)
                    return Fail($"Only {verifiedEntries} transparency log entries verified, need {policy.TransparencyLogThreshold}.");
            }

            var sigResult = VerifyArtifactSignature(artifactInput, bundle, leafCert);
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

    /// <summary>
    /// Managed-key verification: verifies a bundle using a raw public key instead of certificates.
    /// Skips certificate chain validation, SCT checks, and identity checks.
    /// </summary>
    private static (bool Success, VerificationResult? Result) VerifyWithPublicKey(
        ArtifactInput artifactInput,
        SigstoreBundle bundle,
        VerificationPolicy policy,
        TrustedRoot trustRoot)
    {
        var verificationMaterial = bundle.VerificationMaterial;
        if (verificationMaterial == null)
            return Fail("Bundle has no verification material.");

        // Establish timestamps from tlog entries and RFC 3161 timestamps
        var verifiedTimestamps = new List<VerifiedTimestamp>();

        foreach (var tsBytes in verificationMaterial.Rfc3161Timestamps)
        {
            try
            {
                var tsInfo = TimestampParser.Parse(tsBytes);
                ReadOnlyMemory<byte> signatureToTimestamp = GetSignatureBytes(bundle);
                if (trustRoot.TimestampAuthorities.Count > 0)
                {
                    if (TimestampParser.Verify(tsInfo, signatureToTimestamp, trustRoot.TimestampAuthorities))
                    {
                        verifiedTimestamps.Add(new VerifiedTimestamp
                        {
                            Source = TimestampSource.TimestampAuthority,
                            Timestamp = tsInfo.Timestamp
                        });
                    }
                }
                else
                {
                    verifiedTimestamps.Add(new VerifiedTimestamp
                    {
                        Source = TimestampSource.TimestampAuthority,
                        Timestamp = tsInfo.Timestamp
                    });
                }
            }
            catch { }
        }

        foreach (var entry in verificationMaterial.TlogEntries)
        {
            if (entry.IntegratedTime > 0 && entry.InclusionPromise != null)
            {
                if (VerifySignedEntryTimestamp(entry, trustRoot))
                {
                    verifiedTimestamps.Add(new VerifiedTimestamp
                    {
                        Source = TimestampSource.TransparencyLog,
                        Timestamp = DateTimeOffset.FromUnixTimeSeconds(entry.IntegratedTime)
                    });
                }
            }
        }

        if (verifiedTimestamps.Count == 0)
            return Fail("No verified timestamps found. Need at least one timestamp from TSA or transparency log.");

        // Verify tlog inclusion proofs (using the public key for cross-verification)
        if (policy.RequireTransparencyLog)
        {
            int verifiedEntries = 0;
            foreach (var entry in verificationMaterial.TlogEntries)
            {
                if (VerifyTlogEntryForPublicKey(entry, trustRoot, bundle, policy.PublicKey!.Value))
                    verifiedEntries++;
            }

            if (verifiedEntries < policy.TransparencyLogThreshold)
                return Fail($"Only {verifiedEntries} transparency log entries verified, need {policy.TransparencyLogThreshold}.");
        }

        // Verify the artifact signature with the public key
        var sigResult = VerifyArtifactSignatureWithKey(artifactInput, bundle, policy.PublicKey!.Value);
        if (!sigResult.IsValid)
            return Fail($"Signature verification failed: {sigResult.Reason}");

        return (true, new VerificationResult
        {
            SignerIdentity = null,
            VerifiedTimestamps = verifiedTimestamps
        });
    }

    /// <summary>
    /// Verifies a tlog entry for managed-key bundles. Same as VerifyTlogEntry but
    /// cross-verifies the body against a raw public key instead of a certificate.
    /// </summary>
    private static bool VerifyTlogEntryForPublicKey(
        TransparencyLogEntry entry,
        TrustedRoot trustRoot,
        SigstoreBundle bundle,
        ReadOnlyMemory<byte> publicKeySpki)
    {
        if (entry.InclusionProof == null)
            return false;

        var logInfo = trustRoot.TransparencyLogs
            .FirstOrDefault(l => l.LogId.Span.SequenceEqual(entry.LogId.Span));

        if (logInfo == null)
            return false;

        // Verify checkpoint signature
        if (entry.InclusionProof.Checkpoint != null)
        {
            CheckpointData? checkpointData = null;
            foreach (var log in trustRoot.TransparencyLogs)
            {
                var keyIds = ComputeAllCheckpointKeyIds(log);
                foreach (var keyId in keyIds)
                {
                    checkpointData = CheckpointVerifier.VerifyCheckpoint(
                        entry.InclusionProof.Checkpoint,
                        log.PublicKeyBytes.Span,
                        keyId);
                    if (checkpointData != null)
                        break;
                }
                if (checkpointData != null)
                    break;
            }

            if (checkpointData == null)
                return false;

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
        else if (entry.InclusionProof.RootHash.Length > 0)
        {
            var body = entry.Body != null ? Convert.FromBase64String(entry.Body) : [];
            var leafHash = MerkleVerifier.HashLeaf(body);

            if (!MerkleVerifier.VerifyInclusionProof(
                leafHash,
                entry.InclusionProof.LogIndex,
                entry.InclusionProof.TreeSize,
                entry.InclusionProof.Hashes,
                entry.InclusionProof.RootHash.Span))
            {
                return false;
            }
        }

        // Cross-verify tlog entry body against bundle — for managed key, verify
        // that the hashedrekord publicKey content matches the provided key
        if (entry.Body != null)
        {
            if (!CrossVerifyTlogBodyForPublicKey(entry.Body, bundle, publicKeySpki))
                return false;
        }

        return true;
    }

    private static bool CrossVerifyTlogBodyForPublicKey(string body, SigstoreBundle bundle, ReadOnlyMemory<byte> publicKeySpki)
    {
        byte[] bodyBytes;
        try { bodyBytes = Convert.FromBase64String(body); }
        catch { return false; }

        JsonDocument doc;
        try { doc = JsonDocument.Parse(bodyBytes); }
        catch { return false; }

        var root = doc.RootElement;
        var kind = root.GetProperty("kind").GetString();

        if (kind == "hashedrekord")
        {
            var spec = root.GetProperty("spec");
            // Verify signature matches
            if (spec.TryGetProperty("signature", out var sigElem))
            {
                if (sigElem.TryGetProperty("content", out var sigContent))
                {
                    var expectedSig = Convert.FromBase64String(sigContent.GetString()!);
                    var bundleSig = bundle.MessageSignature?.Signature ?? default(ReadOnlyMemory<byte>);
                    if (!expectedSig.AsSpan().SequenceEqual(bundleSig.Span))
                        return false;
                }

                // Verify public key matches (for managed key, the tlog entry stores the public key PEM)
                if (sigElem.TryGetProperty("publicKey", out var pubKeyElem) &&
                    pubKeyElem.TryGetProperty("content", out var keyContent))
                {
                    var expectedKeyPem = Encoding.UTF8.GetString(Convert.FromBase64String(keyContent.GetString()!));
                    var expectedKeyDer = ConvertPemPublicKeyToDer(expectedKeyPem);
                    if (expectedKeyDer != null && !expectedKeyDer.AsSpan().SequenceEqual(publicKeySpki.Span))
                        return false;
                }
            }

            return true;
        }

        // For other kinds, allow
        return true;
    }

    private static byte[]? ConvertPemPublicKeyToDer(string pem)
    {
        var base64 = pem
            .Replace("-----BEGIN PUBLIC KEY-----", "")
            .Replace("-----END PUBLIC KEY-----", "")
            .Replace("\n", "")
            .Replace("\r", "")
            .Trim();

        if (string.IsNullOrEmpty(base64))
            return null;

        try { return Convert.FromBase64String(base64); }
        catch { return null; }
    }

    /// <summary>
    /// Verifies an artifact signature using a raw SPKI public key.
    /// </summary>
    private static (bool IsValid, string? Reason) VerifyArtifactSignatureWithKey(
        ArtifactInput artifactInput,
        SigstoreBundle bundle,
        ReadOnlyMemory<byte> publicKeySpki)
    {
        if (bundle.MessageSignature != null)
        {
            return VerifyMessageSignatureWithKey(artifactInput, bundle.MessageSignature, publicKeySpki);
        }

        if (bundle.DsseEnvelope != null)
        {
            return VerifyDsseSignatureWithKey(bundle.DsseEnvelope, publicKeySpki);
        }

        return (false, "Bundle contains neither a message signature nor a DSSE envelope.");
    }

    private static (bool IsValid, string? Reason) VerifyMessageSignatureWithKey(
        ArtifactInput artifactInput,
        MessageSignature messageSig,
        ReadOnlyMemory<byte> publicKeySpki)
    {
        if (messageSig.Signature.Length == 0)
            return (false, "Message signature is empty.");

        if (artifactInput.IsDigest)
        {
            if (messageSig.MessageDigest is { Digest.Length: > 0 } digest)
            {
                if (!artifactInput.Digest.Span.SequenceEqual(digest.Digest.Span))
                    return (false, "Message digest in bundle does not match provided artifact digest.");
            }
            return VerifyHashWithKey(artifactInput.Digest.Span, messageSig.Signature.Span, publicKeySpki);
        }

        // Stream-based
        byte[] artifactBytes;
        var stream = artifactInput.Stream!;
        if (stream is MemoryStream ms && ms.TryGetBuffer(out var buffer))
        {
            artifactBytes = buffer.ToArray();
        }
        else
        {
            using var memStream = new MemoryStream();
            stream.Position = 0;
            stream.CopyTo(memStream);
            artifactBytes = memStream.ToArray();
        }

        if (messageSig.MessageDigest is { Digest.Length: > 0 } bundleDigest)
        {
            byte[] computedHash = bundleDigest.Algorithm switch
            {
                HashAlgorithmType.Sha256 => SHA256.HashData(artifactBytes),
                HashAlgorithmType.Sha384 => SHA384.HashData(artifactBytes),
                HashAlgorithmType.Sha512 => SHA512.HashData(artifactBytes),
                _ => SHA256.HashData(artifactBytes)
            };
            if (!computedHash.AsSpan().SequenceEqual(bundleDigest.Digest.Span))
                return (false, "Message digest in bundle does not match artifact hash.");
        }

        return VerifyDataWithKey(artifactBytes, messageSig.Signature.Span, publicKeySpki);
    }

    private static (bool IsValid, string? Reason) VerifyDsseSignatureWithKey(
        DsseEnvelope envelope,
        ReadOnlyMemory<byte> publicKeySpki)
    {
        if (envelope.Signatures.Count == 0)
            return (false, "DSSE envelope has no signatures.");

        var payloadType = envelope.PayloadType;
        var payload = envelope.Payload;
        var pae = Encoding.UTF8.GetBytes(
            $"DSSEv1 {payloadType.Length} {payloadType} {payload.Length} ");
        var paeBytes = new byte[pae.Length + payload.Length];
        pae.CopyTo(paeBytes, 0);
        payload.Span.CopyTo(paeBytes.AsSpan(pae.Length));

        var sig = envelope.Signatures[0].Sig;
        return VerifyDataWithKey(paeBytes, sig.Span, publicKeySpki);
    }

    private static (bool IsValid, string? Reason) VerifyDataWithKey(
        byte[] data, ReadOnlySpan<byte> signature, ReadOnlyMemory<byte> publicKeySpki)
    {
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(publicKeySpki.Span, out _);
            bool valid = ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
            return valid ? (true, null) : (false, "ECDSA signature verification failed.");
        }
        catch (CryptographicException) { }

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(publicKeySpki.Span, out _);
            bool valid = rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return valid ? (true, null) : (false, "RSA signature verification failed.");
        }
        catch (CryptographicException) { }

        return (false, "Unsupported public key algorithm.");
    }

    private static (bool IsValid, string? Reason) VerifyHashWithKey(
        ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, ReadOnlyMemory<byte> publicKeySpki)
    {
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(publicKeySpki.Span, out _);
            bool valid = ecdsa.VerifyHash(hash, signature, DSASignatureFormat.Rfc3279DerSequence);
            return valid ? (true, null) : (false, "ECDSA signature verification failed.");
        }
        catch (CryptographicException) { }

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(publicKeySpki.Span, out _);
            bool valid = rsa.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return valid ? (true, null) : (false, "RSA signature verification failed.");
        }
        catch (CryptographicException) { }

        return (false, "Unsupported public key algorithm.");
    }

    private static (bool Success, VerificationResult? Result) Fail(string reason)
    {
        return (false, new VerificationResult { FailureReason = reason });
    }

    private static ReadOnlyMemory<byte> GetSignatureBytes(SigstoreBundle bundle)
    {
        if (bundle.MessageSignature?.Signature is { Length: > 0 } sig)
            return sig;
        if (bundle.DsseEnvelope?.Signatures is { Count: > 0 } sigs)
            return sigs[0].Sig;
        return default;
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
        TrustedRoot trustRoot,
        SigstoreBundle bundle,
        ReadOnlyMemory<byte> leafCertBytes)
    {
        if (entry.InclusionProof == null)
            return false;

        // Find matching log by logId
        var logInfo = trustRoot.TransparencyLogs
            .FirstOrDefault(l => l.LogId.Span.SequenceEqual(entry.LogId.Span));

        if (logInfo == null)
            return false;

        // Verify checkpoint signature
        if (entry.InclusionProof.Checkpoint != null)
        {
            // Try verifying the checkpoint against ALL transparency log keys from the trusted root,
            // since the checkpoint may be signed by a different key than the entry's logId
            // (e.g., rekor2 uses Ed25519 note keys with different key ID computation)
            CheckpointData? checkpointData = null;
            foreach (var log in trustRoot.TransparencyLogs)
            {
                var keyIds = ComputeAllCheckpointKeyIds(log);
                foreach (var keyId in keyIds)
                {
                    checkpointData = CheckpointVerifier.VerifyCheckpoint(
                        entry.InclusionProof.Checkpoint,
                        log.PublicKeyBytes.Span,
                        keyId);
                    if (checkpointData != null)
                        break;
                }
                if (checkpointData != null)
                    break;
            }

            if (checkpointData == null)
            {
                // Checkpoint signature verification failed — reject the entry
                return false;
            }

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
                entry.InclusionProof.RootHash.Span))
            {
                return false;
            }
        }

        // Cross-verify tlog entry body against the bundle contents
        if (entry.Body != null)
        {
            if (!CrossVerifyTlogBody(entry.Body, bundle, leafCertBytes))
                return false;
        }

        return true;
    }

    private static bool CrossVerifyTlogBody(string body, SigstoreBundle bundle, ReadOnlyMemory<byte> leafCertBytes)
    {
        byte[] bodyBytes;
        try
        {
            bodyBytes = Convert.FromBase64String(body);
        }
        catch
        {
            return false;
        }

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(bodyBytes);
        }
        catch
        {
            return false;
        }

        var root = doc.RootElement;
        var kind = root.GetProperty("kind").GetString();

        if (kind == "hashedrekord")
        {
            return CrossVerifyHashedrekord(root.GetProperty("spec"), bundle, leafCertBytes);
        }
        else if (kind == "dsse" || kind == "intoto")
        {
            return CrossVerifyDsse(root.GetProperty("spec"), bundle, leafCertBytes);
        }

        // Unknown kind — allow
        return true;
    }

    private static bool CrossVerifyHashedrekord(JsonElement spec, SigstoreBundle bundle, ReadOnlyMemory<byte> leafCertBytes)
    {
        // Verify signature matches
        if (spec.TryGetProperty("signature", out var sigElem))
        {
            if (sigElem.TryGetProperty("content", out var sigContent))
            {
                var expectedSig = Convert.FromBase64String(sigContent.GetString()!);
                // DSSE bundles store signature in the envelope, not MessageSignature
                var bundleSig = bundle.MessageSignature?.Signature
                    ?? bundle.DsseEnvelope?.Signatures.FirstOrDefault()?.Sig
                    ?? default(ReadOnlyMemory<byte>);
                if (!expectedSig.AsSpan().SequenceEqual(bundleSig.Span))
                    return false;
            }

            // Verify certificate matches
            if (sigElem.TryGetProperty("publicKey", out var pubKeyElem) &&
                pubKeyElem.TryGetProperty("content", out var certContent))
            {
                var expectedCertPem = Encoding.UTF8.GetString(Convert.FromBase64String(certContent.GetString()!));
                var expectedCertDer = ConvertPemToDer(expectedCertPem);
                if (expectedCertDer != null && !expectedCertDer.AsSpan().SequenceEqual(leafCertBytes.Span))
                    return false;
            }
        }

        return true;
    }

    private static bool CrossVerifyDsse(JsonElement spec, SigstoreBundle bundle, ReadOnlyMemory<byte> leafCertBytes)
    {
        if (bundle.DsseEnvelope == null)
            return false;

        // Handle three formats:
        // 1. dsseV002: spec.dsseV002.{signatures, payloadHash} (Rekor v2)
        // 2. intoto: spec.content.{envelope, payloadHash} (Rekor v1)
        // 3. dsse v0.0.1: spec.{signatures, payloadHash} (Rekor v1)

        if (spec.TryGetProperty("dsseV002", out var dsseV002))
        {
            return CrossVerifyDsseV002(dsseV002, bundle, leafCertBytes);
        }

        JsonElement sigSource;
        JsonElement? payloadHashElem = null;

        if (spec.TryGetProperty("content", out var content))
        {
            // intoto format: spec.content.{envelope, hash, payloadHash}
            if (!content.TryGetProperty("envelope", out var envelope))
                return true; // no envelope to cross-check
            sigSource = envelope;
            if (content.TryGetProperty("payloadHash", out var ph))
                payloadHashElem = ph;
        }
        else
        {
            // dsse format: spec.{signatures, payloadHash, envelopeHash}
            sigSource = spec;
            if (spec.TryGetProperty("payloadHash", out var ph))
                payloadHashElem = ph;
        }

        // Verify signature matches
        if (sigSource.TryGetProperty("signatures", out var sigs) && sigs.GetArrayLength() > 0)
        {
            var firstSig = sigs[0];
            if (firstSig.TryGetProperty("signature", out var sigContent) ||
                firstSig.TryGetProperty("sig", out sigContent))
            {
                var sigStr = sigContent.GetString()!;
                // The body may contain base64-of-base64 (intoto format stores
                // the envelope JSON with base64 sigs, which then gets base64-encoded again).
                // Try to decode and compare at the raw level.
                byte[] expectedSig;
                try
                {
                    expectedSig = Convert.FromBase64String(sigStr);
                }
                catch
                {
                    return false;
                }

                var bundleSig = bundle.DsseEnvelope.Signatures.Count > 0
                    ? bundle.DsseEnvelope.Signatures[0].Sig
                    : default(ReadOnlyMemory<byte>);

                // Direct comparison first
                if (!expectedSig.AsSpan().SequenceEqual(bundleSig.Span))
                {
                    // Try one more level of base64 decode (intoto v0.0.2 double-encodes)
                    try
                    {
                        var innerStr = Encoding.UTF8.GetString(expectedSig);
                        var innerSig = Convert.FromBase64String(innerStr);
                        if (!innerSig.AsSpan().SequenceEqual(bundleSig.Span))
                            return false;
                    }
                    catch
                    {
                        return false;
                    }
                }
            }

            // Verify certificate matches
            if (firstSig.TryGetProperty("verifier", out var verifierContent))
            {
                var expectedCertPem = Encoding.UTF8.GetString(Convert.FromBase64String(verifierContent.GetString()!));
                var expectedCertDer = ConvertPemToDer(expectedCertPem);
                if (expectedCertDer != null && !expectedCertDer.AsSpan().SequenceEqual(leafCertBytes.Span))
                    return false;
            }
        }

        // Verify payload hash matches
        if (payloadHashElem is JsonElement hashEl &&
            hashEl.TryGetProperty("value", out var hashValue))
        {
            var expectedHash = hashValue.GetString()!;
            var payloadBytes = bundle.DsseEnvelope.Payload;
            var computedHash = Convert.ToHexString(SHA256.HashData(payloadBytes.Span)).ToLowerInvariant();
            if (computedHash != expectedHash)
                return false;
        }

        return true;
    }

    private static bool CrossVerifyDsseV002(JsonElement dsseV002, SigstoreBundle bundle, ReadOnlyMemory<byte> leafCertBytes)
    {
        if (bundle.DsseEnvelope == null)
            return false;

        // Verify signature matches
        if (dsseV002.TryGetProperty("signatures", out var sigs) && sigs.GetArrayLength() > 0)
        {
            var firstSig = sigs[0];
            if (firstSig.TryGetProperty("content", out var sigContent))
            {
                var expectedSig = Convert.FromBase64String(sigContent.GetString()!);
                var bundleSig = bundle.DsseEnvelope.Signatures.Count > 0
                    ? bundle.DsseEnvelope.Signatures[0].Sig
                    : default(ReadOnlyMemory<byte>);
                if (!expectedSig.AsSpan().SequenceEqual(bundleSig.Span))
                    return false;
            }

            // Verify certificate matches
            if (firstSig.TryGetProperty("verifier", out var verifier))
            {
                byte[]? expectedCertDer = null;
                if (verifier.TryGetProperty("x509Certificate", out var x509) &&
                    x509.TryGetProperty("rawBytes", out var rawBytes))
                {
                    expectedCertDer = Convert.FromBase64String(rawBytes.GetString()!);
                }
                if (expectedCertDer != null && !expectedCertDer.AsSpan().SequenceEqual(leafCertBytes.Span))
                    return false;
            }
        }

        // Verify payload hash matches
        if (dsseV002.TryGetProperty("payloadHash", out var hashElem) &&
            hashElem.TryGetProperty("digest", out var digest))
        {
            var expectedHash = Convert.FromBase64String(digest.GetString()!);
            var payloadBytes = bundle.DsseEnvelope.Payload;
            var computedHash = SHA256.HashData(payloadBytes.Span);
            if (!computedHash.AsSpan().SequenceEqual(expectedHash))
                return false;
        }

        return true;
    }

    private static byte[]? ConvertPemToDer(string pem)
    {
        try
        {
            var lines = pem.Split('\n')
                .Where(l => !l.StartsWith("-----"))
                .Select(l => l.Trim());
            return Convert.FromBase64String(string.Join("", lines));
        }
        catch
        {
            return null;
        }
    }

    private static byte[] ComputeCheckpointKeyId(ReadOnlyMemory<byte> publicKeyBytes)
    {
        var hash = SHA256.HashData(publicKeyBytes.Span);
        return hash.AsSpan(0, 4).ToArray();
    }

    /// <summary>
    /// Computes all possible checkpoint key IDs for a transparency log.
    /// Different key types and log versions use different key ID computation:
    /// - Rekor v1 ECDSA: SHA256(SPKI_DER)[:4]
    /// - Rekor v2 Ed25519 (note format): SHA256(origin + "\n" + 0x01 + raw_ed25519_key)[:4]
    /// </summary>
    private static List<byte[]> ComputeAllCheckpointKeyIds(TransparencyLogInfo log)
    {
        var result = new List<byte[]>();

        // Explicit checkpoint key ID takes priority
        if (log.CheckpointKeyId.HasValue && log.CheckpointKeyId.Value.Length > 0)
        {
            result.Add(log.CheckpointKeyId.Value.ToArray());
            return result;
        }

        // Standard: SHA256(publicKeyBytes)[:4]
        result.Add(ComputeCheckpointKeyId(log.PublicKeyBytes));

        // For Ed25519 keys, also compute the note verifier key ID format:
        // SHA256(origin + "\n" + 0x01 + raw_ed25519_key_32_bytes)[:4]
        if (log.PublicKeyBytes.Length == 44 || // Ed25519 SPKI is 44 bytes
            log.KeyDetails == PublicKeyDetails.PkixEd25519)
        {
            // Extract the 32-byte raw Ed25519 key from SPKI format
            byte[] rawKey;
            if (log.PublicKeyBytes.Length == 44)
            {
                rawKey = log.PublicKeyBytes.Span.Slice(12).ToArray(); // SPKI overhead is 12 bytes for Ed25519
            }
            else
            {
                rawKey = log.PublicKeyBytes.ToArray(); // Assume raw 32-byte key
            }

            // Try with the hostname from baseUrl
            if (log.BaseUrl is not null)
            {
                string origin = log.BaseUrl.Host;

                // Note format key ID: SHA256(origin + "\n" + algByte + rawKey)[:4]
                // algByte = 0x01 for Ed25519
                var data = new byte[Encoding.UTF8.GetByteCount(origin) + 1 + 1 + rawKey.Length];
                int offset = Encoding.UTF8.GetBytes(origin, data);
                data[offset++] = (byte)'\n';
                data[offset++] = 0x01; // Ed25519 algorithm byte
                rawKey.CopyTo(data, offset);
                result.Add(SHA256.HashData(data).AsSpan(0, 4).ToArray());
            }

            // Also try logId[:4] directly
            if (log.LogId.Length >= 4)
            {
                result.Add(log.LogId.Span[..4].ToArray());
            }
        }

        return result;
    }

    /// <summary>
    /// Verifies the Signed Entry Timestamp (SET / inclusion promise) for a tlog entry.
    /// The SET is the log's ECDSA signature over the canonicalized JSON payload:
    /// {"body": base64(canonicalizedBody), "integratedTime": N, "logID": hex(keyId), "logIndex": N}
    /// </summary>
    private static bool VerifySignedEntryTimestamp(TransparencyLogEntry entry, TrustedRoot trustRoot)
    {
        if (entry.InclusionPromise == null || entry.Body == null)
            return false;

        // Find matching log by logId
        var logInfo = trustRoot.TransparencyLogs
            .FirstOrDefault(l => l.LogId.Span.SequenceEqual(entry.LogId.Span));
        if (logInfo == null)
            return false;

        // Check log validity period
        var entryTime = DateTimeOffset.FromUnixTimeSeconds(entry.IntegratedTime);
        if (logInfo.ValidFrom.HasValue && entryTime < logInfo.ValidFrom.Value)
            return false;
        if (logInfo.ValidTo.HasValue && entryTime > logInfo.ValidTo.Value)
            return false;

        // Construct the SET payload (same format as Rekor API response)
        var logIdHex = Convert.ToHexString(entry.LogId.Span).ToLowerInvariant();
        var payloadJson = $"{{\"body\":\"{entry.Body}\",\"integratedTime\":{entry.IntegratedTime},\"logID\":\"{logIdHex}\",\"logIndex\":{entry.LogIndex}}}";

        // Canonicalize — the payload is already in canonical form (sorted keys, no whitespace)
        // but we hash it as-is since Rekor uses this exact format
        var payloadBytes = Encoding.UTF8.GetBytes(payloadJson);
        var hash = SHA256.HashData(payloadBytes);

        try
        {
            using var ecdsa = LoadEcdsaPublicKey(logInfo.PublicKeyBytes.Span);
            if (ecdsa == null)
                return false;

            return ecdsa.VerifyHash(hash, entry.InclusionPromise.Value.Span, DSASignatureFormat.Rfc3279DerSequence);
        }
        catch
        {
            return false;
        }
    }

    private static ECDsa? LoadEcdsaPublicKey(ReadOnlySpan<byte> publicKeyBytes)
    {
        try
        {
            // Try as SubjectPublicKeyInfo (DER)
            var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
            return ecdsa;
        }
        catch
        {
            try
            {
                // Try as PEM
                var pem = Encoding.UTF8.GetString(publicKeyBytes);
                var ecdsa = ECDsa.Create();
                ecdsa.ImportFromPem(pem);
                return ecdsa;
            }
            catch
            {
                return null;
            }
        }
    }

    private static (bool IsValid, string? Reason) VerifyArtifactSignature(
        ArtifactInput artifactInput,
        SigstoreBundle bundle,
        X509Certificate2 leafCert)
    {
        if (bundle.MessageSignature != null)
        {
            return VerifyMessageSignature(artifactInput, bundle.MessageSignature, leafCert);
        }

        if (bundle.DsseEnvelope != null)
        {
            return VerifyDsseSignature(bundle.DsseEnvelope, leafCert);
        }

        return (false, "Bundle contains neither a message signature nor a DSSE envelope.");
    }

    private static (bool IsValid, string? Reason) VerifyMessageSignature(
        ArtifactInput artifactInput,
        MessageSignature messageSig,
        X509Certificate2 leafCert)
    {
        if (messageSig.Signature.Length == 0)
            return (false, "Message signature is empty.");

        if (artifactInput.IsDigest)
        {
            // Digest-based verification: compare provided digest with bundle's digest
            if (messageSig.MessageDigest is { Digest.Length: > 0 } digest)
            {
                if (!artifactInput.Digest.Span.SequenceEqual(digest.Digest.Span))
                    return (false, "Message digest in bundle does not match provided artifact digest.");
            }

            // The signer signed the hash of the artifact. We have the hash (the digest).
            // Use VerifyHash to verify the signature directly against the digest.
            return VerifyHashWithCert(artifactInput.Digest.Span, messageSig.Signature.Span, leafCert);
        }

        // Stream-based verification
        byte[] artifactBytes;
        var stream = artifactInput.Stream!;
        if (stream is MemoryStream ms && ms.TryGetBuffer(out var buffer))
        {
            artifactBytes = buffer.ToArray();
        }
        else
        {
            using var memStream = new MemoryStream();
            stream.Position = 0;
            stream.CopyTo(memStream);
            artifactBytes = memStream.ToArray();
        }

        // Check message digest consistency if present
        if (messageSig.MessageDigest is { Digest.Length: > 0 } bundleDigest)
        {
            byte[] computedHash = bundleDigest.Algorithm switch
            {
                HashAlgorithmType.Sha256 => SHA256.HashData(artifactBytes),
                HashAlgorithmType.Sha384 => SHA384.HashData(artifactBytes),
                HashAlgorithmType.Sha512 => SHA512.HashData(artifactBytes),
                _ => SHA256.HashData(artifactBytes)
            };
            if (!computedHash.AsSpan().SequenceEqual(bundleDigest.Digest.Span))
                return (false, "Message digest in bundle does not match artifact hash.");
        }

        return VerifySignatureWithCert(artifactBytes, messageSig.Signature.Span, leafCert);
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
        payload.Span.CopyTo(paeBytes.AsSpan(pae.Length));

        var sig = envelope.Signatures[0].Sig;
        return VerifySignatureWithCert(paeBytes, sig.Span, leafCert);
    }

    private static (bool IsValid, string? Reason) VerifySignatureWithCert(
        byte[] data,
        ReadOnlySpan<byte> signature,
        X509Certificate2 leafCert)
    {
        // Try ECDSA
        using var ecdsa = leafCert.GetECDsaPublicKey();
        if (ecdsa != null)
        {
            bool valid = ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
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

    private static (bool IsValid, string? Reason) VerifyHashWithCert(
        ReadOnlySpan<byte> hash,
        ReadOnlySpan<byte> signature,
        X509Certificate2 leafCert)
    {
        // Try ECDSA
        using var ecdsa = leafCert.GetECDsaPublicKey();
        if (ecdsa != null)
        {
            bool valid = ecdsa.VerifyHash(hash, signature, DSASignatureFormat.Rfc3279DerSequence);
            return valid
                ? (true, null)
                : (false, "ECDSA signature verification failed.");
        }

        // Try RSA
        using var rsa = leafCert.GetRSAPublicKey();
        if (rsa != null)
        {
            bool valid = rsa.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return valid
                ? (true, null)
                : (false, "RSA signature verification failed.");
        }

        return (false, "Unsupported public key algorithm in certificate.");
    }

    /// <summary>
    /// Represents either an artifact stream or a pre-computed digest for verification.
    /// </summary>
    internal readonly struct ArtifactInput
    {
        public Stream? Stream { get; }
        public ReadOnlyMemory<byte> Digest { get; }
        public HashAlgorithmType DigestAlgorithm { get; }
        public bool IsDigest { get; }

        private ArtifactInput(Stream? stream, ReadOnlyMemory<byte> digest, HashAlgorithmType algorithm, bool isDigest)
        {
            Stream = stream;
            Digest = digest;
            DigestAlgorithm = algorithm;
            IsDigest = isDigest;
        }

        public static ArtifactInput FromStream(Stream stream) =>
            new(stream, default, default, false);

        public static ArtifactInput FromDigest(ReadOnlyMemory<byte> digest, HashAlgorithmType algorithm) =>
            new(null, digest, algorithm, true);
    }
}
