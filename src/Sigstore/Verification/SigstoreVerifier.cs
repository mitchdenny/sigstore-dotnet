using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
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
    /// Downloads the trusted root from the Sigstore public-good TUF target on first use.
    /// </summary>
    public SigstoreVerifier()
    {
        _trustRootProvider = new TrustRoot.PublicGoodTrustRootProvider();
        _certificateValidator = new DefaultCertificateValidator();
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

            // Reject bundles where the chain contains a root (self-signed) certificate
            if (verificationMaterial.CertificateChain is { Count: > 0 })
            {
                foreach (var certBytes in verificationMaterial.CertificateChain)
                {
                    using var cert = X509CertificateLoader.LoadCertificate(certBytes);
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

                    byte[] signatureToTimestamp = GetSignatureBytes(bundle);
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
                        log.PublicKeyBytes,
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
                entry.InclusionProof.RootHash))
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

    private static bool CrossVerifyTlogBody(string body, SigstoreBundle bundle, byte[] leafCertBytes)
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

    private static bool CrossVerifyHashedrekord(JsonElement spec, SigstoreBundle bundle, byte[] leafCertBytes)
    {
        // Verify signature matches
        if (spec.TryGetProperty("signature", out var sigElem))
        {
            if (sigElem.TryGetProperty("content", out var sigContent))
            {
                var expectedSig = Convert.FromBase64String(sigContent.GetString()!);
                var bundleSig = bundle.MessageSignature?.Signature ?? [];
                if (!expectedSig.AsSpan().SequenceEqual(bundleSig))
                    return false;
            }

            // Verify certificate matches
            if (sigElem.TryGetProperty("publicKey", out var pubKeyElem) &&
                pubKeyElem.TryGetProperty("content", out var certContent))
            {
                var expectedCertPem = Encoding.UTF8.GetString(Convert.FromBase64String(certContent.GetString()!));
                var expectedCertDer = ConvertPemToDer(expectedCertPem);
                if (expectedCertDer != null && !expectedCertDer.AsSpan().SequenceEqual(leafCertBytes))
                    return false;
            }
        }

        return true;
    }

    private static bool CrossVerifyDsse(JsonElement spec, SigstoreBundle bundle, byte[] leafCertBytes)
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
                    : [];

                // Direct comparison first
                if (!expectedSig.AsSpan().SequenceEqual(bundleSig))
                {
                    // Try one more level of base64 decode (intoto v0.0.2 double-encodes)
                    try
                    {
                        var innerStr = Encoding.UTF8.GetString(expectedSig);
                        var innerSig = Convert.FromBase64String(innerStr);
                        if (!innerSig.AsSpan().SequenceEqual(bundleSig))
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
                if (expectedCertDer != null && !expectedCertDer.AsSpan().SequenceEqual(leafCertBytes))
                    return false;
            }
        }

        // Verify payload hash matches
        if (payloadHashElem is JsonElement hashEl &&
            hashEl.TryGetProperty("value", out var hashValue))
        {
            var expectedHash = hashValue.GetString()!;
            var payloadBytes = bundle.DsseEnvelope.Payload;
            var computedHash = Convert.ToHexString(SHA256.HashData(payloadBytes)).ToLowerInvariant();
            if (computedHash != expectedHash)
                return false;
        }

        return true;
    }

    private static bool CrossVerifyDsseV002(JsonElement dsseV002, SigstoreBundle bundle, byte[] leafCertBytes)
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
                    : [];
                if (!expectedSig.AsSpan().SequenceEqual(bundleSig))
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
                if (expectedCertDer != null && !expectedCertDer.AsSpan().SequenceEqual(leafCertBytes))
                    return false;
            }
        }

        // Verify payload hash matches
        if (dsseV002.TryGetProperty("payloadHash", out var hashElem) &&
            hashElem.TryGetProperty("digest", out var digest))
        {
            var expectedHash = Convert.FromBase64String(digest.GetString()!);
            var payloadBytes = bundle.DsseEnvelope.Payload;
            var computedHash = SHA256.HashData(payloadBytes);
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

    private static byte[] ComputeCheckpointKeyId(byte[] publicKeyBytes)
    {
        var hash = SHA256.HashData(publicKeyBytes);
        return hash.AsSpan(0, 4).ToArray();
    }

    /// <summary>
    /// Computes all possible checkpoint key IDs for a transparency log.
    /// Different key types and log versions use different key ID computation:
    /// - Rekor v1 ECDSA: SHA256(SPKI_DER)[:4]
    /// - Rekor v2 Ed25519 (note format): SHA256(origin + "\n" + 0x01 + raw_ed25519_key)[:4]
    /// </summary>
    private static List<byte[]> ComputeAllCheckpointKeyIds(TrustRoot.TransparencyLogInfo log)
    {
        var result = new List<byte[]>();

        // Explicit checkpoint key ID takes priority
        if (log.CheckpointKeyId != null && log.CheckpointKeyId.Length > 0)
        {
            result.Add(log.CheckpointKeyId);
            return result;
        }

        // Standard: SHA256(publicKeyBytes)[:4]
        result.Add(ComputeCheckpointKeyId(log.PublicKeyBytes));

        // For Ed25519 keys, also compute the note verifier key ID format:
        // SHA256(origin + "\n" + 0x01 + raw_ed25519_key_32_bytes)[:4]
        if (log.PublicKeyBytes.Length == 44 || // Ed25519 SPKI is 44 bytes
            log.KeyDetails == Common.PublicKeyDetails.PkixEd25519)
        {
            // Extract the 32-byte raw Ed25519 key from SPKI format
            byte[] rawKey;
            if (log.PublicKeyBytes.Length == 44)
            {
                rawKey = log.PublicKeyBytes.AsSpan(12).ToArray(); // SPKI overhead is 12 bytes for Ed25519
            }
            else
            {
                rawKey = log.PublicKeyBytes; // Assume raw 32-byte key
            }

            // Try with the hostname from baseUrl
            if (!string.IsNullOrEmpty(log.BaseUrl))
            {
                string origin;
                try { origin = new Uri(log.BaseUrl).Host; }
                catch { origin = log.BaseUrl; }

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
                result.Add(log.LogId.AsSpan(0, 4).ToArray());
            }
        }

        return result;
    }

    /// <summary>
    /// Verifies the Signed Entry Timestamp (SET / inclusion promise) for a tlog entry.
    /// The SET is the log's ECDSA signature over the canonicalized JSON payload:
    /// {"body": base64(canonicalizedBody), "integratedTime": N, "logID": hex(keyId), "logIndex": N}
    /// </summary>
    private static bool VerifySignedEntryTimestamp(TransparencyLogEntry entry, TrustRoot.TrustedRoot trustRoot)
    {
        if (entry.InclusionPromise == null || entry.Body == null)
            return false;

        // Find matching log by logId
        var logInfo = trustRoot.TransparencyLogs
            .FirstOrDefault(l => l.LogId.SequenceEqual(entry.LogId));
        if (logInfo == null)
            return false;

        // Check log validity period
        var entryTime = DateTimeOffset.FromUnixTimeSeconds(entry.IntegratedTime);
        if (logInfo.ValidFrom.HasValue && entryTime < logInfo.ValidFrom.Value)
            return false;
        if (logInfo.ValidTo.HasValue && entryTime > logInfo.ValidTo.Value)
            return false;

        // Construct the SET payload (same format as Rekor API response)
        var logIdHex = Convert.ToHexString(entry.LogId).ToLowerInvariant();
        var payloadJson = $"{{\"body\":\"{entry.Body}\",\"integratedTime\":{entry.IntegratedTime},\"logID\":\"{logIdHex}\",\"logIndex\":{entry.LogIndex}}}";

        // Canonicalize — the payload is already in canonical form (sorted keys, no whitespace)
        // but we hash it as-is since Rekor uses this exact format
        var payloadBytes = Encoding.UTF8.GetBytes(payloadJson);
        var hash = SHA256.HashData(payloadBytes);

        try
        {
            using var ecdsa = LoadEcdsaPublicKey(logInfo.PublicKeyBytes);
            if (ecdsa == null)
                return false;

            return ecdsa.VerifyHash(hash, entry.InclusionPromise, DSASignatureFormat.Rfc3279DerSequence);
        }
        catch
        {
            return false;
        }
    }

    private static ECDsa? LoadEcdsaPublicKey(byte[] publicKeyBytes)
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

        // Check message digest consistency if present
        if (messageSig.MessageDigest is { Digest.Length: > 0 } digest)
        {
            byte[] computedHash = digest.Algorithm switch
            {
                HashAlgorithmType.Sha2_256 => SHA256.HashData(artifactBytes),
                HashAlgorithmType.Sha2_384 => SHA384.HashData(artifactBytes),
                HashAlgorithmType.Sha2_512 => SHA512.HashData(artifactBytes),
                _ => SHA256.HashData(artifactBytes)
            };
            if (!computedHash.AsSpan().SequenceEqual(digest.Digest))
                return (false, "Message digest in bundle does not match artifact hash.");
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
}
