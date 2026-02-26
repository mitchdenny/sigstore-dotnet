using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Sigstore.TrustRoot;

namespace Sigstore.Verification;

/// <summary>
/// Verifies Signed Certificate Timestamps (SCTs) embedded in X.509 certificates
/// per RFC 6962 §3.3.
/// </summary>
internal static class SctVerifier
{
    // OID for SCT list extension in X.509 certificates
    private const string SctListOid = "1.3.6.1.4.1.11129.2.4.2";
    // OID for the CT poison extension (precertificate marker)
    private const string PoisonOid = "1.3.6.1.4.1.11129.2.4.3";

    /// <summary>
    /// Verifies that at least one SCT in the leaf certificate is signed by a
    /// CT log key from the trusted root.
    /// </summary>
    /// <returns>True if at least one SCT verifies, or if there are no CT logs in the trusted root.</returns>
    public static bool VerifyScts(
        X509Certificate2 leafCert,
        X509Certificate2? issuerCert,
        IReadOnlyList<TransparencyLogInfo> ctLogs)
    {
        // If no CT logs configured, SCT verification is not required
        if (ctLogs.Count == 0)
            return true;

        // Parse SCTs from the certificate
        var scts = ParseScts(leafCert);
        if (scts.Count == 0)
            return true; // No SCTs to verify — skip (some bundles may not have them)

        // Build lookup of CT log keys by log ID
        var ctLogsByLogId = new Dictionary<string, TransparencyLogInfo>();
        foreach (var ct in ctLogs)
        {
            var logId = ComputeCtLogId(ct.PublicKeyBytes);
            ctLogsByLogId[Convert.ToHexString(logId)] = ct;
        }

        // Verify at least one SCT
        foreach (var sct in scts)
        {
            var logIdHex = Convert.ToHexString(sct.LogId);
            if (!ctLogsByLogId.TryGetValue(logIdHex, out var ctLog))
                continue; // Unknown log — skip this SCT

            if (VerifySctSignature(sct, ctLog, leafCert, issuerCert))
                return true;
        }

        return false; // No SCT could be verified
    }

    /// <summary>
    /// Computes the CT log ID as SHA-256 of the log's public key DER.
    /// </summary>
    private static byte[] ComputeCtLogId(byte[] publicKeyBytes)
    {
        return SHA256.HashData(publicKeyBytes);
    }

    /// <summary>
    /// Parses the SCT list extension from the certificate.
    /// The SCT list is a TLS-encoded list per RFC 6962 §3.3.
    /// </summary>
    private static List<Sct> ParseScts(X509Certificate2 cert)
    {
        var scts = new List<Sct>();

        var ext = cert.Extensions[SctListOid];
        if (ext == null)
            return scts;

        // The extension value is an ASN.1 OCTET STRING wrapping TLS-encoded SCT list
        var reader = new AsnReader(ext.RawData, AsnEncodingRules.DER);
        var sctListBytes = reader.ReadOctetString();

        // TLS encoding: uint16 list_length, then repeated { uint16 sct_length, opaque sct_data }
        int offset = 0;
        if (sctListBytes.Length < 2)
            return scts;

        int listLength = (sctListBytes[offset] << 8) | sctListBytes[offset + 1];
        offset += 2;

        int end = offset + listLength;
        if (end > sctListBytes.Length)
            end = sctListBytes.Length;

        while (offset + 2 <= end)
        {
            int sctLength = (sctListBytes[offset] << 8) | sctListBytes[offset + 1];
            offset += 2;

            if (offset + sctLength > end)
                break;

            var sctData = sctListBytes.AsSpan(offset, sctLength);
            offset += sctLength;

            var sct = ParseSingleSct(sctData);
            if (sct != null)
                scts.Add(sct);
        }

        return scts;
    }

    /// <summary>
    /// Parses a single SCT from TLS-encoded data per RFC 6962 §3.2.
    /// </summary>
    private static Sct? ParseSingleSct(ReadOnlySpan<byte> data)
    {
        if (data.Length < 1 + 32 + 8 + 2) // version + logId + timestamp + extensions_length
            return null;

        int offset = 0;

        byte version = data[offset++];
        if (version != 0) // v1
            return null;

        byte[] logId = data.Slice(offset, 32).ToArray();
        offset += 32;

        long timestampMs = 0;
        for (int i = 0; i < 8; i++)
            timestampMs = (timestampMs << 8) | data[offset++];

        // Extensions
        if (offset + 2 > data.Length) return null;
        int extLength = (data[offset] << 8) | data[offset + 1];
        offset += 2;
        byte[] extensions = extLength > 0 && offset + extLength <= data.Length
            ? data.Slice(offset, extLength).ToArray()
            : [];
        offset += extLength;

        // Signature: hash_algorithm(1) + sig_algorithm(1) + sig_length(2) + sig
        if (offset + 4 > data.Length) return null;
        byte hashAlg = data[offset++];
        byte sigAlg = data[offset++];
        int sigLength = (data[offset] << 8) | data[offset + 1];
        offset += 2;

        if (offset + sigLength > data.Length) return null;
        byte[] signature = data.Slice(offset, sigLength).ToArray();

        return new Sct
        {
            Version = version,
            LogId = logId,
            TimestampMs = timestampMs,
            Extensions = extensions,
            HashAlgorithm = hashAlg,
            SignatureAlgorithm = sigAlg,
            Signature = signature
        };
    }

    /// <summary>
    /// Verifies a single SCT signature per RFC 6962 §3.2.
    /// For precertificate SCTs, the signed data is:
    ///   sct_version(1) || signature_type(1) || timestamp(8) ||
    ///   entry_type(2) || issuer_key_hash(32) || tbs_cert_length(3) || tbs_cert ||
    ///   extensions_length(2) || extensions
    /// </summary>
    private static bool VerifySctSignature(
        Sct sct,
        TransparencyLogInfo ctLog,
        X509Certificate2 leafCert,
        X509Certificate2? issuerCert)
    {
        try
        {
            // Build the data to be signed
            byte[] signedData = BuildPrecertSignedData(sct, leafCert, issuerCert);

            // Verify using the CT log's public key
            using var ecdsa = LoadEcdsaFromSpki(ctLog.PublicKeyBytes);
            if (ecdsa != null)
            {
                return ecdsa.VerifyData(
                    signedData,
                    sct.Signature,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.Rfc3279DerSequence);
            }

            // RSA verification
            using var rsa = LoadRsaFromSpki(ctLog.PublicKeyBytes);
            if (rsa != null)
            {
                return rsa.VerifyData(
                    signedData,
                    sct.Signature,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Builds the signed data for a precertificate SCT per RFC 6962 §3.2.
    /// </summary>
    private static byte[] BuildPrecertSignedData(
        Sct sct,
        X509Certificate2 leafCert,
        X509Certificate2? issuerCert)
    {
        // Compute issuer key hash: SHA-256 of the issuer's SubjectPublicKeyInfo
        byte[] issuerKeyHash;
        if (issuerCert != null)
        {
            issuerKeyHash = SHA256.HashData(issuerCert.PublicKey.ExportSubjectPublicKeyInfo());
        }
        else
        {
            // Self-signed or no issuer — use the leaf's own key
            issuerKeyHash = SHA256.HashData(leafCert.PublicKey.ExportSubjectPublicKeyInfo());
        }

        // Get the pre-TBS certificate: the TBSCertificate with the poison and SCT extensions removed
        byte[] preTbs = BuildPreTbsCertificate(leafCert);

        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        // sct_version: v1 = 0
        writer.Write((byte)0);
        // signature_type: certificate_timestamp = 0
        writer.Write((byte)0);
        // timestamp: uint64 milliseconds since epoch
        writer.Write((byte)((sct.TimestampMs >> 56) & 0xFF));
        writer.Write((byte)((sct.TimestampMs >> 48) & 0xFF));
        writer.Write((byte)((sct.TimestampMs >> 40) & 0xFF));
        writer.Write((byte)((sct.TimestampMs >> 32) & 0xFF));
        writer.Write((byte)((sct.TimestampMs >> 24) & 0xFF));
        writer.Write((byte)((sct.TimestampMs >> 16) & 0xFF));
        writer.Write((byte)((sct.TimestampMs >> 8) & 0xFF));
        writer.Write((byte)(sct.TimestampMs & 0xFF));
        // entry_type: precert_entry = 1 (uint16)
        writer.Write((byte)0);
        writer.Write((byte)1);
        // issuer_key_hash: SHA-256 hash of issuer's SPKI
        writer.Write(issuerKeyHash);
        // tbs_certificate length: uint24
        writer.Write((byte)((preTbs.Length >> 16) & 0xFF));
        writer.Write((byte)((preTbs.Length >> 8) & 0xFF));
        writer.Write((byte)(preTbs.Length & 0xFF));
        // tbs_certificate
        writer.Write(preTbs);
        // extensions_length: uint16
        writer.Write((byte)((sct.Extensions.Length >> 8) & 0xFF));
        writer.Write((byte)(sct.Extensions.Length & 0xFF));
        // extensions
        if (sct.Extensions.Length > 0)
            writer.Write(sct.Extensions);

        writer.Flush();
        return ms.ToArray();
    }

    /// <summary>
    /// Builds the pre-TBS certificate by removing the CT poison extension (if present)
    /// and the SCT list extension from the TBSCertificate.
    /// This follows RFC 6962 §3.2 for precertificate SCT verification.
    /// </summary>
    private static byte[] BuildPreTbsCertificate(X509Certificate2 cert)
    {
        // Parse the full certificate to get the TBSCertificate
        var certReader = new AsnReader(cert.RawData, AsnEncodingRules.DER);
        var certSeq = certReader.ReadSequence();
        // TBSCertificate is the first element
        var tbsBytes = certSeq.ReadEncodedValue().ToArray();

        // Now rebuild TBSCertificate without the poison and SCT extensions
        var tbsReader = new AsnReader(tbsBytes, AsnEncodingRules.DER);
        var tbsSeq = tbsReader.ReadSequence();

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            // Read each field of TBSCertificate
            // version [0] EXPLICIT INTEGER
            // serialNumber INTEGER
            // signature AlgorithmIdentifier
            // issuer Name
            // validity Validity
            // subject Name
            // subjectPublicKeyInfo SubjectPublicKeyInfo
            // issuerUniqueID [1] IMPLICIT BIT STRING OPTIONAL
            // subjectUniqueID [2] IMPLICIT BIT STRING OPTIONAL
            // extensions [3] EXPLICIT SEQUENCE OF Extension OPTIONAL

            while (tbsSeq.HasData)
            {
                var tag = tbsSeq.PeekTag();

                // Check for extensions: context-specific [3]
                if (tag == new Asn1Tag(TagClass.ContextSpecific, 3, true))
                {
                    var extWrapper = tbsSeq.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
                    var extSeq = extWrapper.ReadSequence();

                    using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3)))
                    using (writer.PushSequence())
                    {
                        while (extSeq.HasData)
                        {
                            var extBytes = extSeq.ReadEncodedValue();
                            // Parse the extension to check its OID
                            var extReader = new AsnReader(extBytes, AsnEncodingRules.DER);
                            var extInner = extReader.ReadSequence();
                            var oid = extInner.ReadObjectIdentifier();

                            // Skip poison and SCT extensions
                            if (oid == PoisonOid || oid == SctListOid)
                                continue;

                            writer.WriteEncodedValue(extBytes.Span);
                        }
                    }
                }
                else
                {
                    // Copy other fields as-is
                    writer.WriteEncodedValue(tbsSeq.ReadEncodedValue().Span);
                }
            }
        }

        return writer.Encode();
    }

    private static ECDsa? LoadEcdsaFromSpki(byte[] spkiBytes)
    {
        try
        {
            var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(spkiBytes, out _);
            return ecdsa;
        }
        catch
        {
            return null;
        }
    }

    private static RSA? LoadRsaFromSpki(byte[] spkiBytes)
    {
        try
        {
            var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(spkiBytes, out _);
            return rsa;
        }
        catch
        {
            return null;
        }
    }

    private class Sct
    {
        public byte Version { get; init; }
        public required byte[] LogId { get; init; }
        public long TimestampMs { get; init; }
        public required byte[] Extensions { get; init; }
        public byte HashAlgorithm { get; init; }
        public byte SignatureAlgorithm { get; init; }
        public required byte[] Signature { get; init; }
    }
}
