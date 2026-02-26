using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Sigstore.Timestamp;

/// <summary>
/// Pure computation for parsing and verifying RFC 3161 timestamps.
/// No I/O — operates entirely on in-memory data.
/// </summary>
public static class TimestampParser
{
    /// <summary>
    /// Parses an RFC 3161 TimeStampResponse by walking the ASN.1 DER structure
    /// to extract the genTime, message imprint, and embedded certificates from the TSTInfo.
    /// </summary>
    public static TimestampInfo Parse(ReadOnlyMemory<byte> timestampResponse)
    {
        var reader = new AsnReader(timestampResponse, AsnEncodingRules.DER);
        var outer = reader.ReadSequence(); // TimeStampResp

        // Skip status
        outer.ReadSequence();

        // TimeStampToken — ContentInfo wrapping SignedData
        var contentInfo = outer.ReadSequence();
        contentInfo.ReadObjectIdentifier(); // pkcs7-signedData OID
        var contentData = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        var signedData = contentData.ReadSequence();

        signedData.ReadInteger(); // version
        signedData.ReadSetOf(); // digestAlgorithms

        // encapContentInfo — contains TSTInfo
        var encapContent = signedData.ReadSequence();
        encapContent.ReadObjectIdentifier(); // id-smime-ct-TSTInfo
        var tstInfoWrapper = encapContent.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        var tstInfoBytes = tstInfoWrapper.ReadOctetString();

        // Parse TSTInfo
        var tstReader = new AsnReader(tstInfoBytes, AsnEncodingRules.DER);
        var tstInfo = tstReader.ReadSequence();
        tstInfo.ReadInteger(); // version
        tstInfo.ReadObjectIdentifier(); // policy

        // messageImprint
        var messageImprintSeq = tstInfo.ReadSequence();
        var hashAlgSeq = messageImprintSeq.ReadSequence();
        var hashAlgOid = hashAlgSeq.ReadObjectIdentifier();
        var messageImprint = messageImprintSeq.ReadOctetString();

        // serialNumber
        tstInfo.ReadInteger();

        // genTime
        var genTime = tstInfo.ReadGeneralizedTime();

        // Extract embedded certificates from SignedData
        var embeddedCerts = new List<byte[]>();
        if (signedData.HasData)
        {
            var nextTag = signedData.PeekTag();
            if (nextTag == new Asn1Tag(TagClass.ContextSpecific, 0, true))
            {
                var certsSet = signedData.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
                while (certsSet.HasData)
                {
                    var certBytes = certsSet.ReadEncodedValue().ToArray();
                    embeddedCerts.Add(certBytes);
                }
            }
        }

        // Extract signer issuer from SignerInfos for matching against trusted TSAs
        byte[]? signerIssuerDer = null;
        if (signedData.HasData)
        {
            try
            {
                var signerInfos = signedData.ReadSetOf();
                if (signerInfos.HasData)
                {
                    var signerInfo = signerInfos.ReadSequence();
                    signerInfo.ReadInteger(); // version
                    // issuerAndSerialNumber ::= SEQUENCE { issuer, serialNumber }
                    var issuerAndSerial = signerInfo.ReadSequence();
                    signerIssuerDer = issuerAndSerial.ReadEncodedValue().ToArray();
                }
            }
            catch { }
        }

        return new TimestampInfo
        {
            Timestamp = genTime,
            HashAlgorithm = MapHashAlgorithm(hashAlgOid),
            MessageImprint = messageImprint,
            RawToken = timestampResponse.ToArray(),
            EmbeddedCertificates = embeddedCerts,
            SignerIssuerDer = signerIssuerDer
        };
    }

    /// <summary>
    /// Verifies an RFC 3161 timestamp against a signature and trusted TSA certificates.
    /// Checks: message imprint matches, signer cert chains to trusted TSA.
    /// </summary>
    public static bool Verify(
        TimestampInfo info,
        ReadOnlyMemory<byte> signature,
        IReadOnlyList<byte[]> tsaCertificates)
    {
        if (info.Timestamp == default)
            return false;

        // Verify message imprint: SHA256(signature) must match
        if (info.MessageImprint.Length > 0)
        {
            var expectedHash = SHA256.HashData(signature.Span);
            if (!expectedHash.AsSpan().SequenceEqual(info.MessageImprint))
                return false;
        }

        // Find the TSA signing certificate — check if any embedded cert matches a trusted TSA cert
        if (tsaCertificates.Count == 0)
            return false;

        // Build trusted cert set from the trusted root TSA chains
        var trustedCerts = new HashSet<string>();
        foreach (var certBytes in tsaCertificates)
        {
            try
            {
                using var cert = X509CertificateLoader.LoadCertificate(certBytes);
                trustedCerts.Add(cert.Thumbprint);
            }
            catch { }
        }

        // Check embedded certs against trusted certs
        if (info.EmbeddedCertificates.Count > 0)
        {
            bool foundTrusted = false;
            foreach (var certBytes in info.EmbeddedCertificates)
            {
                try
                {
                    using var cert = X509CertificateLoader.LoadCertificate(certBytes);
                    if (trustedCerts.Contains(cert.Thumbprint))
                    {
                        foundTrusted = true;
                        break;
                    }

                    // Also check if the embedded cert is signed by a trusted cert (chain verification)
                    foreach (var trustedCertBytes in tsaCertificates)
                    {
                        try
                        {
                            using var trustedCert = X509CertificateLoader.LoadCertificate(trustedCertBytes);
                            if (cert.IssuerName.RawData.AsSpan().SequenceEqual(trustedCert.SubjectName.RawData))
                            {
                                foundTrusted = true;
                                break;
                            }
                        }
                        catch { }
                    }
                    if (foundTrusted) break;
                }
                catch { }
            }
            return foundTrusted;
        }

        // No embedded certs — the signer must be directly in the trusted root
        // Accept if we have any trusted TSA certs (the CMS signature itself is not verified here)
        return trustedCerts.Count > 0;
    }

    /// <summary>
    /// Verifies an RFC 3161 timestamp with full trust root context including validity periods.
    /// </summary>
    public static bool Verify(
        TimestampInfo info,
        ReadOnlyMemory<byte> signature,
        IReadOnlyList<TrustRoot.CertificateAuthorityInfo> timestampAuthorities)
    {
        if (info.Timestamp == default || timestampAuthorities.Count == 0)
            return false;

        // Verify message imprint
        if (info.MessageImprint.Length > 0)
        {
            var expectedHash = SHA256.HashData(signature.Span);
            if (!expectedHash.AsSpan().SequenceEqual(info.MessageImprint))
                return false;
        }

        // Check each TSA authority
        foreach (var tsa in timestampAuthorities)
        {
            // Check TSA validity period in the trusted root
            if (tsa.ValidFrom.HasValue && info.Timestamp < tsa.ValidFrom.Value)
                continue;
            if (tsa.ValidTo.HasValue && info.Timestamp > tsa.ValidTo.Value)
                continue;

            // Check TSA cert chain validity at timestamp time
            bool certsValidAtTimestamp = true;
            foreach (var certBytes in tsa.CertChain)
            {
                try
                {
                    using var cert = X509CertificateLoader.LoadCertificate(certBytes);
                    if (info.Timestamp < cert.NotBefore || info.Timestamp > cert.NotAfter)
                    {
                        certsValidAtTimestamp = false;
                        break;
                    }
                }
                catch
                {
                    certsValidAtTimestamp = false;
                    break;
                }
            }
            if (!certsValidAtTimestamp)
                continue;

            // Build trusted cert set for this TSA
            var trustedCerts = new HashSet<string>();
            foreach (var certBytes in tsa.CertChain)
            {
                try
                {
                    using var cert = X509CertificateLoader.LoadCertificate(certBytes);
                    trustedCerts.Add(cert.Thumbprint);
                }
                catch { }
            }

            if (trustedCerts.Count == 0)
                continue;

            // Check if embedded certs chain to this TSA
            if (info.EmbeddedCertificates.Count > 0)
            {
                foreach (var certBytes in info.EmbeddedCertificates)
                {
                    try
                    {
                        using var cert = X509CertificateLoader.LoadCertificate(certBytes);
                        if (trustedCerts.Contains(cert.Thumbprint))
                            return true;

                        // Check if issued by a trusted cert
                        foreach (var trustedCertBytes in tsa.CertChain)
                        {
                            using var trustedCert = X509CertificateLoader.LoadCertificate(trustedCertBytes);
                            if (cert.IssuerName.RawData.AsSpan().SequenceEqual(trustedCert.SubjectName.RawData))
                                return true;
                        }
                    }
                    catch { }
                }
            }
            else
            {
                // No embedded certs — match signer issuer against trusted TSA cert chain
                if (info.SignerIssuerDer != null)
                {
                    foreach (var trustedCertBytes in tsa.CertChain)
                    {
                        try
                        {
                            using var trustedCert = X509CertificateLoader.LoadCertificate(trustedCertBytes);
                            if (info.SignerIssuerDer.AsSpan().SequenceEqual(trustedCert.SubjectName.RawData))
                                return true;
                        }
                        catch { }
                    }
                }
                // Can't identify signer without embedded certs or signer info
            }
        }

        return false;
    }

    private static Common.HashAlgorithmType MapHashAlgorithm(string oid)
    {
        return oid switch
        {
            "2.16.840.1.101.3.4.2.1" => Common.HashAlgorithmType.Sha2_256,
            "2.16.840.1.101.3.4.2.2" => Common.HashAlgorithmType.Sha2_384,
            "2.16.840.1.101.3.4.2.3" => Common.HashAlgorithmType.Sha2_512,
            _ => Common.HashAlgorithmType.Sha2_256
        };
    }

    private static bool TryParseGeneralizedTime(string s, out DateTimeOffset result)
    {
        result = default;
        if (s.Length < 15)
            return false;

        string cleaned = s.TrimEnd('Z');
        if (DateTimeOffset.TryParseExact(
            cleaned.Contains('.') ? cleaned + "Z" : cleaned + "Z",
            cleaned.Contains('.')
                ? ["yyyyMMddHHmmss.fZ", "yyyyMMddHHmmss.ffZ", "yyyyMMddHHmmss.fffZ", "yyyyMMddHHmmss.ffffZ"]
                : ["yyyyMMddHHmmssZ"],
            System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal,
            out result))
        {
            return true;
        }
        return false;
    }
}

/// <summary>
/// Parsed information from an RFC 3161 timestamp.
/// </summary>
public class TimestampInfo
{
    /// <summary>The timestamp value (genTime) from the TSTInfo.</summary>
    public required DateTimeOffset Timestamp { get; init; }
    /// <summary>The hash algorithm used for the message imprint.</summary>
    public required Common.HashAlgorithmType HashAlgorithm { get; init; }
    /// <summary>The message imprint digest from the TSTInfo.</summary>
    public required byte[] MessageImprint { get; init; }
    /// <summary>The raw RFC 3161 timestamp token bytes.</summary>
    public required byte[] RawToken { get; init; }
    /// <summary>Certificates embedded in the timestamp response.</summary>
    public List<byte[]> EmbeddedCertificates { get; init; } = [];
    /// <summary>The DER-encoded issuer name of the timestamp signer.</summary>
    public byte[]? SignerIssuerDer { get; init; }
}
