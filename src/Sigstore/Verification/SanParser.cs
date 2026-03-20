using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace Sigstore;

/// <summary>
/// Parses Subject Alternative Name (SAN) values from X.509 certificates using
/// raw ASN.1 decoding, avoiding the platform-dependent <c>X509Extension.Format()</c> method.
/// </summary>
internal static class SanParser
{
    private const string SubjectAlternativeNameOid = "2.5.29.17";

    // ASN.1 context-specific tags for GeneralName (RFC 5280 §4.2.1.6)
    private static readonly Asn1Tag Rfc822NameTag = new(TagClass.ContextSpecific, 1); // email
    private static readonly Asn1Tag DnsNameTag = new(TagClass.ContextSpecific, 2);
    private static readonly Asn1Tag UniformResourceIdentifierTag = new(TagClass.ContextSpecific, 6); // URI

    /// <summary>
    /// Extracts the most relevant SAN value from a certificate.
    /// Priority: email (rfc822Name) → URI (uniformResourceIdentifier) → DNS (dNSName).
    /// </summary>
    /// <returns>The SAN string, or <c>null</c> if no supported SAN type is found.</returns>
    internal static string? ExtractSan(X509Certificate2 cert)
    {
        foreach (var ext in cert.Extensions)
        {
            if (ext.Oid?.Value != SubjectAlternativeNameOid)
                continue;

            return ParseSanExtension(ext.RawData);
        }

        return null;
    }

    private static string? ParseSanExtension(byte[] rawData)
    {
        string? email = null;
        string? uri = null;
        string? dns = null;

        var reader = new AsnReader(rawData, AsnEncodingRules.DER);
        var sequence = reader.ReadSequence();

        while (sequence.HasData)
        {
            var tag = sequence.PeekTag();

            if (tag == Rfc822NameTag)
            {
                var value = sequence.ReadCharacterString(UniversalTagNumber.IA5String, Rfc822NameTag);
                email ??= value;
            }
            else if (tag == UniformResourceIdentifierTag)
            {
                var value = sequence.ReadCharacterString(UniversalTagNumber.IA5String, UniformResourceIdentifierTag);
                uri ??= value;
            }
            else if (tag == DnsNameTag)
            {
                var value = sequence.ReadCharacterString(UniversalTagNumber.IA5String, DnsNameTag);
                dns ??= value;
            }
            else
            {
                // Skip unsupported GeneralName types (otherName, x400Address, directoryName, etc.)
                sequence.ReadEncodedValue();
            }
        }

        // Priority: email → URI → DNS
        return email ?? uri ?? dns;
    }
}
