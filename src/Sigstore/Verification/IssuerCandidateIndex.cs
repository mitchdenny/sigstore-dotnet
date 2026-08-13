using System.Formats.Asn1;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Sigstore;

/// <summary>
/// A lookup, built once per <see cref="TrustedRoot"/>, from a leaf certificate's issuer name and
/// authority key identifier to the certificate authorities that could have issued it.
/// </summary>
/// <remarks>
/// <para>
/// A precertificate SCT commits to a hash of the issuing certificate's public key, so SCT
/// verification needs that exact certificate. Selecting it by subject name alone is not safe: an
/// authority that rotates its key keeps its subject name, so a trusted root can legitimately hold
/// several distinct authorities sharing one name. Picking the first name match then reconstructs
/// the signed data with the wrong key and every SCT appears invalid.
/// </para>
/// <para>
/// Resolving an issuer therefore has to compare subject names and key identifiers, which requires
/// decoding every candidate certificate. Doing that per verification costs time proportional to the
/// size of the trusted root, so the decoded form is cached here against the trusted root instance
/// and each subsequent lookup is a dictionary probe. The cache assumes a trusted root is not
/// mutated after construction, which holds for every instance this library produces.
/// </para>
/// </remarks>
internal sealed class IssuerCandidateIndex
{
    // OID of the X.509 authority key identifier extension (RFC 5280 4.2.1.1).
    private const string AuthorityKeyIdentifierOid = "2.5.29.35";
    // OID of the X.509 subject key identifier extension (RFC 5280 4.2.1.2).
    private const string SubjectKeyIdentifierOid = "2.5.29.14";

    private static readonly ConditionalWeakTable<TrustedRoot, IssuerCandidateIndex> Cache = new();

    private readonly Dictionary<string, SubjectGroup> _bySubject = [];

    private IssuerCandidateIndex(TrustedRoot trustRoot)
    {
        foreach (var authority in trustRoot.CertificateAuthorities)
        {
            foreach (var certificateBytes in authority.CertificateChain)
            {
                string subjectKey;
                ReadOnlyMemory<byte>? subjectKeyId;

                try
                {
                    using var certificate = X509CertificateLoader.LoadCertificate(certificateBytes.Span);
                    subjectKey = Convert.ToHexString(certificate.SubjectName.RawData);
                    subjectKeyId = GetSubjectKeyIdentifier(certificate);
                }
                catch (CryptographicException)
                {
                    continue;
                }

                if (!_bySubject.TryGetValue(subjectKey, out var group))
                {
                    group = new SubjectGroup();
                    _bySubject[subjectKey] = group;
                }

                group.All.Add(certificateBytes);

                if (subjectKeyId is { } identifier)
                {
                    var identifierKey = Convert.ToHexString(identifier.Span);
                    if (!group.BySubjectKeyIdentifier.TryGetValue(identifierKey, out var matches))
                    {
                        matches = [];
                        group.BySubjectKeyIdentifier[identifierKey] = matches;
                    }

                    matches.Add(certificateBytes);
                }
                else
                {
                    group.WithoutSubjectKeyIdentifier.Add(certificateBytes);
                }
            }
        }
    }

    /// <summary>
    /// Returns the index for <paramref name="trustRoot"/>, building it on first use.
    /// </summary>
    /// <param name="trustRoot">The trusted root to index.</param>
    public static IssuerCandidateIndex For(TrustedRoot trustRoot) =>
        Cache.GetValue(trustRoot, static root => new IssuerCandidateIndex(root));

    /// <summary>
    /// Collects the certificates that may have issued <paramref name="leafCert"/>, most likely first.
    /// </summary>
    /// <remarks>
    /// When the leaf names its issuer's key and the trusted root holds a certificate publishing that
    /// key identifier, authorities publishing a different one cannot have issued the leaf and are
    /// excluded. Authorities that omit the extension cannot be ruled out, so they are retained as
    /// fallbacks, as are all name matches when the leaf itself omits the extension.
    /// </remarks>
    /// <param name="leafCert">The certificate whose issuer is being resolved.</param>
    /// <param name="owned">Receives the certificates loaded here, which the caller must dispose.</param>
    public List<X509Certificate2> Resolve(X509Certificate2 leafCert, List<X509Certificate2> owned)
    {
        if (!_bySubject.TryGetValue(Convert.ToHexString(leafCert.IssuerName.RawData), out var group))
            return [];

        List<ReadOnlyMemory<byte>> selected;

        if (GetAuthorityKeyIdentifier(leafCert) is { } authorityKeyId &&
            group.BySubjectKeyIdentifier.TryGetValue(Convert.ToHexString(authorityKeyId.Span), out var exact))
        {
            selected = group.WithoutSubjectKeyIdentifier.Count == 0
                ? exact
                : [.. exact, .. group.WithoutSubjectKeyIdentifier];
        }
        else
        {
            selected = group.All;
        }

        var candidates = new List<X509Certificate2>(selected.Count);

        foreach (var certificateBytes in selected)
        {
            X509Certificate2 certificate;
            try
            {
                certificate = X509CertificateLoader.LoadCertificate(certificateBytes.Span);
            }
            catch (CryptographicException)
            {
                continue;
            }

            owned.Add(certificate);
            candidates.Add(certificate);
        }

        return candidates;
    }

    private static ReadOnlyMemory<byte>? GetAuthorityKeyIdentifier(X509Certificate2 cert)
    {
        var extension = cert.Extensions[AuthorityKeyIdentifierOid];
        if (extension == null)
            return null;

        try
        {
            // Unlike the subject key identifier extension, this type's byte[] constructor decodes
            // the extension rather than treating the bytes as an identifier.
            return new X509AuthorityKeyIdentifierExtension(extension.RawData, extension.Critical)
                .KeyIdentifier;
        }
        catch (AsnContentException)
        {
            return null;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    private static ReadOnlyMemory<byte>? GetSubjectKeyIdentifier(X509Certificate2 cert)
    {
        var extension = cert.Extensions[SubjectKeyIdentifierOid];
        if (extension == null)
            return null;

        try
        {
            // The extension value is a bare OCTET STRING (RFC 5280 4.2.1.2). It is decoded here
            // rather than through X509SubjectKeyIdentifierExtension, whose byte[] constructor would
            // treat the encoded value as the identifier itself and leave its DER header in place,
            // preventing it from ever matching an authority key identifier.
            return new AsnReader(extension.RawData, AsnEncodingRules.DER).ReadOctetString();
        }
        catch (AsnContentException)
        {
            return null;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    /// <summary>
    /// The certificates in a trusted root that share one subject name.
    /// </summary>
    private sealed class SubjectGroup
    {
        public List<ReadOnlyMemory<byte>> All { get; } = [];

        public Dictionary<string, List<ReadOnlyMemory<byte>>> BySubjectKeyIdentifier { get; } = [];

        public List<ReadOnlyMemory<byte>> WithoutSubjectKeyIdentifier { get; } = [];
    }
}
