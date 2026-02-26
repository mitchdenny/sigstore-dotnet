namespace Sigstore.Common;

/// <summary>
/// Supported public key algorithms and their encoding/signature details.
/// Maps to the Sigstore algorithm registry.
/// </summary>
public enum PublicKeyDetails
{
    /// <summary>Unspecified key type.</summary>
    Unspecified = 0,
    /// <summary>ECDSA on P-256 with SHA-256 (PKIX encoded).</summary>
    PkixEcdsaP256Sha256 = 5,
    /// <summary>Ed25519 (PKIX encoded).</summary>
    PkixEd25519 = 7,
    /// <summary>Ed25519ph pre-hashed (PKIX encoded).</summary>
    PkixEd25519Ph = 8,
    /// <summary>RSA PKCS#1 v1.5 2048-bit with SHA-256 (PKIX encoded).</summary>
    PkixRsaPkcs1v152048Sha256 = 9,
    /// <summary>RSA PKCS#1 v1.5 3072-bit with SHA-256 (PKIX encoded).</summary>
    PkixRsaPkcs1v153072Sha256 = 10,
    /// <summary>RSA PKCS#1 v1.5 4096-bit with SHA-256 (PKIX encoded).</summary>
    PkixRsaPkcs1v154096Sha256 = 11,
    /// <summary>ECDSA on P-384 with SHA-384 (PKIX encoded).</summary>
    PkixEcdsaP384Sha384 = 12,
    /// <summary>ECDSA on P-521 with SHA-512 (PKIX encoded).</summary>
    PkixEcdsaP521Sha512 = 13,
    /// <summary>RSA-PSS 2048-bit with SHA-256 (PKIX encoded).</summary>
    PkixRsaPss2048Sha256 = 16,
    /// <summary>RSA-PSS 3072-bit with SHA-256 (PKIX encoded).</summary>
    PkixRsaPss3072Sha256 = 17,
    /// <summary>RSA-PSS 4096-bit with SHA-256 (PKIX encoded).</summary>
    PkixRsaPss4096Sha256 = 18,
    /// <summary>ML-DSA-65 post-quantum signature.</summary>
    MlDsa65 = 21,
    /// <summary>ML-DSA-87 post-quantum signature.</summary>
    MlDsa87 = 22
}
