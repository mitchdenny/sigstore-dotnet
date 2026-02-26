namespace Sigstore.Common;

/// <summary>
/// Supported public key algorithms and their encoding/signature details.
/// Maps to the Sigstore algorithm registry.
/// </summary>
public enum PublicKeyDetails
{
    Unspecified = 0,
    PkixEcdsaP256Sha256 = 5,
    PkixEd25519 = 7,
    PkixEd25519Ph = 8,
    PkixRsaPkcs1v152048Sha256 = 9,
    PkixRsaPkcs1v153072Sha256 = 10,
    PkixRsaPkcs1v154096Sha256 = 11,
    PkixEcdsaP384Sha384 = 12,
    PkixEcdsaP521Sha512 = 13,
    PkixRsaPss2048Sha256 = 16,
    PkixRsaPss3072Sha256 = 17,
    PkixRsaPss4096Sha256 = 18,
    MlDsa65 = 21,
    MlDsa87 = 22
}
