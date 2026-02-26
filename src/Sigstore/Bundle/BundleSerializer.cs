using System.Text.Json;
using System.Text.Json.Serialization;
using Sigstore.Common;

namespace Sigstore.Bundle;

// JSON DTO types that mirror the Sigstore bundle protobuf-JSON schema.
// These are internal and only used for serialization/deserialization.

internal sealed class BundleJson
{
    public string? MediaType { get; set; }
    public VerificationMaterialJson? VerificationMaterial { get; set; }
    public MessageSignatureJson? MessageSignature { get; set; }
    public DsseEnvelopeJson? DsseEnvelope { get; set; }
}

internal sealed class VerificationMaterialJson
{
    // v0.3+: single certificate
    public CertificateJson? Certificate { get; set; }
    // v0.1/v0.2: certificate chain
    public CertificateChainJson? X509CertificateChain { get; set; }
    public PublicKeyIdentifierJson? PublicKey { get; set; }
    public List<TlogEntryJson>? TlogEntries { get; set; }
    public TimestampVerificationDataJson? TimestampVerificationData { get; set; }
}

internal sealed class CertificateJson
{
    public string? RawBytes { get; set; }
}

internal sealed class CertificateChainJson
{
    public List<CertificateJson>? Certificates { get; set; }
}

internal sealed class PublicKeyIdentifierJson
{
    public string? Hint { get; set; }
}

internal sealed class TimestampVerificationDataJson
{
    public List<Rfc3161TimestampJson>? Rfc3161Timestamps { get; set; }
}

internal sealed class Rfc3161TimestampJson
{
    public string? SignedTimestamp { get; set; }
}

internal sealed class TlogEntryJson
{
    public string? LogIndex { get; set; }
    public LogIdJson? LogId { get; set; }
    public KindVersionJson? KindVersion { get; set; }
    public string? IntegratedTime { get; set; }
    public InclusionPromiseJson? InclusionPromise { get; set; }
    public InclusionProofJson? InclusionProof { get; set; }
    public string? CanonicalizedBody { get; set; }
}

internal sealed class LogIdJson
{
    public string? KeyId { get; set; }
}

internal sealed class KindVersionJson
{
    public string? Kind { get; set; }
    public string? Version { get; set; }
}

internal sealed class InclusionPromiseJson
{
    public string? SignedEntryTimestamp { get; set; }
}

internal sealed class InclusionProofJson
{
    public string? LogIndex { get; set; }
    public string? RootHash { get; set; }
    public string? TreeSize { get; set; }
    public List<string>? Hashes { get; set; }
    public CheckpointJson? Checkpoint { get; set; }
}

internal sealed class CheckpointJson
{
    public string? Envelope { get; set; }
}

internal sealed class MessageSignatureJson
{
    public HashOutputJson? MessageDigest { get; set; }
    public string? Signature { get; set; }
}

internal sealed class HashOutputJson
{
    public string? Algorithm { get; set; }
    public string? Digest { get; set; }
}

internal sealed class DsseEnvelopeJson
{
    public string? PayloadType { get; set; }
    public string? Payload { get; set; }
    public List<DsseSignatureJson>? Signatures { get; set; }
}

internal sealed class DsseSignatureJson
{
    public string? Keyid { get; set; }
    public string? Sig { get; set; }
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    WriteIndented = false)]
[JsonSerializable(typeof(BundleJson))]
internal sealed partial class BundleJsonContext : JsonSerializerContext;

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(BundleJson))]
internal sealed partial class BundleJsonReadContext : JsonSerializerContext;

internal static class BundleSerializer
{
    public static SigstoreBundle Deserialize(string json)
    {
        var dto = JsonSerializer.Deserialize(json, BundleJsonReadContext.Default.BundleJson)
                  ?? throw new JsonException("Failed to deserialize Sigstore bundle.");
        return FromDto(dto);
    }

    public static SigstoreBundle Deserialize(Stream stream)
    {
        var dto = JsonSerializer.Deserialize(stream, BundleJsonReadContext.Default.BundleJson)
                  ?? throw new JsonException("Failed to deserialize Sigstore bundle.");
        return FromDto(dto);
    }

    public static string Serialize(SigstoreBundle bundle)
    {
        var dto = ToDto(bundle);
        return JsonSerializer.Serialize(dto, BundleJsonContext.Default.BundleJson);
    }

    private static SigstoreBundle FromDto(BundleJson dto)
    {
        var bundle = new SigstoreBundle
        {
            MediaType = dto.MediaType ?? "application/vnd.dev.sigstore.bundle.v0.3+json"
        };

        if (dto.VerificationMaterial != null)
        {
            bundle.VerificationMaterial = FromDto(dto.VerificationMaterial);
        }

        if (dto.MessageSignature != null)
        {
            bundle.MessageSignature = FromDto(dto.MessageSignature);
        }

        if (dto.DsseEnvelope != null)
        {
            bundle.DsseEnvelope = FromDto(dto.DsseEnvelope);
        }

        return bundle;
    }

    private static VerificationMaterial FromDto(VerificationMaterialJson dto)
    {
        var material = new VerificationMaterial();

        // v0.3+: single certificate
        if (dto.Certificate?.RawBytes != null)
        {
            material.Certificate = Convert.FromBase64String(dto.Certificate.RawBytes);
        }

        // v0.1/v0.2: certificate chain
        if (dto.X509CertificateChain?.Certificates != null)
        {
            material.CertificateChain = dto.X509CertificateChain.Certificates
                .Where(c => c.RawBytes != null)
                .Select(c => Convert.FromBase64String(c.RawBytes!))
                .ToList();
        }

        if (dto.PublicKey?.Hint != null)
        {
            material.PublicKeyHint = dto.PublicKey.Hint;
        }

        if (dto.TlogEntries != null)
        {
            material.TlogEntries = dto.TlogEntries.Select(FromDto).ToList();
        }

        if (dto.TimestampVerificationData?.Rfc3161Timestamps != null)
        {
            material.Rfc3161Timestamps = dto.TimestampVerificationData.Rfc3161Timestamps
                .Where(t => t.SignedTimestamp != null)
                .Select(t => Convert.FromBase64String(t.SignedTimestamp!))
                .ToList();
        }

        return material;
    }

    private static TransparencyLogEntry FromDto(TlogEntryJson dto)
    {
        var entry = new TransparencyLogEntry();

        if (dto.LogIndex != null)
            entry.LogIndex = long.Parse(dto.LogIndex);

        if (dto.LogId?.KeyId != null)
            entry.LogId = Convert.FromBase64String(dto.LogId.KeyId);

        if (dto.CanonicalizedBody != null)
            entry.Body = dto.CanonicalizedBody;

        if (dto.IntegratedTime != null)
            entry.IntegratedTime = long.Parse(dto.IntegratedTime);

        if (dto.InclusionProof != null)
            entry.InclusionProof = FromDto(dto.InclusionProof);

        if (dto.InclusionPromise?.SignedEntryTimestamp != null)
            entry.InclusionPromise = Convert.FromBase64String(dto.InclusionPromise.SignedEntryTimestamp);

        return entry;
    }

    private static InclusionProof FromDto(InclusionProofJson dto)
    {
        var proof = new InclusionProof();

        if (dto.LogIndex != null)
            proof.LogIndex = long.Parse(dto.LogIndex);

        if (dto.TreeSize != null)
            proof.TreeSize = long.Parse(dto.TreeSize);

        if (dto.RootHash != null)
            proof.RootHash = Convert.FromBase64String(dto.RootHash);

        if (dto.Hashes != null)
            proof.Hashes = dto.Hashes.Select(Convert.FromBase64String).ToList();

        if (dto.Checkpoint?.Envelope != null)
            proof.Checkpoint = dto.Checkpoint.Envelope;

        return proof;
    }

    private static MessageSignature FromDto(MessageSignatureJson dto)
    {
        var sig = new MessageSignature();

        if (dto.Signature != null)
            sig.Signature = Convert.FromBase64String(dto.Signature);

        if (dto.MessageDigest != null)
        {
            sig.MessageDigest = new HashOutput
            {
                Algorithm = ParseHashAlgorithm(dto.MessageDigest.Algorithm),
                Digest = dto.MessageDigest.Digest != null
                    ? Convert.FromBase64String(dto.MessageDigest.Digest)
                    : []
            };
        }

        return sig;
    }

    private static DsseEnvelope FromDto(DsseEnvelopeJson dto)
    {
        var envelope = new DsseEnvelope
        {
            PayloadType = dto.PayloadType ?? "",
            Payload = dto.Payload != null ? Convert.FromBase64String(dto.Payload) : []
        };

        if (dto.Signatures != null)
        {
            envelope.Signatures = dto.Signatures.Select(s => new DsseSignature
            {
                KeyId = s.Keyid ?? "",
                Sig = s.Sig != null ? Convert.FromBase64String(s.Sig) : []
            }).ToList();
        }

        return envelope;
    }

    // --- To DTO ---

    private static BundleJson ToDto(SigstoreBundle bundle)
    {
        var dto = new BundleJson
        {
            MediaType = bundle.MediaType
        };

        if (bundle.VerificationMaterial != null)
            dto.VerificationMaterial = ToDto(bundle.VerificationMaterial, bundle.MediaType);

        if (bundle.MessageSignature != null)
            dto.MessageSignature = ToDto(bundle.MessageSignature);

        if (bundle.DsseEnvelope != null)
            dto.DsseEnvelope = ToDto(bundle.DsseEnvelope);

        return dto;
    }

    private static VerificationMaterialJson ToDto(VerificationMaterial material, string mediaType)
    {
        var dto = new VerificationMaterialJson();

        if (material.Certificate != null)
        {
            // Check if this is a v0.1/v0.2 bundle that uses x509CertificateChain
            bool useLegacyChain = mediaType.Contains("0.1") || mediaType.Contains("0.2");
            if (useLegacyChain)
            {
                dto.X509CertificateChain = new CertificateChainJson
                {
                    Certificates = [new CertificateJson { RawBytes = Convert.ToBase64String(material.Certificate) }]
                };
            }
            else
            {
                dto.Certificate = new CertificateJson
                {
                    RawBytes = Convert.ToBase64String(material.Certificate)
                };
            }
        }

        if (material.CertificateChain != null)
        {
            dto.X509CertificateChain = new CertificateChainJson
            {
                Certificates = material.CertificateChain
                    .Select(c => new CertificateJson { RawBytes = Convert.ToBase64String(c) })
                    .ToList()
            };
        }

        if (material.PublicKeyHint != null)
        {
            dto.PublicKey = new PublicKeyIdentifierJson { Hint = material.PublicKeyHint };
        }

        if (material.TlogEntries.Count > 0)
        {
            dto.TlogEntries = material.TlogEntries.Select(ToDto).ToList();
        }

        if (material.Rfc3161Timestamps.Count > 0)
        {
            dto.TimestampVerificationData = new TimestampVerificationDataJson
            {
                Rfc3161Timestamps = material.Rfc3161Timestamps
                    .Select(t => new Rfc3161TimestampJson { SignedTimestamp = Convert.ToBase64String(t) })
                    .ToList()
            };
        }

        return dto;
    }

    private static TlogEntryJson ToDto(TransparencyLogEntry entry)
    {
        var dto = new TlogEntryJson
        {
            LogIndex = entry.LogIndex.ToString(),
            IntegratedTime = entry.IntegratedTime.ToString()
        };

        if (entry.LogId.Length > 0)
            dto.LogId = new LogIdJson { KeyId = Convert.ToBase64String(entry.LogId) };

        if (entry.Body != null)
            dto.CanonicalizedBody = entry.Body;

        if (entry.InclusionProof != null)
            dto.InclusionProof = ToDto(entry.InclusionProof);

        if (entry.InclusionPromise != null)
            dto.InclusionPromise = new InclusionPromiseJson
            {
                SignedEntryTimestamp = Convert.ToBase64String(entry.InclusionPromise)
            };

        return dto;
    }

    private static InclusionProofJson ToDto(InclusionProof proof)
    {
        var dto = new InclusionProofJson
        {
            LogIndex = proof.LogIndex.ToString(),
            TreeSize = proof.TreeSize.ToString()
        };

        if (proof.RootHash.Length > 0)
            dto.RootHash = Convert.ToBase64String(proof.RootHash);

        if (proof.Hashes.Count > 0)
            dto.Hashes = proof.Hashes.Select(Convert.ToBase64String).ToList();

        if (proof.Checkpoint != null)
            dto.Checkpoint = new CheckpointJson { Envelope = proof.Checkpoint };

        return dto;
    }

    private static MessageSignatureJson ToDto(MessageSignature sig)
    {
        var dto = new MessageSignatureJson();

        if (sig.Signature.Length > 0)
            dto.Signature = Convert.ToBase64String(sig.Signature);

        if (sig.MessageDigest != null)
        {
            dto.MessageDigest = new HashOutputJson
            {
                Algorithm = FormatHashAlgorithm(sig.MessageDigest.Algorithm),
                Digest = sig.MessageDigest.Digest.Length > 0
                    ? Convert.ToBase64String(sig.MessageDigest.Digest)
                    : null
            };
        }

        return dto;
    }

    private static DsseEnvelopeJson ToDto(DsseEnvelope envelope)
    {
        var dto = new DsseEnvelopeJson
        {
            PayloadType = envelope.PayloadType,
            Payload = envelope.Payload.Length > 0 ? Convert.ToBase64String(envelope.Payload) : null
        };

        if (envelope.Signatures.Count > 0)
        {
            dto.Signatures = envelope.Signatures.Select(s => new DsseSignatureJson
            {
                Keyid = string.IsNullOrEmpty(s.KeyId) ? null : s.KeyId,
                Sig = s.Sig.Length > 0 ? Convert.ToBase64String(s.Sig) : null
            }).ToList();
        }

        return dto;
    }

    // --- Hash algorithm mapping ---

    internal static HashAlgorithmType ParseHashAlgorithm(string? value)
    {
        return value switch
        {
            "SHA2_256" => HashAlgorithmType.Sha2_256,
            "SHA2_384" => HashAlgorithmType.Sha2_384,
            "SHA2_512" => HashAlgorithmType.Sha2_512,
            "SHA3_256" => HashAlgorithmType.Sha3_256,
            "SHA3_384" => HashAlgorithmType.Sha3_384,
            _ => HashAlgorithmType.Unspecified
        };
    }

    internal static string FormatHashAlgorithm(HashAlgorithmType alg)
    {
        return alg switch
        {
            HashAlgorithmType.Sha2_256 => "SHA2_256",
            HashAlgorithmType.Sha2_384 => "SHA2_384",
            HashAlgorithmType.Sha2_512 => "SHA2_512",
            HashAlgorithmType.Sha3_256 => "SHA3_256",
            HashAlgorithmType.Sha3_384 => "SHA3_384",
            _ => "HASH_ALGORITHM_UNSPECIFIED"
        };
    }

    internal static PublicKeyDetails ParseKeyDetails(string? value)
    {
        return value switch
        {
            "PKIX_ECDSA_P256_SHA_256" => PublicKeyDetails.PkixEcdsaP256Sha256,
            "PKIX_ED25519" => PublicKeyDetails.PkixEd25519,
            "PKIX_ED25519_PH" => PublicKeyDetails.PkixEd25519Ph,
            "PKIX_RSA_PKCS1V15_2048_SHA256" => PublicKeyDetails.PkixRsaPkcs1v152048Sha256,
            "PKIX_RSA_PKCS1V15_3072_SHA256" => PublicKeyDetails.PkixRsaPkcs1v153072Sha256,
            "PKIX_RSA_PKCS1V15_4096_SHA256" => PublicKeyDetails.PkixRsaPkcs1v154096Sha256,
            "PKIX_ECDSA_P384_SHA_384" => PublicKeyDetails.PkixEcdsaP384Sha384,
            "PKIX_ECDSA_P521_SHA_512" => PublicKeyDetails.PkixEcdsaP521Sha512,
            "PKIX_RSA_PSS_2048_SHA256" => PublicKeyDetails.PkixRsaPss2048Sha256,
            "PKIX_RSA_PSS_3072_SHA256" => PublicKeyDetails.PkixRsaPss3072Sha256,
            "PKIX_RSA_PSS_4096_SHA256" => PublicKeyDetails.PkixRsaPss4096Sha256,
            "ML_DSA_65" => PublicKeyDetails.MlDsa65,
            "ML_DSA_87" => PublicKeyDetails.MlDsa87,
            _ => PublicKeyDetails.Unspecified
        };
    }

    internal static string FormatKeyDetails(PublicKeyDetails details)
    {
        return details switch
        {
            PublicKeyDetails.PkixEcdsaP256Sha256 => "PKIX_ECDSA_P256_SHA_256",
            PublicKeyDetails.PkixEd25519 => "PKIX_ED25519",
            PublicKeyDetails.PkixEd25519Ph => "PKIX_ED25519_PH",
            PublicKeyDetails.PkixRsaPkcs1v152048Sha256 => "PKIX_RSA_PKCS1V15_2048_SHA256",
            PublicKeyDetails.PkixRsaPkcs1v153072Sha256 => "PKIX_RSA_PKCS1V15_3072_SHA256",
            PublicKeyDetails.PkixRsaPkcs1v154096Sha256 => "PKIX_RSA_PKCS1V15_4096_SHA256",
            PublicKeyDetails.PkixEcdsaP384Sha384 => "PKIX_ECDSA_P384_SHA_384",
            PublicKeyDetails.PkixEcdsaP521Sha512 => "PKIX_ECDSA_P521_SHA_512",
            PublicKeyDetails.PkixRsaPss2048Sha256 => "PKIX_RSA_PSS_2048_SHA256",
            PublicKeyDetails.PkixRsaPss3072Sha256 => "PKIX_RSA_PSS_3072_SHA256",
            PublicKeyDetails.PkixRsaPss4096Sha256 => "PKIX_RSA_PSS_4096_SHA256",
            PublicKeyDetails.MlDsa65 => "ML_DSA_65",
            PublicKeyDetails.MlDsa87 => "ML_DSA_87",
            _ => "PUBLIC_KEY_DETAILS_UNSPECIFIED"
        };
    }
}
