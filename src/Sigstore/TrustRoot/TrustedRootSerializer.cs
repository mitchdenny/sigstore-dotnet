using System.Text.Json;
using System.Text.Json.Serialization;
using Sigstore.Bundle;
using Sigstore.Common;

namespace Sigstore.TrustRoot;

// JSON DTO types for the Sigstore trusted root format.

internal sealed class TrustedRootJson
{
    public string? MediaType { get; set; }
    public List<TransparencyLogJson>? Tlogs { get; set; }
    public List<CertificateAuthorityJson>? CertificateAuthorities { get; set; }
    public List<TransparencyLogJson>? Ctlogs { get; set; }
    public List<CertificateAuthorityJson>? TimestampAuthorities { get; set; }
}

internal sealed class TransparencyLogJson
{
    public string? BaseUrl { get; set; }
    public string? HashAlgorithm { get; set; }
    public TransparencyLogPublicKeyJson? PublicKey { get; set; }
    public Bundle.LogIdJson? LogId { get; set; }
    public byte[]? CheckpointKeyId { get; set; }
    [JsonPropertyName("operator")]
    public string? Operator { get; set; }
}

internal sealed class TransparencyLogPublicKeyJson
{
    public string? RawBytes { get; set; }
    public string? KeyDetails { get; set; }
    public TimeRangeJson? ValidFor { get; set; }
}

internal sealed class TimeRangeJson
{
    public string? Start { get; set; }
    public string? End { get; set; }
}

internal sealed class CertificateAuthorityJson
{
    public DistinguishedNameJson? Subject { get; set; }
    public string? Uri { get; set; }
    public CertChainJson? CertChain { get; set; }
    public TimeRangeJson? ValidFor { get; set; }
    [JsonPropertyName("operator")]
    public string? Operator { get; set; }
}

internal sealed class DistinguishedNameJson
{
    public string? Organization { get; set; }
    public string? CommonName { get; set; }
}

internal sealed class CertChainJson
{
    public List<Bundle.CertificateJson>? Certificates { get; set; }
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(TrustedRootJson))]
internal sealed partial class TrustedRootJsonContext : JsonSerializerContext;

internal static class TrustedRootSerializer
{
    public static TrustedRoot Deserialize(string json)
    {
        var dto = JsonSerializer.Deserialize(json, TrustedRootJsonContext.Default.TrustedRootJson)
                  ?? throw new JsonException("Failed to deserialize TrustedRoot.");
        return FromDto(dto);
    }

    private static TrustedRoot FromDto(TrustedRootJson dto)
    {
        var root = new TrustedRoot
        {
            MediaType = dto.MediaType ?? "application/vnd.dev.sigstore.trustedroot+json;version=0.1"
        };

        if (dto.Tlogs != null)
            root.TransparencyLogs = dto.Tlogs.Select(FromDto).ToList();

        if (dto.CertificateAuthorities != null)
            root.CertificateAuthorities = dto.CertificateAuthorities.Select(FromCaDto).ToList();

        if (dto.Ctlogs != null)
            root.CtLogs = dto.Ctlogs.Select(FromDto).ToList();

        if (dto.TimestampAuthorities != null)
            root.TimestampAuthorities = dto.TimestampAuthorities.Select(FromCaDto).ToList();

        return root;
    }

    private static TransparencyLogInfo FromDto(TransparencyLogJson dto)
    {
        var info = new TransparencyLogInfo
        {
            BaseUrl = dto.BaseUrl ?? "",
            HashAlgorithm = BundleSerializer.ParseHashAlgorithm(dto.HashAlgorithm)
        };

        if (dto.PublicKey != null)
        {
            if (dto.PublicKey.RawBytes != null)
                info.PublicKeyBytes = Convert.FromBase64String(dto.PublicKey.RawBytes);

            info.KeyDetails = BundleSerializer.ParseKeyDetails(dto.PublicKey.KeyDetails);

            if (dto.PublicKey.ValidFor != null)
            {
                if (dto.PublicKey.ValidFor.Start != null)
                    info.ValidFrom = DateTimeOffset.Parse(dto.PublicKey.ValidFor.Start);
                if (dto.PublicKey.ValidFor.End != null)
                    info.ValidTo = DateTimeOffset.Parse(dto.PublicKey.ValidFor.End);
            }
        }

        if (dto.LogId?.KeyId != null)
            info.LogId = Convert.FromBase64String(dto.LogId.KeyId);

        if (dto.Operator != null)
            info.Operator = dto.Operator;

        return info;
    }

    private static CertificateAuthorityInfo FromCaDto(CertificateAuthorityJson dto)
    {
        var info = new CertificateAuthorityInfo
        {
            Uri = dto.Uri ?? ""
        };

        if (dto.CertChain?.Certificates != null)
        {
            info.CertChain = dto.CertChain.Certificates
                .Where(c => c.RawBytes != null)
                .Select(c => Convert.FromBase64String(c.RawBytes!))
                .ToList();
        }

        if (dto.ValidFor != null)
        {
            if (dto.ValidFor.Start != null)
                info.ValidFrom = DateTimeOffset.Parse(dto.ValidFor.Start);
            if (dto.ValidFor.End != null)
                info.ValidTo = DateTimeOffset.Parse(dto.ValidFor.End);
        }

        if (dto.Operator != null)
            info.Operator = dto.Operator;

        return info;
    }
}
