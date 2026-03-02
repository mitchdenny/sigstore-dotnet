using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sigstore;

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
    public LogIdJson? LogId { get; set; }
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
    public List<CertificateJson>? Certificates { get; set; }
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
        return new TrustedRoot
        {
            MediaType = dto.MediaType ?? "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            TransparencyLogs = dto.Tlogs?.Select(FromDto).ToList() ?? [],
            CertificateAuthorities = dto.CertificateAuthorities?.Select(FromCaDto).ToList() ?? [],
            CtLogs = dto.Ctlogs?.Select(FromDto).ToList() ?? [],
            TimestampAuthorities = dto.TimestampAuthorities?.Select(FromCaDto).ToList() ?? []
        };
    }

    private static TransparencyLogInfo FromDto(TransparencyLogJson dto)
    {
        return new TransparencyLogInfo
        {
            BaseUrl = dto.BaseUrl ?? "",
            HashAlgorithm = BundleSerializer.ParseHashAlgorithm(dto.HashAlgorithm),
            PublicKeyBytes = dto.PublicKey?.RawBytes != null
                ? Convert.FromBase64String(dto.PublicKey.RawBytes)
                : [],
            KeyDetails = dto.PublicKey != null
                ? BundleSerializer.ParseKeyDetails(dto.PublicKey.KeyDetails)
                : default,
            ValidFrom = dto.PublicKey?.ValidFor?.Start != null
                ? DateTimeOffset.Parse(dto.PublicKey.ValidFor.Start)
                : null,
            ValidTo = dto.PublicKey?.ValidFor?.End != null
                ? DateTimeOffset.Parse(dto.PublicKey.ValidFor.End)
                : null,
            LogId = dto.LogId?.KeyId != null
                ? Convert.FromBase64String(dto.LogId.KeyId)
                : [],
            Operator = dto.Operator
        };
    }

    private static CertificateAuthorityInfo FromCaDto(CertificateAuthorityJson dto)
    {
        return new CertificateAuthorityInfo
        {
            Uri = dto.Uri ?? "",
            CertChain = dto.CertChain?.Certificates != null
                ? dto.CertChain.Certificates
                    .Where(c => c.RawBytes != null)
                    .Select(c => Convert.FromBase64String(c.RawBytes!))
                    .ToList()
                : [],
            ValidFrom = dto.ValidFor?.Start != null
                ? DateTimeOffset.Parse(dto.ValidFor.Start)
                : null,
            ValidTo = dto.ValidFor?.End != null
                ? DateTimeOffset.Parse(dto.ValidFor.End)
                : null,
            Operator = dto.Operator
        };
    }
}
