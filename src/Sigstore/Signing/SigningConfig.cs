using System.Text.Json;

namespace Sigstore.Signing;

/// <summary>
/// Signing configuration that specifies service URLs and API versions
/// for Sigstore signing infrastructure (Fulcio, Rekor, TSA).
/// Parsed from the signing_config.v0.2.json TUF target.
/// </summary>
public sealed class SigningConfig
{
    /// <summary>
    /// Certificate Authority service URLs (Fulcio).
    /// </summary>
    public IReadOnlyList<ServiceEndpoint> CaUrls { get; init; } = [];

    /// <summary>
    /// Rekor transparency log service URLs.
    /// </summary>
    public IReadOnlyList<ServiceEndpoint> RekorTlogUrls { get; init; } = [];

    /// <summary>
    /// Timestamp Authority service URLs.
    /// </summary>
    public IReadOnlyList<ServiceEndpoint> TsaUrls { get; init; } = [];

    /// <summary>
    /// Parses a signing_config.v0.2.json file.
    /// </summary>
    public static SigningConfig Deserialize(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        return new SigningConfig
        {
            CaUrls = ParseServiceList(root, "caUrls"),
            RekorTlogUrls = ParseServiceList(root, "rekorTlogUrls"),
            TsaUrls = ParseServiceList(root, "tsaUrls")
        };
    }

    /// <summary>
    /// Selects the best (newest, highest API version) service endpoint from a list.
    /// Filters to currently valid services and returns the one with the highest
    /// API version and newest start date.
    /// </summary>
    public static ServiceEndpoint? SelectBest(IReadOnlyList<ServiceEndpoint> endpoints)
    {
        var now = DateTimeOffset.UtcNow;
        return endpoints
            .Where(e => e.ValidFrom <= now && (e.ValidTo == null || e.ValidTo >= now))
            .OrderByDescending(e => e.MajorApiVersion)
            .ThenByDescending(e => e.ValidFrom)
            .FirstOrDefault();
    }

    private static List<ServiceEndpoint> ParseServiceList(JsonElement root, string propertyName)
    {
        if (!root.TryGetProperty(propertyName, out var array))
            return [];

        var result = new List<ServiceEndpoint>();
        foreach (var item in array.EnumerateArray())
        {
            var url = item.GetProperty("url").GetString()!;
            var apiVersion = item.TryGetProperty("majorApiVersion", out var v) ? v.GetInt32() : 1;

            DateTimeOffset validFrom = default;
            DateTimeOffset? validTo = null;
            if (item.TryGetProperty("validFor", out var validFor))
            {
                if (validFor.TryGetProperty("start", out var start))
                    validFrom = DateTimeOffset.Parse(start.GetString()!);
                if (validFor.TryGetProperty("end", out var end))
                    validTo = DateTimeOffset.Parse(end.GetString()!);
            }

            result.Add(new ServiceEndpoint
            {
                Url = url,
                MajorApiVersion = apiVersion,
                ValidFrom = validFrom,
                ValidTo = validTo
            });
        }

        return result;
    }
}

/// <summary>
/// A service endpoint from the signing configuration.
/// </summary>
public sealed class ServiceEndpoint
{
    /// <summary>The service URL.</summary>
    public required string Url { get; init; }

    /// <summary>The major API version supported by this service.</summary>
    public int MajorApiVersion { get; init; } = 1;

    /// <summary>Start of the validity period.</summary>
    public DateTimeOffset ValidFrom { get; init; }

    /// <summary>End of the validity period (null = still active).</summary>
    public DateTimeOffset? ValidTo { get; init; }
}
