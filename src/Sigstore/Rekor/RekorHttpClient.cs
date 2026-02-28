using System.Text;
using System.Text.Json;
using Sigstore.Common;

namespace Sigstore.Rekor;

/// <summary>
/// HTTP client for Rekor transparency log API. Supports both v1 and v2.
/// </summary>
public sealed class RekorHttpClient : IRekorClient, IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private readonly Uri _baseUrl;
    private readonly int _majorApiVersion;

    /// <summary>
    /// Creates a Rekor client with a new HttpClient.
    /// </summary>
    /// <param name="baseUrl">The Rekor base URL.</param>
    /// <param name="majorApiVersion">The API version to use (1 or 2). Default: 1.</param>
    public RekorHttpClient(Uri baseUrl, int majorApiVersion = 1)
        : this(new HttpClient(), baseUrl, majorApiVersion, ownsHttpClient: true)
    {
    }

    /// <summary>
    /// Creates a Rekor client with an existing HttpClient.
    /// </summary>
    public RekorHttpClient(HttpClient httpClient, Uri baseUrl, int majorApiVersion = 1)
        : this(httpClient, baseUrl, majorApiVersion, ownsHttpClient: false)
    {
    }

    private RekorHttpClient(HttpClient httpClient, Uri baseUrl, int majorApiVersion, bool ownsHttpClient)
    {
        _httpClient = httpClient;
        _baseUrl = baseUrl;
        _majorApiVersion = majorApiVersion;
        _ownsHttpClient = ownsHttpClient;
    }

    /// <inheritdoc />
    public async Task<TransparencyLogEntry> SubmitEntryAsync(
        RekorEntry entry,
        CancellationToken cancellationToken = default)
    {
        if (_majorApiVersion >= 2)
            return await SubmitEntryV2Async(entry, cancellationToken);

        return await SubmitEntryV1Async(entry, cancellationToken);
    }

    private async Task<TransparencyLogEntry> SubmitEntryV1Async(
        RekorEntry entry,
        CancellationToken cancellationToken)
    {
        var url = new Uri(_baseUrl, "api/v1/log/entries");

        var hashAlg = FormatHashAlgorithm(entry.DigestAlgorithm);
        var hashValue = Convert.ToHexString(entry.ArtifactDigest.ToArray()).ToLowerInvariant();
        var sigContent = Convert.ToBase64String(entry.Signature.ToArray());
        var pubKeyContent = Convert.ToBase64String(Encoding.UTF8.GetBytes(entry.VerificationMaterial));

        var body = $@"{{""kind"":""hashedrekord"",""apiVersion"":""0.0.1"",""spec"":{{""data"":{{""hash"":{{""algorithm"":""{hashAlg}"",""value"":""{hashValue}""}}}},""signature"":{{""content"":""{sigContent}"",""publicKey"":{{""content"":""{pubKeyContent}""}}}}}}}}";

        var responseBody = await PostJsonAsync(url, body, cancellationToken);

        using var doc = JsonDocument.Parse(responseBody);
        var root = doc.RootElement;

        // v1 response is { "uuid": { ... entry data ... } }
        foreach (var prop in root.EnumerateObject())
        {
            return ParseV1LogEntry(prop.Value);
        }

        throw new InvalidOperationException("Rekor response is empty.");
    }

    private async Task<TransparencyLogEntry> SubmitEntryV2Async(
        RekorEntry entry,
        CancellationToken cancellationToken)
    {
        var url = new Uri(_baseUrl, "api/v2/log/entries");

        var digestBase64 = Convert.ToBase64String(entry.ArtifactDigest.ToArray());
        var sigBase64 = Convert.ToBase64String(entry.Signature.ToArray());

        // The verification material is PEM-encoded cert — extract DER bytes
        var certDerBase64 = ExtractDerFromPem(entry.VerificationMaterial);

        // Build protobuf-JSON CreateEntryRequest
        var body = $@"{{""hashedRekordRequestV002"":{{""digest"":""{digestBase64}"",""signature"":{{""content"":""{sigBase64}"",""verifier"":{{""x509Certificate"":{{""rawBytes"":""{certDerBase64}""}},""keyDetails"":""PKIX_ECDSA_P256_SHA_256""}}}}}}}}";

        var responseBody = await PostJsonAsync(url, body, cancellationToken);

        // v2 response is a protobuf-JSON TransparencyLogEntry
        try
        {
            return ParseV2LogEntry(responseBody);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"Failed to parse Rekor v2 response: {ex.Message}. Response: {responseBody[..Math.Min(responseBody.Length, 500)]}", ex);
        }
    }

    /// <inheritdoc />
    public async Task<TransparencyLogEntry> SubmitDsseEntryAsync(
        RekorDsseEntry entry,
        CancellationToken cancellationToken = default)
    {
        if (_majorApiVersion >= 2)
            return await SubmitDsseEntryV2Async(entry, cancellationToken);
        return await SubmitDsseEntryV1Async(entry, cancellationToken);
    }

    private async Task<TransparencyLogEntry> SubmitDsseEntryV1Async(
        RekorDsseEntry entry,
        CancellationToken cancellationToken)
    {
        var url = new Uri(_baseUrl, "api/v1/log/entries");

        // Build the DSSE envelope JSON to embed in the request
        var payloadBase64 = Convert.ToBase64String(entry.Payload);
        var sigBase64 = Convert.ToBase64String(entry.Signature);
        var envelopeJson = $@"{{""payloadType"":""{entry.PayloadType}"",""payload"":""{payloadBase64}"",""signatures"":[{{""sig"":""{sigBase64}""}}]}}";
        var envelopeContent = Convert.ToBase64String(Encoding.UTF8.GetBytes(envelopeJson));
        var pubKeyContent = Convert.ToBase64String(Encoding.UTF8.GetBytes(entry.VerificationMaterial));

        var body = $@"{{""kind"":""dsse"",""apiVersion"":""0.0.1"",""spec"":{{""proposedContent"":{{""envelope"":""{envelopeContent}"",""verifiers"":[""{pubKeyContent}""]}}}}}}";

        var responseBody = await PostJsonAsync(url, body, cancellationToken);

        using var doc = JsonDocument.Parse(responseBody);
        var root = doc.RootElement;

        foreach (var prop in root.EnumerateObject())
        {
            return ParseV1LogEntry(prop.Value);
        }

        throw new InvalidOperationException("Rekor response is empty.");
    }

    private async Task<TransparencyLogEntry> SubmitDsseEntryV2Async(
        RekorDsseEntry entry,
        CancellationToken cancellationToken)
    {
        var url = new Uri(_baseUrl, "api/v2/log/entries");

        var payloadBase64 = Convert.ToBase64String(entry.Payload);
        var sigBase64 = Convert.ToBase64String(entry.Signature);
        var certDerBase64 = ExtractDerFromPem(entry.VerificationMaterial);

        // Build protobuf-JSON DSSERequestV002
        var body = $@"{{""dsseRequestV002"":{{""envelope"":{{""payload"":""{payloadBase64}"",""payloadType"":""{entry.PayloadType}"",""signatures"":[{{""sig"":""{sigBase64}""}}]}},""verifiers"":[{{""x509Certificate"":{{""rawBytes"":""{certDerBase64}""}},""keyDetails"":""PKIX_ECDSA_P256_SHA_256""}}]}}}}";

        var responseBody = await PostJsonAsync(url, body, cancellationToken);

        try
        {
            return ParseV2LogEntry(responseBody);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"Failed to parse Rekor v2 DSSE response: {ex.Message}. Response: {responseBody[..Math.Min(responseBody.Length, 500)]}", ex);
        }
    }

    private async Task<string> PostJsonAsync(Uri url, string body, CancellationToken cancellationToken)
    {
        using var httpRequest = new HttpRequestMessage(HttpMethod.Post, url);
        httpRequest.Content = new StringContent(body, Encoding.UTF8, "application/json");
        httpRequest.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

        using var response = await _httpClient.SendAsync(httpRequest, cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"Rekor request failed ({response.StatusCode}): {responseBody}");

        return responseBody;
    }

    private static string ExtractDerFromPem(string pem)
    {
        var base64 = pem
            .Replace("-----BEGIN CERTIFICATE-----", "")
            .Replace("-----END CERTIFICATE-----", "")
            .Replace("\n", "")
            .Replace("\r", "")
            .Trim();
        var derBytes = Convert.FromBase64String(base64);
        return Convert.ToBase64String(derBytes);
    }

    private static string FormatHashAlgorithm(HashAlgorithmType alg) => alg switch
    {
        HashAlgorithmType.Sha2_256 => "sha256",
        HashAlgorithmType.Sha2_384 => "sha384",
        HashAlgorithmType.Sha2_512 => "sha512",
        _ => "sha256"
    };

    private static TransparencyLogEntry ParseV1LogEntry(JsonElement entry)
    {
        var logIndex = entry.GetProperty("logIndex").GetInt64();
        var body = entry.GetProperty("body").GetString()!;
        var integratedTime = entry.GetProperty("integratedTime").GetInt64();

        // LogID is hex-encoded in v1
        var logIdHex = entry.GetProperty("logID").GetString()!;
        var logId = Convert.FromHexString(logIdHex);

        InclusionProof? inclusionProof = null;
        byte[]? inclusionPromise = null;

        if (entry.TryGetProperty("verification", out var verification))
        {
            if (verification.TryGetProperty("inclusionProof", out var proof))
            {
                var hashes = new List<byte[]>();
                if (proof.TryGetProperty("hashes", out var hashesElem))
                {
                    foreach (var h in hashesElem.EnumerateArray())
                        hashes.Add(Convert.FromHexString(h.GetString()!));
                }

                string? checkpoint = null;
                if (proof.TryGetProperty("checkpoint", out var cp))
                    checkpoint = cp.GetString();

                inclusionProof = new InclusionProof
                {
                    LogIndex = proof.GetProperty("logIndex").GetInt64(),
                    TreeSize = proof.GetProperty("treeSize").GetInt64(),
                    RootHash = Convert.FromHexString(proof.GetProperty("rootHash").GetString()!),
                    Hashes = hashes,
                    Checkpoint = checkpoint
                };
            }

            if (verification.TryGetProperty("signedEntryTimestamp", out var set))
            {
                inclusionPromise = Convert.FromBase64String(set.GetString()!);
            }
        }

        // Parse kind and version from the base64-encoded body
        var bodyJson = Encoding.UTF8.GetString(Convert.FromBase64String(body));
        using var bodyDoc = JsonDocument.Parse(bodyJson);
        var kind = bodyDoc.RootElement.TryGetProperty("kind", out var kindElem) ? kindElem.GetString() ?? "hashedrekord" : "hashedrekord";
        var kindVersion = bodyDoc.RootElement.TryGetProperty("apiVersion", out var avElem) ? avElem.GetString() ?? "0.0.1" : "0.0.1";

        return new TransparencyLogEntry
        {
            LogIndex = logIndex,
            LogId = logId,
            Kind = kind,
            KindVersion = kindVersion,
            Body = body,
            IntegratedTime = integratedTime,
            InclusionProof = inclusionProof,
            InclusionPromise = inclusionPromise
        };
    }

    internal static TransparencyLogEntry ParseV2LogEntry(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var logIndex = root.TryGetProperty("logIndex", out var li) && li.ValueKind != JsonValueKind.Null
            ? ParseInt64(li)
            : 0;

        byte[] logId = [];
        if (root.TryGetProperty("logId", out var logIdElem) && logIdElem.ValueKind == JsonValueKind.Object
            && logIdElem.TryGetProperty("keyId", out var keyId))
            logId = Convert.FromBase64String(keyId.GetString()!);

        string? kind = null;
        string? version = null;
        if (root.TryGetProperty("kindVersion", out var kv) && kv.ValueKind == JsonValueKind.Object)
        {
            kind = kv.TryGetProperty("kind", out var k) ? k.GetString() : null;
            version = kv.TryGetProperty("version", out var v) ? v.GetString() : null;
        }

        var integratedTime = root.TryGetProperty("integratedTime", out var it) && it.ValueKind != JsonValueKind.Null
            ? ParseInt64(it)
            : 0;

        byte[]? inclusionPromise = null;
        if (root.TryGetProperty("inclusionPromise", out var ip) && ip.ValueKind == JsonValueKind.Object
            && ip.TryGetProperty("signedEntryTimestamp", out var set))
        {
            inclusionPromise = Convert.FromBase64String(set.GetString()!);
        }

        InclusionProof? inclusionProof = null;
        if (root.TryGetProperty("inclusionProof", out var proofElem) && proofElem.ValueKind == JsonValueKind.Object)
        {
            var proofLogIndex = proofElem.TryGetProperty("logIndex", out var pli)
                ? ParseInt64(pli)
                : 0;

            var treeSize = proofElem.TryGetProperty("treeSize", out var ts)
                ? ParseInt64(ts)
                : 0;

            byte[] rootHash = [];
            if (proofElem.TryGetProperty("rootHash", out var rh))
                rootHash = Convert.FromBase64String(rh.GetString()!);

            var hashes = new List<byte[]>();
            if (proofElem.TryGetProperty("hashes", out var hashesElem))
            {
                foreach (var h in hashesElem.EnumerateArray())
                    hashes.Add(Convert.FromBase64String(h.GetString()!));
            }

            string? checkpoint = null;
            if (proofElem.TryGetProperty("checkpoint", out var cpElem) && cpElem.ValueKind == JsonValueKind.Object
                && cpElem.TryGetProperty("envelope", out var env))
            {
                checkpoint = env.GetString();
            }

            inclusionProof = new InclusionProof
            {
                LogIndex = proofLogIndex,
                TreeSize = treeSize,
                RootHash = rootHash,
                Hashes = hashes,
                Checkpoint = checkpoint
            };
        }

        string? body = null;
        if (root.TryGetProperty("canonicalizedBody", out var cb))
            body = cb.GetString();

        return new TransparencyLogEntry
        {
            LogIndex = logIndex,
            LogId = logId,
            Kind = kind,
            KindVersion = version,
            Body = body,
            IntegratedTime = integratedTime,
            InclusionProof = inclusionProof,
            InclusionPromise = inclusionPromise
        };
    }

    // Protobuf-JSON may encode int64 as either a string or a number.
    internal static long ParseInt64(JsonElement element) =>
        element.ValueKind == JsonValueKind.Number
            ? element.GetInt64()
            : long.Parse(element.GetString()!);

    /// <inheritdoc />
    public void Dispose()
    {
        if (_ownsHttpClient)
            _httpClient.Dispose();
    }
}
