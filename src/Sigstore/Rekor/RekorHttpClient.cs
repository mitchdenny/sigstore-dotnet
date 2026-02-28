using System.Text;
using System.Text.Json;
using Sigstore.Common;

namespace Sigstore.Rekor;

/// <summary>
/// HTTP client for Rekor v1 transparency log API.
/// </summary>
public sealed class RekorHttpClient : IRekorClient, IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private readonly Uri _baseUrl;

    /// <summary>
    /// Creates a Rekor client with a new HttpClient.
    /// </summary>
    public RekorHttpClient(Uri baseUrl)
        : this(new HttpClient(), baseUrl, ownsHttpClient: true)
    {
    }

    /// <summary>
    /// Creates a Rekor client with an existing HttpClient.
    /// </summary>
    public RekorHttpClient(HttpClient httpClient, Uri baseUrl)
        : this(httpClient, baseUrl, ownsHttpClient: false)
    {
    }

    private RekorHttpClient(HttpClient httpClient, Uri baseUrl, bool ownsHttpClient)
    {
        _httpClient = httpClient;
        _baseUrl = baseUrl;
        _ownsHttpClient = ownsHttpClient;
    }

    /// <inheritdoc />
    public async Task<TransparencyLogEntry> SubmitEntryAsync(
        RekorEntry entry,
        CancellationToken cancellationToken = default)
    {
        var url = new Uri(_baseUrl, "api/v1/log/entries");

        var hashAlg = entry.DigestAlgorithm switch
        {
            HashAlgorithmType.Sha2_256 => "sha256",
            HashAlgorithmType.Sha2_384 => "sha384",
            HashAlgorithmType.Sha2_512 => "sha512",
            _ => "sha256"
        };

        var hashValue = Convert.ToHexString(entry.ArtifactDigest.ToArray()).ToLowerInvariant();
        var sigContent = Convert.ToBase64String(entry.Signature.ToArray());
        var pubKeyContent = Convert.ToBase64String(Encoding.UTF8.GetBytes(entry.VerificationMaterial));

        // Build JSON manually for AOT compatibility
        var body = $@"{{""kind"":""hashedrekord"",""apiVersion"":""0.0.1"",""spec"":{{""data"":{{""hash"":{{""algorithm"":""{hashAlg}"",""value"":""{hashValue}""}}}},""signature"":{{""content"":""{sigContent}"",""publicKey"":{{""content"":""{pubKeyContent}""}}}}}}}}";

        using var httpRequest = new HttpRequestMessage(HttpMethod.Post, url);
        httpRequest.Content = new StringContent(body, Encoding.UTF8, "application/json");

        using var response = await _httpClient.SendAsync(httpRequest, cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"Rekor request failed ({response.StatusCode}): {responseBody}");

        using var doc = JsonDocument.Parse(responseBody);
        var root = doc.RootElement;

        // Response is { "uuid": { ... entry data ... } }
        foreach (var prop in root.EnumerateObject())
        {
            var entryData = prop.Value;
            return ParseLogEntry(entryData);
        }

        throw new InvalidOperationException("Rekor response is empty.");
    }

    private static TransparencyLogEntry ParseLogEntry(JsonElement entry)
    {
        var logIndex = entry.GetProperty("logIndex").GetInt64();
        var body = entry.GetProperty("body").GetString()!;
        var integratedTime = entry.GetProperty("integratedTime").GetInt64();

        // LogID is the hex-encoded SHA-256 of the log's public key
        var logIdHex = entry.GetProperty("logID").GetString()!;
        var logId = Convert.FromHexString(logIdHex);

        // Parse verification
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

        return new TransparencyLogEntry
        {
            LogIndex = logIndex,
            LogId = logId,
            Body = body,
            IntegratedTime = integratedTime,
            InclusionProof = inclusionProof,
            InclusionPromise = inclusionPromise
        };
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_ownsHttpClient)
            _httpClient.Dispose();
    }
}
