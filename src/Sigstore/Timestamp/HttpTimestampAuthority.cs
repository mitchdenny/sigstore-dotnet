using System.Formats.Asn1;
using System.Net.Http.Headers;
using System.Security.Cryptography;

namespace Sigstore.Timestamp;

/// <summary>
/// HTTP client for RFC 3161 Timestamp Authority.
/// </summary>
public sealed class HttpTimestampAuthority : ITimestampAuthority, IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private readonly Uri _baseUrl;

    /// <summary>
    /// Creates a TSA client with a new HttpClient.
    /// </summary>
    public HttpTimestampAuthority(Uri baseUrl)
        : this(new HttpClient(), baseUrl, ownsHttpClient: true)
    {
    }

    /// <summary>
    /// Creates a TSA client with an existing HttpClient.
    /// </summary>
    public HttpTimestampAuthority(HttpClient httpClient, Uri baseUrl)
        : this(httpClient, baseUrl, ownsHttpClient: false)
    {
    }

    private HttpTimestampAuthority(HttpClient httpClient, Uri baseUrl, bool ownsHttpClient)
    {
        _httpClient = httpClient;
        _baseUrl = baseUrl;
        _ownsHttpClient = ownsHttpClient;
    }

    /// <inheritdoc />
    public async Task<TimestampResponse> GetTimestampAsync(
        ReadOnlyMemory<byte> signature,
        CancellationToken cancellationToken = default)
    {
        var url = new Uri(_baseUrl, "api/v1/timestamp");

        // Build RFC 3161 TimeStampReq
        var hash = SHA256.HashData(signature.Span);
        var tsReq = BuildTimestampRequest(hash);

        using var httpRequest = new HttpRequestMessage(HttpMethod.Post, url);
        httpRequest.Content = new ByteArrayContent(tsReq);
        httpRequest.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");

        using var response = await _httpClient.SendAsync(httpRequest, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var errorBody = await response.Content.ReadAsStringAsync(cancellationToken);
            throw new InvalidOperationException($"TSA request failed ({response.StatusCode}): {errorBody}");
        }

        var tsResp = await response.Content.ReadAsByteArrayAsync(cancellationToken);
        return new TimestampResponse { RawBytes = tsResp };
    }

    /// <summary>
    /// Builds a minimal RFC 3161 TimeStampReq DER structure.
    /// </summary>
    private static byte[] BuildTimestampRequest(byte[] messageHash)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);

        // TimeStampReq ::= SEQUENCE {
        //   version INTEGER { v1(1) },
        //   messageImprint MessageImprint,
        //   certReq BOOLEAN DEFAULT FALSE
        // }
        writer.PushSequence();

        // version
        writer.WriteInteger(1);

        // MessageImprint ::= SEQUENCE {
        //   hashAlgorithm AlgorithmIdentifier,
        //   hashedMessage OCTET STRING
        // }
        writer.PushSequence();

        // AlgorithmIdentifier for SHA-256
        writer.PushSequence();
        writer.WriteObjectIdentifier("2.16.840.1.101.3.4.2.1"); // SHA-256 OID
        writer.PopSequence();

        writer.WriteOctetString(messageHash);
        writer.PopSequence();

        // certReq = true (request certificates in response)
        writer.WriteBoolean(true);

        writer.PopSequence();
        return writer.Encode();
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_ownsHttpClient)
            _httpClient.Dispose();
    }
}
