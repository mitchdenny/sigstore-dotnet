using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Sigstore.Fulcio;

/// <summary>
/// HTTP client for Fulcio v2 certificate authority API.
/// </summary>
public sealed class FulcioHttpClient : IFulcioClient, IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private readonly Uri _baseUrl;

    /// <summary>
    /// Creates a Fulcio client with a new HttpClient.
    /// </summary>
    public FulcioHttpClient(Uri baseUrl)
        : this(new HttpClient(), baseUrl, ownsHttpClient: true)
    {
    }

    /// <summary>
    /// Creates a Fulcio client with an existing HttpClient.
    /// </summary>
    public FulcioHttpClient(HttpClient httpClient, Uri baseUrl)
        : this(httpClient, baseUrl, ownsHttpClient: false)
    {
    }

    private FulcioHttpClient(HttpClient httpClient, Uri baseUrl, bool ownsHttpClient)
    {
        _httpClient = httpClient;
        _baseUrl = baseUrl;
        _ownsHttpClient = ownsHttpClient;
    }

    /// <inheritdoc />
    public async Task<CertificateResponse> GetSigningCertificateAsync(
        CertificateRequest request,
        CancellationToken cancellationToken = default)
    {
        var url = new Uri(_baseUrl, "api/v2/signingCert");

        // Fulcio v2 expects base64-encoded PEM CSR in the certificateSigningRequest field
        var csrBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(request.CertificateSigningRequest));

        // Build JSON manually for AOT compatibility
        var body = $"{{\"credentials\":{{\"oidcIdentityToken\":\"{JsonEncodedText.Encode(request.IdentityToken)}\"}},\"certificateSigningRequest\":\"{csrBase64}\"}}";

        using var httpRequest = new HttpRequestMessage(HttpMethod.Post, url);
        httpRequest.Content = new StringContent(body, Encoding.UTF8, "application/json");
        httpRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", request.IdentityToken);

        using var response = await _httpClient.SendAsync(httpRequest, cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"Fulcio request failed ({response.StatusCode}): {responseBody}");

        using var doc = JsonDocument.Parse(responseBody);
        var root = doc.RootElement;

        // Response may contain signedCertificateEmbeddedSct or signedCertificateDetachedSct
        JsonElement chainElem;
        if (root.TryGetProperty("signedCertificateEmbeddedSct", out var embedded) &&
            embedded.TryGetProperty("chain", out var embeddedChain))
        {
            chainElem = embeddedChain;
        }
        else if (root.TryGetProperty("signedCertificateDetachedSct", out var detached) &&
                 detached.TryGetProperty("chain", out var detachedChain))
        {
            chainElem = detachedChain;
        }
        else
        {
            throw new InvalidOperationException("Fulcio response does not contain a certificate chain.");
        }

        var certPems = chainElem.GetProperty("certificates");
        var certChain = new List<byte[]>();
        foreach (var certPem in certPems.EnumerateArray())
        {
            var pem = certPem.GetString()!;
            var der = ConvertPemToDer(pem);
            certChain.Add(der);
        }

        return new CertificateResponse { CertificateChain = certChain };
    }

    private static byte[] ConvertPemToDer(string pem)
    {
        var lines = pem.Split('\n')
            .Where(l => !l.StartsWith("-----"))
            .Select(l => l.Trim());
        return Convert.FromBase64String(string.Join("", lines));
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_ownsHttpClient)
            _httpClient.Dispose();
    }
}
