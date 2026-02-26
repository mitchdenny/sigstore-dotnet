namespace Tuf;

/// <summary>
/// Fetches TUF metadata and targets over HTTP.
/// </summary>
public sealed class HttpTufRepository : ITufRepository, IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly Uri _metadataBaseUrl;
    private readonly Uri _targetsBaseUrl;
    private readonly bool _ownsHttpClient;

    /// <summary>
    /// Creates a new HTTP TUF repository fetcher.
    /// </summary>
    public HttpTufRepository(Uri metadataBaseUrl, Uri targetsBaseUrl)
        : this(new HttpClient(), metadataBaseUrl, targetsBaseUrl, ownsHttpClient: true)
    {
    }

    /// <summary>
    /// Creates a new HTTP TUF repository fetcher with a provided HttpClient.
    /// </summary>
    public HttpTufRepository(HttpClient httpClient, Uri metadataBaseUrl, Uri targetsBaseUrl, bool ownsHttpClient = false)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _metadataBaseUrl = metadataBaseUrl;
        _targetsBaseUrl = targetsBaseUrl;
        _ownsHttpClient = ownsHttpClient;
    }

    /// <inheritdoc/>
    public async Task<byte[]?> FetchMetadataAsync(string role, int? version = null, CancellationToken cancellationToken = default)
    {
        var fileName = version.HasValue ? $"{version}.{role}.json" : $"{role}.json";
        var url = new Uri(_metadataBaseUrl, fileName);

        try
        {
            var response = await _httpClient.GetAsync(url, cancellationToken);
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                return null;
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsByteArrayAsync(cancellationToken);
        }
        catch (HttpRequestException)
        {
            return null;
        }
    }

    /// <inheritdoc/>
    public async Task<byte[]?> FetchTargetAsync(string targetPath, CancellationToken cancellationToken = default)
    {
        var url = new Uri(_targetsBaseUrl, targetPath);

        try
        {
            var response = await _httpClient.GetAsync(url, cancellationToken);
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                return null;
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsByteArrayAsync(cancellationToken);
        }
        catch (HttpRequestException)
        {
            return null;
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_ownsHttpClient)
            _httpClient.Dispose();
    }
}
