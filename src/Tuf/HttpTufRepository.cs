using System.Diagnostics;

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
        TagList tags = default;
        tags.Add("tuf.metadata.role", NormalizeRole(role));
        tags.Add("tuf.repository.versioned", version.HasValue);
        using var activity =
            TufInstrumentation.StartActivity(
                "tuf.repository.metadata.fetch",
                tags);
        try
        {
            var escapedRole = Uri.EscapeDataString(role);
            var fileName = version.HasValue ? $"{version}.{escapedRole}.json" : $"{escapedRole}.json";
            var url = new Uri(_metadataBaseUrl, fileName);

            using var response = await _httpClient.GetAsync(url, cancellationToken);
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                activity?.SetTag("tuf.repository.found", false);
                return null;
            }

            response.EnsureSuccessStatusCode();
            activity?.SetTag("tuf.repository.found", true);
            return await response.Content.ReadAsByteArrayAsync(cancellationToken);
        }
        catch (Exception exception)
        {
            TufInstrumentation.SetError(
                activity,
                exception,
                cancellationToken);
            throw;
        }
    }

    /// <inheritdoc/>
    public async Task<byte[]?> FetchTargetAsync(string targetPath, CancellationToken cancellationToken = default)
    {
        using var activity =
            TufInstrumentation.StartActivity(
                "tuf.repository.target.fetch");
        try
        {
            var url = new Uri(_targetsBaseUrl, targetPath);

            using var response = await _httpClient.GetAsync(url, cancellationToken);
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                activity?.SetTag("tuf.repository.found", false);
                return null;
            }

            response.EnsureSuccessStatusCode();
            activity?.SetTag("tuf.repository.found", true);
            return await response.Content.ReadAsByteArrayAsync(cancellationToken);
        }
        catch (Exception exception)
        {
            TufInstrumentation.SetError(
                activity,
                exception,
                cancellationToken);
            throw;
        }
    }

    private static string NormalizeRole(string role) =>
        role is "root" or "timestamp" or "snapshot" or "targets"
            ? role
            : "delegated";

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_ownsHttpClient)
            _httpClient.Dispose();
    }
}
