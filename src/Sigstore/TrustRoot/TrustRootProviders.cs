using Sigstore.Common;

namespace Sigstore.TrustRoot;

/// <summary>
/// Loads a trusted root from a JSON file on disk.
/// </summary>
public sealed class FileTrustRootProvider : ITrustRootProvider
{
    private readonly string _path;

    /// <summary>
    /// Creates a provider that reads the trusted root from the given file path.
    /// </summary>
    public FileTrustRootProvider(string path)
    {
        _path = path ?? throw new ArgumentNullException(nameof(path));
    }

    /// <inheritdoc />
    public async Task<TrustedRoot> GetTrustRootAsync(CancellationToken cancellationToken = default)
    {
        string json = await File.ReadAllTextAsync(_path, cancellationToken);
        return TrustedRoot.Deserialize(json);
    }
}

/// <summary>
/// Wraps an already-loaded <see cref="TrustedRoot"/> instance.
/// Useful for testing or when the root is obtained from a custom source.
/// </summary>
public sealed class InMemoryTrustRootProvider : ITrustRootProvider
{
    private readonly TrustedRoot _trustRoot;

    /// <summary>
    /// Creates a provider wrapping the given trusted root.
    /// </summary>
    public InMemoryTrustRootProvider(TrustedRoot trustRoot)
    {
        _trustRoot = trustRoot ?? throw new ArgumentNullException(nameof(trustRoot));
    }

    /// <inheritdoc />
    public Task<TrustedRoot> GetTrustRootAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(_trustRoot);
    }
}

/// <summary>
/// Downloads the trusted root for the Sigstore public-good instance from the
/// sigstore/root-signing GitHub repository. Caches the result for the lifetime
/// of the provider.
/// </summary>
public sealed class PublicGoodTrustRootProvider : ITrustRootProvider, IDisposable
{
    /// <summary>
    /// The default URL for the Sigstore public-good trusted root.
    /// </summary>
    public static readonly Uri DefaultTrustedRootUrl = new(
        "https://raw.githubusercontent.com/sigstore/root-signing/main/targets/trusted_root.json");

    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private readonly Uri _url;
    private TrustedRoot? _cached;

    /// <summary>
    /// Creates a provider that downloads from the default Sigstore public-good URL.
    /// </summary>
    public PublicGoodTrustRootProvider()
        : this(new HttpClient(), ownsHttpClient: true, DefaultTrustedRootUrl)
    {
    }

    /// <summary>
    /// Creates a provider using the given <see cref="HttpClient"/>.
    /// </summary>
    public PublicGoodTrustRootProvider(HttpClient httpClient)
        : this(httpClient, ownsHttpClient: false, DefaultTrustedRootUrl)
    {
    }

    /// <summary>
    /// Creates a provider using the given <see cref="HttpClient"/> and URL.
    /// </summary>
    public PublicGoodTrustRootProvider(HttpClient httpClient, Uri trustedRootUrl)
        : this(httpClient, ownsHttpClient: false, trustedRootUrl)
    {
    }

    private PublicGoodTrustRootProvider(HttpClient httpClient, bool ownsHttpClient, Uri url)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _url = url ?? throw new ArgumentNullException(nameof(url));
        _ownsHttpClient = ownsHttpClient;
    }

    /// <inheritdoc />
    public async Task<TrustedRoot> GetTrustRootAsync(CancellationToken cancellationToken = default)
    {
        if (_cached is not null)
        {
            return _cached;
        }

        string json = await _httpClient.GetStringAsync(_url, cancellationToken);
        _cached = TrustedRoot.Deserialize(json);
        return _cached;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _httpClient.Dispose();
        }
    }
}
