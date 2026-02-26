namespace Tuf;

/// <summary>
/// A TUF client that securely updates metadata and downloads targets
/// from a TUF repository, implementing the TUF specification §5.1-5.6.
/// </summary>
public sealed class TufClient : IDisposable
{
    private readonly TufClientOptions _options;
    private readonly ITufRepository _repository;
    private readonly ITufCache _cache;
    private readonly bool _ownsRepository;

    /// <summary>
    /// Creates a new TUF client with the specified options.
    /// </summary>
    public TufClient(TufClientOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _cache = options.Cache ?? new InMemoryTufCache();

        if (options.Repository != null)
        {
            _repository = options.Repository;
            _ownsRepository = false;
        }
        else
        {
            _repository = new HttpTufRepository(
                options.MetadataBaseUrl,
                options.TargetsBaseUrl ?? new Uri(options.MetadataBaseUrl, "../targets/"));
            _ownsRepository = true;
        }

        // Initialize cache with the trusted root if not already present
        var cachedRoot = _cache.LoadMetadata("root");
        if (cachedRoot == null)
        {
            _cache.StoreMetadata("root", options.TrustedRoot);
        }
    }

    /// <summary>
    /// Refreshes local metadata from the TUF repository.
    /// Implements the TUF client update workflow (spec §5.1-5.6).
    /// </summary>
    /// <returns>True if the refresh succeeded, false otherwise.</returns>
    public async Task<bool> RefreshAsync(CancellationToken cancellationToken = default)
    {
        // TODO: Implement spec §5.1-5.6
        await Task.CompletedTask;
        throw new NotImplementedException();
    }

    /// <summary>
    /// Downloads a target file, verifying its hash and length against targets metadata.
    /// Automatically refreshes metadata if needed.
    /// </summary>
    /// <param name="targetPath">The target path as specified in targets metadata.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The verified target file contents.</returns>
    public async Task<byte[]> DownloadTargetAsync(string targetPath, CancellationToken cancellationToken = default)
    {
        // TODO: Implement target download with hash/length verification
        await Task.CompletedTask;
        throw new NotImplementedException();
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_ownsRepository && _repository is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
}
