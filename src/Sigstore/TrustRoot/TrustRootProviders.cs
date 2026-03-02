
namespace Sigstore;

/// <summary>
/// Loads a trusted root from a JSON file on disk.
/// </summary>
public sealed class FileTrustRootProvider : ITrustRootProvider
{
    private readonly FileInfo _file;

    /// <summary>
    /// Creates a provider that reads the trusted root from the given file.
    /// </summary>
    public FileTrustRootProvider(FileInfo file)
    {
        _file = file ?? throw new ArgumentNullException(nameof(file));
    }

    /// <inheritdoc />
    public async Task<TrustedRoot> GetTrustRootAsync(CancellationToken cancellationToken = default)
    {
        string json = await File.ReadAllTextAsync(_file.FullName, cancellationToken);
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
