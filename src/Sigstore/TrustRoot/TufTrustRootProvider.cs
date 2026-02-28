using System.Reflection;
using Sigstore.Common;
using Tuf;

namespace Sigstore.TrustRoot;

/// <summary>
/// Obtains the Sigstore trusted root via The Update Framework (TUF),
/// providing cryptographic verification of the trust root chain.
/// This is the recommended trust root provider for production use.
/// </summary>
/// <remarks>
/// The provider embeds bootstrap root.json files for both production and staging
/// Sigstore TUF repositories. The TUF client uses secure update protocols to
/// walk from the bootstrap root to the latest trusted_root.json target.
/// </remarks>
public sealed class TufTrustRootProvider : ITrustRootProvider, IDisposable
{
    /// <summary>
    /// The Sigstore production TUF repository URL.
    /// </summary>
    public static readonly Uri ProductionUrl = new("https://tuf-repo-cdn.sigstore.dev/");

    /// <summary>
    /// The Sigstore staging TUF repository URL.
    /// </summary>
    public static readonly Uri StagingUrl = new("https://tuf-repo-cdn.sigstage.dev/");

    /// <summary>
    /// The TUF target path for the Sigstore trusted root.
    /// </summary>
    private const string TrustedRootTargetPath = "trusted_root.json";

    private readonly TufClient _tufClient;
    private TrustedRoot? _cached;

    /// <summary>
    /// Creates a TUF-based trust root provider for the given repository URL.
    /// For well-known Sigstore URLs (<see cref="ProductionUrl"/> and <see cref="StagingUrl"/>),
    /// the embedded bootstrap root is selected automatically.
    /// For custom URLs, provide a bootstrap root via <see cref="TufTrustRootProviderOptions.CustomTrustedRoot"/>.
    /// </summary>
    /// <param name="repositoryUrl">The TUF repository base URL.</param>
    /// <param name="options">Optional configuration overrides.</param>
    /// <exception cref="ArgumentException">
    /// Thrown when a custom URL is provided without <see cref="TufTrustRootProviderOptions.CustomTrustedRoot"/>.
    /// </exception>
    public TufTrustRootProvider(Uri repositoryUrl, TufTrustRootProviderOptions? options = null)
    {
        options ??= new TufTrustRootProviderOptions();
        var trustedRoot = options.CustomTrustedRoot ?? SelectEmbeddedRoot(repositoryUrl);
        var cache = options.Cache ?? CreateDefaultCache(repositoryUrl);

        var targetsUrl = new Uri(repositoryUrl, "targets/");

        _tufClient = new TufClient(new TufClientOptions
        {
            MetadataBaseUrl = repositoryUrl,
            TargetsBaseUrl = targetsUrl,
            TrustedRoot = trustedRoot,
            Cache = cache,
            Repository = options.Repository
        });
    }

    /// <inheritdoc />
    public async Task<TrustedRoot> GetTrustRootAsync(CancellationToken cancellationToken = default)
    {
        if (_cached is not null)
            return _cached;

        var targetBytes = await _tufClient.DownloadTargetAsync(TrustedRootTargetPath, cancellationToken);
        var json = System.Text.Encoding.UTF8.GetString(targetBytes);
        _cached = TrustedRoot.Deserialize(json);
        return _cached;
    }

    /// <summary>
    /// Selects the embedded bootstrap root.json for a well-known repository URL.
    /// </summary>
    private static byte[] SelectEmbeddedRoot(Uri repositoryUrl)
    {
        if (repositoryUrl == ProductionUrl || repositoryUrl.Host == ProductionUrl.Host)
            return LoadEmbeddedRoot("Sigstore.TrustRoot.TufData.root.json");

        if (repositoryUrl == StagingUrl || repositoryUrl.Host == StagingUrl.Host)
            return LoadEmbeddedRoot("Sigstore.TrustRoot.TufData.root-staging.json");

        throw new ArgumentException(
            $"No embedded bootstrap root for '{repositoryUrl}'. " +
            $"Provide a CustomTrustedRoot in TufTrustRootProviderOptions, " +
            $"or use TufTrustRootProvider.ProductionUrl or TufTrustRootProvider.StagingUrl.",
            nameof(repositoryUrl));
    }

    /// <summary>
    /// Loads an embedded bootstrap root.json from the assembly resources.
    /// </summary>
    private static byte[] LoadEmbeddedRoot(string resourceName)
    {
        var assembly = typeof(TufTrustRootProvider).Assembly;
        using var stream = assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException($"Embedded TUF root '{resourceName}' not found in assembly.");
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }

    /// <summary>
    /// Creates a default disk-based cache at <c>$HOME/.sigstore/dotnet/tuf/{url-slug}/</c>.
    /// </summary>
    private static ITufCache CreateDefaultCache(Uri repositoryUrl)
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrEmpty(home))
            return new InMemoryTufCache();

        var urlSlug = repositoryUrl.Host.Replace(".", "-");
        var cachePath = Path.Combine(home, ".sigstore", "dotnet", "tuf", urlSlug);
        return new FileSystemTufCache(cachePath);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _tufClient.Dispose();
    }
}

/// <summary>
/// Configuration options for <see cref="TufTrustRootProvider"/>.
/// </summary>
public sealed class TufTrustRootProviderOptions
{
    /// <summary>
    /// A custom TUF root.json to use instead of the embedded bootstrap root.
    /// Required when using a custom (non-Sigstore) TUF repository URL.
    /// </summary>
    public byte[]? CustomTrustedRoot { get; init; }

    /// <summary>
    /// Custom TUF cache implementation. Defaults to a file-system cache
    /// at <c>$HOME/.sigstore/dotnet/tuf/{url-slug}/</c>.
    /// </summary>
    public ITufCache? Cache { get; init; }

    /// <summary>
    /// Custom TUF repository implementation. If null, <see cref="HttpTufRepository"/> is used.
    /// </summary>
    public ITufRepository? Repository { get; init; }
}
