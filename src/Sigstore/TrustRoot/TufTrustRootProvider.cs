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
/// The provider embeds a bootstrap root.json from the Sigstore TUF
/// repository and uses TUF's secure update protocol to fetch the latest
/// trusted_root.json target. Custom root overrides are supported for
/// root key compromise recovery scenarios.
/// </remarks>
public sealed class TufTrustRootProvider : ITrustRootProvider, IDisposable
{
    /// <summary>
    /// The default Sigstore TUF repository metadata URL.
    /// </summary>
    public static readonly Uri DefaultMetadataUrl = new("https://tuf-repo-cdn.sigstore.dev/");

    /// <summary>
    /// The default Sigstore TUF repository targets URL.
    /// </summary>
    public static readonly Uri DefaultTargetsUrl = new("https://tuf-repo-cdn.sigstore.dev/targets/");

    /// <summary>
    /// The TUF target path for the Sigstore trusted root.
    /// </summary>
    private const string TrustedRootTargetPath = "trusted_root.json";

    private readonly TufClient _tufClient;
    private TrustedRoot? _cached;

    /// <summary>
    /// Creates a TUF-based trust root provider using the default Sigstore TUF repository
    /// and the embedded bootstrap root.json.
    /// </summary>
    public TufTrustRootProvider()
        : this(new TufTrustRootProviderOptions())
    {
    }

    /// <summary>
    /// Creates a TUF-based trust root provider with the specified options.
    /// </summary>
    public TufTrustRootProvider(TufTrustRootProviderOptions options)
    {
        var trustedRoot = options.CustomTrustedRoot ?? LoadEmbeddedRoot();
        var cache = options.Cache ?? new InMemoryTufCache();

        _tufClient = new TufClient(new TufClientOptions
        {
            MetadataBaseUrl = options.MetadataBaseUrl ?? DefaultMetadataUrl,
            TargetsBaseUrl = options.TargetsBaseUrl ?? DefaultTargetsUrl,
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
    /// Loads the embedded bootstrap root.json from the assembly resources.
    /// </summary>
    private static byte[] LoadEmbeddedRoot()
    {
        var assembly = typeof(TufTrustRootProvider).Assembly;
        using var stream = assembly.GetManifestResourceStream("Sigstore.TrustRoot.TufData.root.json")
            ?? throw new InvalidOperationException("Embedded TUF root.json not found in assembly.");
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
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
    /// Override the TUF repository metadata URL. Defaults to the Sigstore public-good CDN.
    /// </summary>
    public Uri? MetadataBaseUrl { get; init; }

    /// <summary>
    /// Override the TUF repository targets URL. Defaults to the Sigstore public-good CDN.
    /// </summary>
    public Uri? TargetsBaseUrl { get; init; }

    /// <summary>
    /// A custom TUF root.json to use instead of the embedded bootstrap root.
    /// Use this for root key compromise recovery by providing a new trusted root.
    /// </summary>
    public byte[]? CustomTrustedRoot { get; init; }

    /// <summary>
    /// Custom TUF cache implementation. Defaults to <see cref="InMemoryTufCache"/>.
    /// </summary>
    public ITufCache? Cache { get; init; }

    /// <summary>
    /// Custom TUF repository implementation. If null, <see cref="HttpTufRepository"/> is used.
    /// </summary>
    public ITufRepository? Repository { get; init; }
}
