using System.Reflection;
using Tuf;

namespace Sigstore;

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
    private readonly TimeSpan _refreshInterval;
    private readonly TimeSpan _refreshRetryInterval;
    private readonly TimeProvider _timeProvider;
    private readonly SemaphoreSlim _refreshGate = new(1, 1);
    private ProviderState _state = ProviderState.Empty;

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
        if (options.RefreshInterval < TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(
                nameof(options.RefreshInterval),
                "Refresh interval cannot be negative.");
        if (options.RefreshRetryInterval < TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(
                nameof(options.RefreshRetryInterval),
                "Refresh retry interval cannot be negative.");

        var trustedRoot = options.CustomTrustedRoot ?? SelectEmbeddedRoot(repositoryUrl);
        var cache = options.Cache ?? CreateDefaultCache(repositoryUrl);

        _refreshInterval = options.RefreshInterval;
        _refreshRetryInterval = options.RefreshRetryInterval;
        _timeProvider = options.TimeProvider;

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
        var now = _timeProvider.GetUtcNow();
        var state = Volatile.Read(ref _state);
        if (CanUseFreshValue(state.Cached, now) ||
            CanUseRetryValue(state, now))
        {
            return state.Cached!.Root;
        }

        await _refreshGate.WaitAsync(cancellationToken);
        try
        {
            now = _timeProvider.GetUtcNow();
            state = Volatile.Read(ref _state);
            if (CanUseFreshValue(state.Cached, now) ||
                CanUseRetryValue(state, now))
            {
                return state.Cached!.Root;
            }

            try
            {
                var target = await _tufClient.GetTargetAsync(
                    TrustedRootTargetPath,
                    cancellationToken);
                var trustedRoot = DeserializeTrustedRoot(target.Content);
                var completedAt = _timeProvider.GetUtcNow();
                var metadataExpires = target.Metadata.Expires;

                if (metadataExpires <= completedAt)
                {
                    throw new TufExpiredException("metadata", metadataExpires);
                }

                var cached = new CachedTrustRoot(trustedRoot, completedAt, metadataExpires);
                Volatile.Write(ref _state, new ProviderState(cached, DateTimeOffset.MinValue));
                return trustedRoot;
            }
            catch (Exception ex) when (IsRepositoryUnavailable(ex, cancellationToken))
            {
                state = Volatile.Read(ref _state);
                now = _timeProvider.GetUtcNow();
                var cached = state.Cached;
                if (cached is null || cached.MetadataExpires <= now)
                {
                    throw;
                }

                var retryAfter = AddClamped(now, _refreshRetryInterval);
                Volatile.Write(ref _state, new ProviderState(cached, retryAfter));
                return cached.Root;
            }
        }
        finally
        {
            _refreshGate.Release();
        }
    }

    private static TrustedRoot DeserializeTrustedRoot(
        ReadOnlyMemory<byte> targetBytes)
    {
        var json = System.Text.Encoding.UTF8.GetString(targetBytes.Span);
        return TrustedRoot.Deserialize(json);
    }

    private bool CanUseFreshValue(CachedTrustRoot? cached, DateTimeOffset now) =>
        cached is not null &&
        cached.MetadataExpires > now &&
        IsWithinRefreshInterval(cached.RefreshedAt, now);

    private static bool CanUseRetryValue(ProviderState state, DateTimeOffset now) =>
        state.Cached is not null &&
        state.Cached.MetadataExpires > now &&
        state.RetryAfter > now;

    private bool IsWithinRefreshInterval(DateTimeOffset refreshedAt, DateTimeOffset now) =>
        refreshedAt <= now && now - refreshedAt < _refreshInterval;

    private static DateTimeOffset AddClamped(DateTimeOffset value, TimeSpan interval)
    {
        var remaining = DateTimeOffset.MaxValue - value;
        return interval >= remaining ? DateTimeOffset.MaxValue : value + interval;
    }

    private static bool IsRepositoryUnavailable(
        Exception exception,
        CancellationToken cancellationToken) =>
        exception is HttpRequestException ||
        exception is OperationCanceledException && !cancellationToken.IsCancellationRequested;

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
    /// Creates a versioned default disk cache under
    /// <c>$HOME/.sigstore/dotnet/{version-family}/tuf/{url-slug}/</c>.
    /// </summary>
    private static ITufCache CreateDefaultCache(Uri repositoryUrl)
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrEmpty(home))
            return new InMemoryTufCache();

        var assembly = typeof(TufTrustRootProvider).Assembly;
        var informationalVersion = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion
            ?? assembly.GetName().Version?.ToString()
            ?? "unknown";
        var cachePath = GetDefaultCachePath(home, repositoryUrl, informationalVersion);
        var versionPath = GetDefaultCacheVersionPath(home, informationalVersion);
        var tufPath = Path.Combine(versionPath, "tuf");
        return TryPreparePrivateCacheDirectory(versionPath) &&
               TryPreparePrivateCacheDirectory(tufPath)
            ? new FileSystemTufCache(cachePath)
            : new InMemoryTufCache();
    }

    internal static string GetDefaultCachePath(
        string home,
        Uri repositoryUrl,
        string informationalVersion)
    {
        return Path.Combine(
            GetDefaultCacheVersionPath(home, informationalVersion),
            "tuf",
            repositoryUrl.Host);
    }

    private static string GetDefaultCacheVersionPath(
        string home,
        string informationalVersion)
    {
        var separator = informationalVersion.IndexOfAny(['-', '+']);
        var versionFamily = separator >= 0
            ? informationalVersion[..separator]
            : informationalVersion;
        return Path.Combine(
            home,
            ".sigstore",
            "dotnet",
            versionFamily);
    }

    internal static bool TryPreparePrivateCacheDirectory(string path)
    {
        const UnixFileMode mode =
            UnixFileMode.UserRead |
            UnixFileMode.UserWrite |
            UnixFileMode.UserExecute;

        try
        {
            var directory = new DirectoryInfo(path);
            if (!directory.Exists)
            {
                if (OperatingSystem.IsWindows())
                {
                    Directory.CreateDirectory(path);
                }
                else
                {
                    Directory.CreateDirectory(path, mode);
                }
                directory.Refresh();
            }

            if (directory.LinkTarget is not null ||
                (directory.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                return false;
            }

            return OperatingSystem.IsWindows() ||
                   File.GetUnixFileMode(path) == mode;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _tufClient.Dispose();
        _refreshGate.Dispose();
    }

    private sealed record CachedTrustRoot(
        TrustedRoot Root,
        DateTimeOffset RefreshedAt,
        DateTimeOffset MetadataExpires);

    private sealed record ProviderState(
        CachedTrustRoot? Cached,
        DateTimeOffset RetryAfter)
    {
        public static ProviderState Empty { get; } =
            new(null, DateTimeOffset.MinValue);
    }
}

/// <summary>
/// Configuration options for <see cref="TufTrustRootProvider"/>.
/// </summary>
public sealed class TufTrustRootProviderOptions
{
    /// <summary>
    /// How long a successfully refreshed trusted root may be reused without
    /// checking the TUF repository again. Signed TUF metadata expiry always
    /// takes precedence. Set to zero to refresh on every request. Defaults to
    /// 24 hours.
    /// </summary>
    public TimeSpan RefreshInterval { get; init; } = TimeSpan.FromHours(24);

    /// <summary>
    /// How long to wait before retrying the TUF repository after a transient
    /// refresh failure while cached metadata remains unexpired. Defaults to
    /// five minutes. Set to zero to retry on every request.
    /// </summary>
    public TimeSpan RefreshRetryInterval { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// A custom TUF root.json to use instead of the embedded bootstrap root.
    /// Required when using a custom (non-Sigstore) TUF repository URL.
    /// </summary>
    public byte[]? CustomTrustedRoot { get; init; }

    /// <summary>
    /// Custom TUF cache implementation. Defaults to a file-system cache
    /// under
    /// <c>$HOME/.sigstore/dotnet/{version-family}/tuf/{url-slug}/</c>.
    /// </summary>
    public ITufCache? Cache { get; init; }

    /// <summary>
    /// Custom TUF repository implementation. If null, <see cref="HttpTufRepository"/> is used.
    /// </summary>
    public ITufRepository? Repository { get; init; }

    internal TimeProvider TimeProvider { get; init; } = TimeProvider.System;
}
