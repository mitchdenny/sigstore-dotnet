using System.Reflection;
using Tuf;
using Tuf.Tests;

namespace Sigstore.Tests;

public sealed class TufTrustRootProviderTests
{
    [Fact]
    public async Task GetTrustRootAsync_UsesMemoryWithinRefreshInterval()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var (repository, countingRepository) = CreateRepository(clock);
        using var provider = CreateProvider(
            repository,
            countingRepository,
            new InMemoryTufCache(),
            clock,
            refreshInterval: TimeSpan.FromHours(1));

        var first = await provider.GetTrustRootAsync();
        var requestCount = countingRepository.RequestCount;
        var second = await provider.GetTrustRootAsync();

        Assert.Same(first, second);
        Assert.Equal(requestCount, countingRepository.RequestCount);
    }

    [Fact]
    public async Task GetTrustRootAsync_CoalescesConcurrentRefreshes()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var (repository, countingRepository) = CreateRepository(clock);
        using var provider = CreateProvider(
            repository,
            countingRepository,
            new InMemoryTufCache(),
            clock,
            refreshInterval: TimeSpan.FromHours(1));

        var results = await Task.WhenAll(
            Enumerable.Range(0, 20).Select(_ => provider.GetTrustRootAsync()));

        Assert.All(results, result => Assert.Same(results[0], result));
        Assert.Equal(1, countingRepository.TimestampRequests);
    }

    [Fact]
    public async Task GetTrustRootAsync_RefreshesAfterInterval()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var (repository, countingRepository) = CreateRepository(clock);
        using var provider = CreateProvider(
            repository,
            countingRepository,
            new InMemoryTufCache(),
            clock,
            refreshInterval: TimeSpan.FromHours(1));

        await provider.GetTrustRootAsync();
        var requestCount = countingRepository.RequestCount;
        clock.Advance(TimeSpan.FromHours(1));

        await provider.GetTrustRootAsync();

        Assert.True(countingRepository.RequestCount > requestCount);
        Assert.Equal(2, countingRepository.TimestampRequests);
    }

    [Fact]
    public async Task GetTrustRootAsync_ZeroRefreshIntervalRefreshesEveryRequest()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var (repository, countingRepository) = CreateRepository(clock);
        using var provider = CreateProvider(
            repository,
            countingRepository,
            new InMemoryTufCache(),
            clock,
            refreshInterval: TimeSpan.Zero);

        await provider.GetTrustRootAsync();
        await provider.GetTrustRootAsync();

        Assert.Equal(2, countingRepository.TimestampRequests);
    }

    [Fact]
    public async Task GetTrustRootAsync_ThrottlesRetriesAfterTransientFailure()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var (repository, countingRepository) = CreateRepository(clock);
        using var provider = CreateProvider(
            repository,
            countingRepository,
            new InMemoryTufCache(),
            clock,
            refreshInterval: TimeSpan.FromHours(1),
            retryInterval: TimeSpan.FromMinutes(5));

        var cached = await provider.GetTrustRootAsync();
        clock.Advance(TimeSpan.FromHours(2));
        countingRepository.Unavailable = true;

        var fallback = await provider.GetTrustRootAsync();
        var failedRequestCount = countingRepository.RequestCount;
        clock.Advance(TimeSpan.FromMinutes(4));
        var throttled = await provider.GetTrustRootAsync();

        Assert.Same(cached, fallback);
        Assert.Same(cached, throttled);
        Assert.Equal(failedRequestCount, countingRepository.RequestCount);

        clock.Advance(TimeSpan.FromMinutes(1));
        await provider.GetTrustRootAsync();
        Assert.True(countingRepository.RequestCount > failedRequestCount);
    }

    [Fact]
    public async Task GetTrustRootAsync_DoesNotUseCachePastSignedExpiry()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var (repository, countingRepository) = CreateRepository(
            clock,
            timestampLifetime: TimeSpan.FromMinutes(30));
        using var provider = CreateProvider(
            repository,
            countingRepository,
            new InMemoryTufCache(),
            clock,
            refreshInterval: TimeSpan.FromHours(24));

        await provider.GetTrustRootAsync();
        clock.Advance(TimeSpan.FromMinutes(31));
        countingRepository.Unavailable = true;

        await Assert.ThrowsAsync<HttpRequestException>(
            () => provider.GetTrustRootAsync());
    }

    [Fact]
    public void Constructor_RejectsNegativeRefreshIntervals()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new TufTrustRootProvider(
                new Uri("https://example.com/"),
                new TufTrustRootProviderOptions
                {
                    CustomTrustedRoot = "root"u8.ToArray(),
                    RefreshInterval = TimeSpan.FromSeconds(-1)
                }));

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new TufTrustRootProvider(
                new Uri("https://example.com/"),
                new TufTrustRootProviderOptions
                {
                    CustomTrustedRoot = "root"u8.ToArray(),
                    RefreshRetryInterval = TimeSpan.FromSeconds(-1)
                }));
    }

    [Fact]
    public void DefaultCachePath_UsesSemanticVersionFamily()
    {
        var home = Path.Combine(Path.GetTempPath(), "home");

        var path = TufTrustRootProvider.GetDefaultCachePath(
            home,
            TufTrustRootProvider.ProductionUrl,
            "1.2.3-preview.1+build.linux");

        Assert.Equal(
            Path.Combine(
                home,
                ".sigstore",
                "dotnet",
                "1.2.3",
                "tuf",
                "tuf-repo-cdn.sigstore.dev"),
            path);
    }

    [Fact]
    public void DefaultCachePath_UsesStampedAssemblyVersionFamily()
    {
        var informationalVersion = typeof(TufTrustRootProvider)
            .Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()!
            .InformationalVersion;
        var versionFamily = informationalVersion.Split(['-', '+'], 2)[0];

        var path = TufTrustRootProvider.GetDefaultCachePath(
            Path.GetTempPath(),
            TufTrustRootProvider.ProductionUrl,
            informationalVersion);

        Assert.True(System.Version.TryParse(versionFamily, out var parsedVersion));
        Assert.Equal(3, parsedVersion.ToString().Split('.').Length);
        Assert.Contains(
            Path.Combine(".sigstore", "dotnet", versionFamily, "tuf"),
            path);
    }

    [Fact]
    public void PrivateCacheDirectory_RequiresOwnerOnlyUnixMode()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(path);
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead |
                UnixFileMode.UserWrite |
                UnixFileMode.UserExecute |
                UnixFileMode.GroupRead |
                UnixFileMode.GroupExecute);

            Assert.False(
                TufTrustRootProvider.TryPreparePrivateCacheDirectory(path));
            Assert.True(
                (File.GetUnixFileMode(path) & UnixFileMode.GroupRead) != 0);
        }
        finally
        {
            Directory.Delete(path);
        }
    }

    private static TufTrustRootProvider CreateProvider(
        RepositorySimulator repository,
        CountingRepository countingRepository,
        ITufCache cache,
        TimeProvider timeProvider,
        TimeSpan refreshInterval,
        TimeSpan? retryInterval = null) =>
        new(
            new Uri("https://example.com/metadata/"),
            new TufTrustRootProviderOptions
            {
                CustomTrustedRoot = repository.GetInitialRoot(),
                Cache = cache,
                Repository = countingRepository,
                RefreshInterval = refreshInterval,
                RefreshRetryInterval = retryInterval ?? TimeSpan.FromMinutes(5),
                TimeProvider = timeProvider
            });

    private static (RepositorySimulator Repository, CountingRepository Counting)
        CreateRepository(
            TimeProvider timeProvider,
            TimeSpan? timestampLifetime = null)
    {
        var now = timeProvider.GetUtcNow();
        var repository = new RepositorySimulator
        {
            RootExpiry = now.AddDays(30),
            TimestampExpiry = now.Add(timestampLifetime ?? TimeSpan.FromDays(7)),
            SnapshotExpiry = now.AddDays(7),
            TargetsExpiry = now.AddDays(7),
            ComputeMetafileHashesAndLength = true
        };
        repository.AddTarget(
            "trusted_root.json",
            """
            {
              "mediaType": "application/vnd.dev.sigstore.trustedroot.v0.2+json",
              "tlogs": [],
              "certificateAuthorities": [],
              "ctlogs": [],
              "timestampAuthorities": []
            }
            """u8.ToArray());
        repository.BumpNonRootVersions();
        repository.PublishAll();
        return (repository, new CountingRepository(repository));
    }

    private sealed class CountingRepository : ITufRepository
    {
        private readonly ITufRepository _inner;
        private int _requestCount;
        private int _timestampRequests;

        public CountingRepository(ITufRepository inner)
        {
            _inner = inner;
        }

        public bool Unavailable { get; set; }

        public int RequestCount => Volatile.Read(ref _requestCount);

        public int TimestampRequests => Volatile.Read(ref _timestampRequests);

        public Task<byte[]?> FetchMetadataAsync(
            string role,
            int? version = null,
            CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _requestCount);
            if (role == "timestamp")
            {
                Interlocked.Increment(ref _timestampRequests);
            }

            if (Unavailable)
            {
                throw new HttpRequestException("Repository unavailable.");
            }

            return _inner.FetchMetadataAsync(role, version, cancellationToken);
        }

        public Task<byte[]?> FetchTargetAsync(
            string targetPath,
            CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _requestCount);
            if (Unavailable)
            {
                throw new HttpRequestException("Repository unavailable.");
            }

            return _inner.FetchTargetAsync(targetPath, cancellationToken);
        }
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private readonly object _gate = new();
        private DateTimeOffset _utcNow;

        public ManualTimeProvider(DateTimeOffset utcNow)
        {
            _utcNow = utcNow;
        }

        public override DateTimeOffset GetUtcNow()
        {
            lock (_gate)
            {
                return _utcNow;
            }
        }

        public void Advance(TimeSpan value)
        {
            lock (_gate)
            {
                _utcNow += value;
            }
        }
    }

}
