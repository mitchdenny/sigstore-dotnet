namespace Tuf.Tests;

public class TufClientTests : IDisposable
{
    private readonly RepositorySimulator _repo;
    private TufClient? _client;

    public TufClientTests()
    {
        _repo = new RepositorySimulator();
    }

    private TufClient CreateClient(byte[]? trustedRoot = null)
    {
        var cache = new InMemoryTufCache();
        _client = new TufClient(new TufClientOptions
        {
            MetadataBaseUrl = new Uri("https://example.com/metadata/"),
            TrustedRoot = trustedRoot ?? _repo.GetInitialRoot(),
            Repository = _repo,
            Cache = cache
        });
        return _client;
    }

    public void Dispose()
    {
        _client?.Dispose();
    }

    // ---- Basic Refresh ----

    [Fact]
    public async Task Refresh_BasicFlow_Succeeds()
    {
        _repo.AddTarget("trusted_root.json", "hello"u8.ToArray());
        _repo.BumpNonRootVersions();
        var client = CreateClient();

        await client.RefreshAsync();

        // Should have fetched root (404 for v2), timestamp, snapshot, targets
        Assert.Contains("2.root.json", _repo.RequestLog);
        Assert.Contains("timestamp.json", _repo.RequestLog);
    }

    [Fact]
    public async Task Refresh_ThenDownloadTarget_Succeeds()
    {
        var content = "test content"u8.ToArray();
        _repo.AddTarget("myfile.txt", content);
        _repo.BumpNonRootVersions();
        var client = CreateClient();

        var result = await client.DownloadTargetAsync("myfile.txt");

        Assert.Equal(content, result);
    }

    [Fact]
    public async Task DownloadTarget_ImplicitRefresh()
    {
        var content = "auto-refresh"u8.ToArray();
        _repo.AddTarget("autofile.txt", content);
        _repo.BumpNonRootVersions();
        var client = CreateClient();

        // DownloadTargetAsync should trigger RefreshAsync automatically
        var result = await client.DownloadTargetAsync("autofile.txt");
        Assert.Equal(content, result);
    }

    [Fact]
    public async Task DownloadTarget_NotInTargets_Throws()
    {
        _repo.AddTarget("exists.txt", "data"u8.ToArray());
        _repo.BumpNonRootVersions();
        var client = CreateClient();

        var ex = await Assert.ThrowsAsync<TufException>(
            () => client.DownloadTargetAsync("nonexistent.txt"));
        Assert.Contains("not found", ex.Message);
    }

    [Fact]
    public async Task DownloadTarget_CachesContent()
    {
        var content = "cached"u8.ToArray();
        _repo.AddTarget("cached.txt", content);
        _repo.BumpNonRootVersions();
        var client = CreateClient();

        await client.RefreshAsync();
        var result1 = await client.DownloadTargetAsync("cached.txt");
        var result2 = await client.DownloadTargetAsync("cached.txt");

        Assert.Equal(content, result1);
        Assert.Equal(content, result2);
        // Only fetched from repo once
        Assert.Equal(1, _repo.RequestLog.Count(r => r == "target:cached.txt"));
    }

    // ---- Root Rotation ----

    [Fact]
    public async Task Refresh_RootRotation_FetchesNewRoot()
    {
        var client = CreateClient();

        // Bump root version after client is created
        _repo.BumpRootVersion();
        _repo.BumpNonRootVersions();

        await client.RefreshAsync();

        // Should have fetched root v2 and v3 (404)
        Assert.Contains("2.root.json", _repo.RequestLog);
        Assert.Contains("3.root.json", _repo.RequestLog);
    }

    [Fact]
    public async Task Refresh_MultipleRootRotations_FetchesAll()
    {
        var client = CreateClient();

        _repo.BumpRootVersion(); // v2
        _repo.BumpRootVersion(); // v3
        _repo.BumpNonRootVersions();

        await client.RefreshAsync();

        Assert.Contains("2.root.json", _repo.RequestLog);
        Assert.Contains("3.root.json", _repo.RequestLog);
        Assert.Contains("4.root.json", _repo.RequestLog); // 404
    }

    // ---- Signature Verification Failures ----

    [Fact]
    public async Task Refresh_UnsignedTimestamp_Throws()
    {
        _repo.UnsignedRoles.Add("timestamp");
        _repo.BumpNonRootVersions();
        var client = CreateClient();

        var ex = await Assert.ThrowsAsync<TufException>(() => client.RefreshAsync());
        Assert.Contains("Timestamp signature verification failed", ex.Message);
    }

    [Fact]
    public async Task Refresh_UnsignedSnapshot_Throws()
    {
        _repo.UnsignedRoles.Add("snapshot");
        _repo.BumpNonRootVersions();
        var client = CreateClient();

        var ex = await Assert.ThrowsAsync<TufException>(() => client.RefreshAsync());
        Assert.Contains("Snapshot signature verification failed", ex.Message);
    }

    [Fact]
    public async Task Refresh_UnsignedTargets_Throws()
    {
        _repo.UnsignedRoles.Add("targets");
        _repo.BumpNonRootVersions();
        var client = CreateClient();

        var ex = await Assert.ThrowsAsync<TufException>(() => client.RefreshAsync());
        Assert.Contains("Targets signature verification failed", ex.Message);
    }

    // ---- Expiry Checks ----

    [Fact]
    public async Task Refresh_ExpiredRoot_Throws()
    {
        _repo.ExpiredRoles.Add("root");
        _repo.PublishAll();
        var client = CreateClient();

        await Assert.ThrowsAsync<TufExpiredException>(() => client.RefreshAsync());
    }

    [Fact]
    public async Task Refresh_ExpiredTimestamp_Throws()
    {
        _repo.ExpiredRoles.Add("timestamp");
        _repo.PublishAll();
        var client = CreateClient();

        await Assert.ThrowsAsync<TufExpiredException>(() => client.RefreshAsync());
    }

    [Fact]
    public async Task Refresh_ExpiredSnapshot_Throws()
    {
        _repo.ExpiredRoles.Add("snapshot");
        _repo.PublishAll();
        var client = CreateClient();

        await Assert.ThrowsAsync<TufExpiredException>(() => client.RefreshAsync());
    }

    [Fact]
    public async Task Refresh_ExpiredTargets_Throws()
    {
        _repo.ExpiredRoles.Add("targets");
        _repo.PublishAll();
        var client = CreateClient();

        await Assert.ThrowsAsync<TufExpiredException>(() => client.RefreshAsync());
    }

    // ---- Rollback Attack ----

    [Fact]
    public async Task Refresh_TimestampRollback_Throws()
    {
        var client = CreateClient();
        await client.RefreshAsync();

        // Simulate rollback: reduce timestamp version
        _repo.TimestampVersion = 0;
        _repo.PublishAll();

        // Create a new client with the same cache that remembers the old timestamp
        // Actually, RefreshAsync on the same client should detect rollback
        var ex = await Assert.ThrowsAsync<TufException>(() => client.RefreshAsync());
        Assert.Contains("rollback", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // ---- Target Hash Verification ----

    [Fact]
    public async Task DownloadTarget_HashMismatch_Throws()
    {
        _repo.AddTarget("file.txt", "original"u8.ToArray());
        _repo.BumpNonRootVersions();
        var client = CreateClient();
        await client.RefreshAsync();

        // Now tamper with the target content on the repo
        // We need to modify the repo's stored target after metadata is published
        var field = typeof(RepositorySimulator).GetField("_targets",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        var targets = (Dictionary<string, byte[]>)field!.GetValue(_repo)!;
        targets["file.txt"] = "tampered"u8.ToArray();

        var ex = await Assert.ThrowsAsync<TufException>(
            () => client.DownloadTargetAsync("file.txt"));
        Assert.Contains("hash verification failed", ex.Message);
    }
}
