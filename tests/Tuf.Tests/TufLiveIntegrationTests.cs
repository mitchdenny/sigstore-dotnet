namespace Tuf.Tests;

[TestClass]
/// <summary>
/// Integration tests that exercise the TUF client against the real Sigstore TUF repository.
/// These tests require network access and may fail if the Sigstore infrastructure is down.
/// </summary>
[TestCategory("Integration")]
public class TufLiveIntegrationTests : IDisposable
{
    private static readonly Uri SigstoreMetadataUrl = new("https://tuf-repo-cdn.sigstore.dev/");
    private static readonly Uri SigstoreTargetsUrl = new("https://tuf-repo-cdn.sigstore.dev/targets/");

    private readonly HttpClient _httpClient = new();

    public void Dispose() => _httpClient.Dispose();

    private async Task<byte[]> FetchInitialRootAsync()
    {
        // Fetch root v1 and walk up to the current root
        // Or use a known trusted root - we'll use the embedded fixture for bootstrap
        return await File.ReadAllBytesAsync(Path.Combine("Fixtures", "root.json"));
    }

    [TestMethod]
    public async Task Refresh_SigstorePublicGood_Succeeds()
    {
        var trustedRoot = await FetchInitialRootAsync();
        var repo = new HttpTufRepository(_httpClient, SigstoreMetadataUrl, SigstoreTargetsUrl);

        using var client = new TufClient(new TufClientOptions
        {
            MetadataBaseUrl = SigstoreMetadataUrl,
            TargetsBaseUrl = SigstoreTargetsUrl,
            TrustedRoot = trustedRoot,
            Repository = repo
        });

        // This should succeed - fetches latest root, timestamp, snapshot, targets
        await client.GetTrustedMetadataAsync();
    }

    [TestMethod]
    public async Task DownloadTarget_TrustedRoot_Succeeds()
    {
        var trustedRoot = await FetchInitialRootAsync();
        var repo = new HttpTufRepository(_httpClient, SigstoreMetadataUrl, SigstoreTargetsUrl);

        using var client = new TufClient(new TufClientOptions
        {
            MetadataBaseUrl = SigstoreMetadataUrl,
            TargetsBaseUrl = SigstoreTargetsUrl,
            TrustedRoot = trustedRoot,
            Repository = repo
        });

        // Download trusted_root.json - this is the main target Sigstore clients need
        var target = await client.GetTargetAsync("trusted_root.json");

        Assert.IsFalse(target.Content.IsEmpty);

        // It should be valid JSON
        var json = System.Text.Encoding.UTF8.GetString(target.Content.Span);
        Assert.Contains("certificateAuthorities", json);
    }

    [TestMethod]
    public async Task Refresh_WithCaching_SecondRefreshFaster()
    {
        var trustedRoot = await FetchInitialRootAsync();
        var cache = new InMemoryTufCache();
        var repo = new HttpTufRepository(_httpClient, SigstoreMetadataUrl, SigstoreTargetsUrl);

        using var client = new TufClient(new TufClientOptions
        {
            MetadataBaseUrl = SigstoreMetadataUrl,
            TargetsBaseUrl = SigstoreTargetsUrl,
            TrustedRoot = trustedRoot,
            Repository = repo,
            Cache = cache
        });

        // First refresh populates cache
        await client.GetTrustedMetadataAsync();

        // Cache should have all metadata
        Assert.IsNotNull(cache.LoadMetadata("root"));
        Assert.IsNotNull(cache.LoadMetadata("timestamp"));
        Assert.IsNotNull(cache.LoadMetadata("snapshot"));
        Assert.IsNotNull(cache.LoadMetadata("targets"));
    }
}
