using System.Net;

namespace Tuf.Tests;

public sealed class TufRepositoryTests
{
    [Fact]
    public async Task HttpTufRepository_FetchMetadata_EncodesRoleName()
    {
        Uri? requestedUri = null;
        using var handler = new RecordingMessageHandler(request =>
        {
            requestedUri = request.RequestUri;
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });
        using var httpClient = new HttpClient(handler);
        using var repository = new HttpTufRepository(
            httpClient,
            new Uri("https://example.com/metadata/"),
            new Uri("https://example.com/targets/"));

        await repository.FetchMetadataAsync("../delegatedrole", 2);

        Assert.Equal(
            "https://example.com/metadata/2...%2Fdelegatedrole.json",
            requestedUri?.ToString());
    }

    [Fact]
    public async Task HttpTufRepository_FetchMetadata_ServerErrorThrows()
    {
        using var handler = new RecordingMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.InternalServerError));
        using var httpClient = new HttpClient(handler);
        using var repository = new HttpTufRepository(
            httpClient,
            new Uri("https://example.com/metadata/"),
            new Uri("https://example.com/targets/"));

        await Assert.ThrowsAsync<HttpRequestException>(
            () => repository.FetchMetadataAsync("root", 2));
    }

    [Fact]
    public async Task HttpTufRepository_FetchTarget_ServerErrorThrows()
    {
        using var handler = new RecordingMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.InternalServerError));
        using var httpClient = new HttpClient(handler);
        using var repository = new HttpTufRepository(
            httpClient,
            new Uri("https://example.com/metadata/"),
            new Uri("https://example.com/targets/"));

        await Assert.ThrowsAsync<HttpRequestException>(
            () => repository.FetchTargetAsync("artifact.txt"));
    }

    [Fact]
    public void FileSystemTufCache_StoresEscapedRoleNames()
    {
        var basePath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("n"));

        try
        {
            var cache = new FileSystemTufCache(basePath);
            var data = "metadata"u8.ToArray();

            cache.StoreMetadata("../delegatedrole", data);

            Assert.Equal(data, cache.LoadMetadata("../delegatedrole"));
            Assert.True(File.Exists(Path.Combine(basePath, "..%2Fdelegatedrole.json")));
        }
        finally
        {
            if (Directory.Exists(basePath))
            {
                Directory.Delete(basePath, recursive: true);
            }
        }
    }

    private sealed class RecordingMessageHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _handleRequest;

        public RecordingMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> handleRequest)
        {
            _handleRequest = handleRequest;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(_handleRequest(request));
    }
}
