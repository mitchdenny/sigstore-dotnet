using System.Net;

namespace Tuf.Tests;

[TestClass]
public sealed class TufRepositoryTests
{
    [TestMethod]
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

        Assert.AreEqual(
            "https://example.com/metadata/2...%2Fdelegatedrole.json",
            requestedUri?.ToString());
    }

    [TestMethod]
    public async Task HttpTufRepository_FetchMetadata_ServerErrorThrows()
    {
        using var handler = new RecordingMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.InternalServerError));
        using var httpClient = new HttpClient(handler);
        using var repository = new HttpTufRepository(
            httpClient,
            new Uri("https://example.com/metadata/"),
            new Uri("https://example.com/targets/"));

        await Assert.ThrowsExactlyAsync<HttpRequestException>(
            () => repository.FetchMetadataAsync("root", 2));
    }

    [TestMethod]
    public async Task HttpTufRepository_FetchTarget_ServerErrorThrows()
    {
        using var handler = new RecordingMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.InternalServerError));
        using var httpClient = new HttpClient(handler);
        using var repository = new HttpTufRepository(
            httpClient,
            new Uri("https://example.com/metadata/"),
            new Uri("https://example.com/targets/"));

        await Assert.ThrowsExactlyAsync<HttpRequestException>(
            () => repository.FetchTargetAsync("artifact.txt"));
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
