using Sigstore.Signing;
using Sigstore.Fulcio;
using Sigstore.Rekor;
using Sigstore.Timestamp;
using Sigstore.Oidc;
using Sigstore.Common;

namespace Sigstore.Tests.Signing;

public class SigstoreSignerTests
{
    [Fact]
    public async Task SignAsync_Stream_ThrowsOnNull()
    {
        var signer = CreateSigner();

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => signer.SignAsync((Stream)null!));
    }

    [Fact]
    public async Task AttestAsync_ThrowsOnNull()
    {
        var signer = CreateSigner();

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => signer.AttestAsync(null!));
    }

    [Fact]
    public void Constructor_ThrowsOnNullFulcioClient()
    {
        Assert.Throws<ArgumentNullException>(
            () => new SigstoreSigner(null!, new FakeRekorClient(), new FakeTsa(), new FakeTokenProvider()));
    }

    [Fact]
    public void Constructor_ThrowsOnNullRekorClient()
    {
        Assert.Throws<ArgumentNullException>(
            () => new SigstoreSigner(new FakeFulcioClient(), null!, new FakeTsa(), new FakeTokenProvider()));
    }

    [Fact]
    public void Constructor_ThrowsOnNullTimestampAuthority()
    {
        Assert.Throws<ArgumentNullException>(
            () => new SigstoreSigner(new FakeFulcioClient(), new FakeRekorClient(), null!, new FakeTokenProvider()));
    }

    [Fact]
    public void Constructor_ThrowsOnNullTokenProvider()
    {
        Assert.Throws<ArgumentNullException>(
            () => new SigstoreSigner(new FakeFulcioClient(), new FakeRekorClient(), new FakeTsa(), null!));
    }

    private static SigstoreSigner CreateSigner() =>
        new(new FakeFulcioClient(), new FakeRekorClient(), new FakeTsa(), new FakeTokenProvider());

    private class FakeFulcioClient : IFulcioClient
    {
        public Task<CertificateResponse> GetSigningCertificateAsync(CertificateRequest request, CancellationToken ct = default)
            => throw new NotImplementedException();
    }

    private class FakeRekorClient : IRekorClient
    {
        public Task<TransparencyLogEntry> SubmitEntryAsync(RekorEntry entry, CancellationToken ct = default)
            => throw new NotImplementedException();
    }

    private class FakeTsa : ITimestampAuthority
    {
        public Task<TimestampResponse> GetTimestampAsync(ReadOnlyMemory<byte> signature, CancellationToken ct = default)
            => throw new NotImplementedException();
    }

    private class FakeTokenProvider : IOidcTokenProvider
    {
        public Task<OidcToken> GetTokenAsync(CancellationToken ct = default)
            => throw new NotImplementedException();
    }
}
