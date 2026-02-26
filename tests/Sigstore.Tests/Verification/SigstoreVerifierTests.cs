using Sigstore.Verification;
using Sigstore.Common;

namespace Sigstore.Tests.Verification;

public class SigstoreVerifierTests
{
    [Fact]
    public async Task VerifyAsync_ThrowsOnNullArtifact()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => verifier.VerifyAsync(null!, new SigstoreBundle(), new VerificationPolicy()));
    }

    [Fact]
    public async Task VerifyAsync_ThrowsOnNullBundle()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => verifier.VerifyAsync(Stream.Null, null!, new VerificationPolicy()));
    }

    [Fact]
    public async Task VerifyAsync_ThrowsOnNullPolicy()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => verifier.VerifyAsync(Stream.Null, new SigstoreBundle(), null!));
    }

    [Fact]
    public async Task TryVerifyAsync_ThrowsOnNullArtifact()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => verifier.TryVerifyAsync(null!, new SigstoreBundle(), new VerificationPolicy()));
    }

    [Fact]
    public async Task TryVerifyAsync_ThrowsOnNullBundle()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => verifier.TryVerifyAsync(Stream.Null, null!, new VerificationPolicy()));
    }

    [Fact]
    public async Task TryVerifyAsync_ThrowsOnNullPolicy()
    {
        var verifier = new SigstoreVerifier(new FakeTrustRootProvider());

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => verifier.TryVerifyAsync(Stream.Null, new SigstoreBundle(), null!));
    }

    [Fact]
    public void Constructor_ThrowsOnNullTrustRootProvider()
    {
        Assert.Throws<ArgumentNullException>(
            () => new SigstoreVerifier(null!));
    }

    private class FakeTrustRootProvider : ITrustRootProvider
    {
        public Task<Sigstore.TrustRoot.TrustedRoot> GetTrustRootAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(new Sigstore.TrustRoot.TrustedRoot());
    }
}
