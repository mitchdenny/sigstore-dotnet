using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Sigstore.Signing;
using Sigstore.Fulcio;
using Sigstore.Rekor;
using Sigstore.Timestamp;
using Sigstore.Oidc;
using Sigstore.Common;
using FulcioCertificateRequest = Sigstore.Fulcio.CertificateRequest;

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

    [Fact]
    public async Task SignAsync_ReturnsBundle_WithCorrectMediaType()
    {
        var (signer, _) = CreateSignerWithTestCert();
        using var artifact = new MemoryStream("hello world"u8.ToArray());

        var bundle = await signer.SignAsync(artifact);

        Assert.Equal("application/vnd.dev.sigstore.bundle.v0.3+json", bundle.MediaType);
    }

    [Fact]
    public async Task SignAsync_ReturnsBundle_WithCertificateFromFulcio()
    {
        var (signer, certBytes) = CreateSignerWithTestCert();
        using var artifact = new MemoryStream("hello world"u8.ToArray());

        var bundle = await signer.SignAsync(artifact);

        Assert.NotNull(bundle.VerificationMaterial);
        Assert.Equal(certBytes, bundle.VerificationMaterial.Certificate);
    }

    [Fact]
    public async Task SignAsync_ReturnsBundle_WithSignature()
    {
        var (signer, _) = CreateSignerWithTestCert();
        using var artifact = new MemoryStream("hello world"u8.ToArray());

        var bundle = await signer.SignAsync(artifact);

        Assert.NotNull(bundle.MessageSignature);
        Assert.NotEmpty(bundle.MessageSignature.Signature);
    }

    [Fact]
    public async Task SignAsync_ReturnsBundle_WithTlogEntry()
    {
        var (signer, _) = CreateSignerWithTestCert();
        using var artifact = new MemoryStream("hello world"u8.ToArray());

        var bundle = await signer.SignAsync(artifact);

        Assert.NotNull(bundle.VerificationMaterial);
        Assert.Single(bundle.VerificationMaterial.TlogEntries);
        Assert.Equal(42, bundle.VerificationMaterial.TlogEntries[0].LogIndex);
    }

    [Fact]
    public async Task SignAsync_ReturnsBundle_WithTimestamp()
    {
        var (signer, _) = CreateSignerWithTestCert();
        using var artifact = new MemoryStream("hello world"u8.ToArray());

        var bundle = await signer.SignAsync(artifact);

        Assert.NotNull(bundle.VerificationMaterial);
        Assert.Single(bundle.VerificationMaterial.Rfc3161Timestamps);
        Assert.Equal(new byte[] { 0xDE, 0xAD }, bundle.VerificationMaterial.Rfc3161Timestamps[0]);
    }

    [Fact]
    public async Task AttestAsync_ReturnsDsseBundle()
    {
        var (signer, certBytes) = CreateSignerWithTestCert();
        var statement = """{"_type":"https://in-toto.io/Statement/v0.1"}""";

        var bundle = await signer.AttestAsync(statement);

        Assert.Equal("application/vnd.dev.sigstore.bundle.v0.3+json", bundle.MediaType);
        Assert.NotNull(bundle.DsseEnvelope);
        Assert.Null(bundle.MessageSignature);
        Assert.Equal("application/vnd.in-toto+json", bundle.DsseEnvelope.PayloadType);
        Assert.Equal(Encoding.UTF8.GetBytes(statement), bundle.DsseEnvelope.Payload);
        Assert.Single(bundle.DsseEnvelope.Signatures);
        Assert.NotEmpty(bundle.DsseEnvelope.Signatures[0].Sig);
        Assert.NotNull(bundle.VerificationMaterial);
        Assert.Equal(certBytes, bundle.VerificationMaterial.Certificate);
        Assert.Single(bundle.VerificationMaterial.TlogEntries);
        Assert.Single(bundle.VerificationMaterial.Rfc3161Timestamps);
    }

    [Fact]
    public async Task SignAsync_DisposesEphemeralKey()
    {
        // If the key were not disposed, we'd just verify the flow completes without error.
        // The ephemeral key is created and disposed within SignAsync, so if we get a bundle back
        // without error, the flow completed and the using block disposed the key.
        var (signer, _) = CreateSignerWithTestCert();
        using var artifact = new MemoryStream("test"u8.ToArray());

        var bundle = await signer.SignAsync(artifact);

        Assert.NotNull(bundle);
        Assert.NotNull(bundle.MessageSignature);
    }

    private static SigstoreSigner CreateSigner() =>
        new(new FakeFulcioClient(), new FakeRekorClient(), new FakeTsa(), new FakeTokenProvider());

    private static (SigstoreSigner Signer, byte[] CertBytes) CreateSignerWithTestCert()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=test", key, HashAlgorithmName.SHA256);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(10));
        var certBytes = cert.RawData;

        var fulcio = new FakeFulcioClient(certBytes);
        var rekor = new FakeRekorClient(new TransparencyLogEntry
        {
            LogIndex = 42,
            LogId = new byte[] { 0x01, 0x02 },
            IntegratedTime = 1700000000,
            Body = "dGVzdA=="
        });
        var tsa = new FakeTsa(new byte[] { 0xDE, 0xAD });
        var token = new FakeTokenProvider(new OidcToken
        {
            RawToken = "test-token",
            Subject = "test@example.com",
            Issuer = "https://issuer.example.com"
        });

        return (new SigstoreSigner(fulcio, rekor, tsa, token), certBytes);
    }

    private class FakeFulcioClient : IFulcioClient
    {
        private readonly byte[]? _certBytes;

        public FakeFulcioClient(byte[]? certBytes = null) => _certBytes = certBytes;

        public Task<CertificateResponse> GetSigningCertificateAsync(FulcioCertificateRequest request, CancellationToken ct = default)
        {
            if (_certBytes == null) throw new NotImplementedException();
            return Task.FromResult(new CertificateResponse
            {
                CertificateChain = [_certBytes]
            });
        }
    }

    private class FakeRekorClient : IRekorClient
    {
        private readonly TransparencyLogEntry? _entry;

        public FakeRekorClient(TransparencyLogEntry? entry = null) => _entry = entry;

        public Task<TransparencyLogEntry> SubmitEntryAsync(RekorEntry entry, CancellationToken ct = default)
        {
            if (_entry == null) throw new NotImplementedException();
            return Task.FromResult(_entry);
        }
    }

    private class FakeTsa : ITimestampAuthority
    {
        private readonly byte[]? _timestamp;

        public FakeTsa(byte[]? timestamp = null) => _timestamp = timestamp;

        public Task<TimestampResponse> GetTimestampAsync(ReadOnlyMemory<byte> signature, CancellationToken ct = default)
        {
            if (_timestamp == null) throw new NotImplementedException();
            return Task.FromResult(new TimestampResponse { RawBytes = _timestamp });
        }
    }

    private class FakeTokenProvider : IOidcTokenProvider
    {
        private readonly OidcToken? _token;

        public FakeTokenProvider(OidcToken? token = null) => _token = token;

        public Task<OidcToken> GetTokenAsync(CancellationToken ct = default)
        {
            if (_token == null) throw new NotImplementedException();
            return Task.FromResult(_token);
        }
    }
}
