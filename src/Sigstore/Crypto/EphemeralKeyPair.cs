using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Sigstore.Crypto;

/// <summary>
/// An ephemeral ECDSA P-256 keypair for Sigstore keyless signing.
/// The key is destroyed when disposed.
/// </summary>
internal sealed class EphemeralKeyPair : IDisposable
{
    private readonly ECDsa _key;

    public EphemeralKeyPair()
    {
        _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    }

    public ECDsa Key => _key;

    public byte[] Sign(byte[] data) => _key.SignData(data, HashAlgorithmName.SHA256);

    public string CreateCsr(string subject)
    {
        var req = new CertificateRequest($"CN={subject}", _key, HashAlgorithmName.SHA256);
        return req.CreateSigningRequestPem();
    }

    public void Dispose() => _key.Dispose();
}
