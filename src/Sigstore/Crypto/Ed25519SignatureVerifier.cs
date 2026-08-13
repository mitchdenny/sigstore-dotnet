using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace Sigstore;

internal static class Ed25519SignatureVerifier
{
    private static ReadOnlySpan<byte> SubjectPublicKeyInfoPrefix =>
        [0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00];

    public static bool Verify(
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> signature)
    {
        if (signature.Length != Ed25519PrivateKeyParameters.SignatureSize)
            return false;

        ReadOnlySpan<byte> rawKey;
        if (publicKey.Length == Ed25519PublicKeyParameters.KeySize)
        {
            rawKey = publicKey;
        }
        else if (publicKey.Length == SubjectPublicKeyInfoPrefix.Length + Ed25519PublicKeyParameters.KeySize &&
                 publicKey[..SubjectPublicKeyInfoPrefix.Length].SequenceEqual(SubjectPublicKeyInfoPrefix))
        {
            rawKey = publicKey[SubjectPublicKeyInfoPrefix.Length..];
        }
        else
        {
            return false;
        }

        try
        {
            var key = new Ed25519PublicKeyParameters(rawKey);
            return key.Verify(Ed25519.Algorithm.Ed25519, null, message, signature);
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
}
