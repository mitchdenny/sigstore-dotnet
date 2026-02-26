using Sigstore.Common;

namespace Sigstore.Tests.Crypto;

public class PublicKeyDetailsTests
{
    [Theory]
    [InlineData(PublicKeyDetails.PkixEcdsaP256Sha256, 5)]
    [InlineData(PublicKeyDetails.PkixEd25519, 7)]
    [InlineData(PublicKeyDetails.PkixRsaPkcs1v152048Sha256, 9)]
    [InlineData(PublicKeyDetails.PkixRsaPss2048Sha256, 16)]
    [InlineData(PublicKeyDetails.PkixEcdsaP384Sha384, 12)]
    [InlineData(PublicKeyDetails.PkixEcdsaP521Sha512, 13)]
    [InlineData(PublicKeyDetails.MlDsa65, 21)]
    [InlineData(PublicKeyDetails.MlDsa87, 22)]
    public void PublicKeyDetails_HasCorrectProtobufValues(PublicKeyDetails details, int expectedValue)
    {
        // These values must match the protobuf-specs enum values exactly
        // to ensure interoperability with other Sigstore clients.
        Assert.Equal(expectedValue, (int)details);
    }

    [Fact]
    public void PublicKeyDetails_Unspecified_IsZero()
    {
        Assert.Equal(0, (int)PublicKeyDetails.Unspecified);
    }
}
