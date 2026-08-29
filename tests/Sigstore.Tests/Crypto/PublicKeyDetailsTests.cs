using Sigstore;

namespace Sigstore.Tests.Crypto;

[TestClass]
public class PublicKeyDetailsTests
{
    [TestMethod]
    [DataRow(PublicKeyDetails.PkixEcdsaP256Sha256, 5)]
    [DataRow(PublicKeyDetails.PkixEd25519, 7)]
    [DataRow(PublicKeyDetails.PkixRsaPkcs1v152048Sha256, 9)]
    [DataRow(PublicKeyDetails.PkixRsaPss2048Sha256, 16)]
    [DataRow(PublicKeyDetails.PkixEcdsaP384Sha384, 12)]
    [DataRow(PublicKeyDetails.PkixEcdsaP521Sha512, 13)]
    [DataRow(PublicKeyDetails.MlDsa65, 21)]
    [DataRow(PublicKeyDetails.MlDsa87, 22)]
    public void PublicKeyDetails_HasCorrectProtobufValues(PublicKeyDetails details, int expectedValue)
    {
        // These values must match the protobuf-specs enum values exactly
        // to ensure interoperability with other Sigstore clients.
        Assert.AreEqual(expectedValue, (int)details);
    }

    [TestMethod]
    public void PublicKeyDetails_Unspecified_IsZero()
    {
        Assert.AreEqual(0, (int)PublicKeyDetails.Unspecified);
    }
}
