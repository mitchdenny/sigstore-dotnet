using System.Text.Json;
using Sigstore;

namespace Sigstore.Tests.TrustRoot;

[TestClass]
public class TrustedRootTests
{
    [TestMethod]
    public void DefaultMediaType_IsV02()
    {
        var root = new TrustedRoot();

        Assert.AreEqual("application/vnd.dev.sigstore.trustedroot.v0.2+json", root.MediaType);
    }

    [TestMethod]
    public void NewTrustedRoot_HasEmptyCollections()
    {
        var root = new TrustedRoot();

        Assert.IsEmpty(root.TransparencyLogs);
        Assert.IsEmpty(root.CertificateAuthorities);
        Assert.IsEmpty(root.CtLogs);
        Assert.IsEmpty(root.TimestampAuthorities);
    }

    [TestMethod]
    public void TransparencyLogInfo_SetsProperties()
    {
        var logInfo = new TransparencyLogInfo
        {
            BaseUrl = new Uri("https://rekor.sigstore.dev"),
            HashAlgorithm = HashAlgorithmType.Sha256,
            PublicKeyBytes = new byte[] { 1, 2, 3 },
            LogId = new byte[] { 4, 5, 6 },
            Operator = "sigstore.dev"
        };

        Assert.AreEqual(new Uri("https://rekor.sigstore.dev"), logInfo.BaseUrl);
        Assert.AreEqual(HashAlgorithmType.Sha256, logInfo.HashAlgorithm);
        Assert.AreEqual("sigstore.dev", logInfo.Operator);
    }

    [TestMethod]
    public void CertificateAuthorityInfo_SetsProperties()
    {
        var caInfo = new CertificateAuthorityInfo
        {
            Uri = new Uri("https://fulcio.sigstore.dev"),
            CertificateChain = [new byte[] { 1, 2, 3 }],
            Operator = "sigstore.dev",
            ValidFrom = DateTimeOffset.Parse("2022-01-01T00:00:00Z"),
            ValidTo = DateTimeOffset.Parse("2030-01-01T00:00:00Z")
        };

        Assert.AreEqual(new Uri("https://fulcio.sigstore.dev"), caInfo.Uri);
        TestSeq.Single(caInfo.CertificateChain);
        Assert.IsNotNull(caInfo.ValidFrom);
        Assert.IsNotNull(caInfo.ValidTo);
    }

    // --- Deserialization tests ---

    private const string TrustedRootJson = """
        {
          "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
          "tlogs": [
            {
              "baseUrl": "https://rekor.sigstore.dev",
              "hashAlgorithm": "SHA2_256",
              "publicKey": {
                "rawBytes": "AQID",
                "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                "validFor": {
                  "start": "2021-01-12T11:53:27Z"
                }
              },
              "logId": {"keyId": "BAUG"}
            }
          ],
          "certificateAuthorities": [
            {
              "subject": {"organization": "sigstore.dev", "commonName": "sigstore"},
              "uri": "https://fulcio.sigstore.dev",
              "certChain": {
                "certificates": [{"rawBytes": "BwgJ"}]
              },
              "validFor": {
                "start": "2021-03-07T03:20:29Z",
                "end": "2022-12-31T23:59:59.999Z"
              }
            }
          ],
          "ctlogs": [
            {
              "baseUrl": "https://ctfe.sigstore.dev/test",
              "hashAlgorithm": "SHA2_256",
              "publicKey": {
                "rawBytes": "CgsM",
                "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                "validFor": {"start": "2021-03-14T00:00:00Z"}
              },
              "logId": {"keyId": "DQ4P"}
            }
          ],
          "timestampAuthorities": []
        }
        """;

    [TestMethod]
    public void Deserialize_ParsesMediaType()
    {
        var root = TrustedRoot.Deserialize(TrustedRootJson);

        Assert.AreEqual("application/vnd.dev.sigstore.trustedroot+json;version=0.1", root.MediaType);
    }

    [TestMethod]
    public void Deserialize_ParsesTransparencyLogs()
    {
        var root = TrustedRoot.Deserialize(TrustedRootJson);

        TestSeq.Single(root.TransparencyLogs);
        var tlog = root.TransparencyLogs[0];
        Assert.AreEqual(new Uri("https://rekor.sigstore.dev"), tlog.BaseUrl);
        Assert.AreEqual(HashAlgorithmType.Sha256, tlog.HashAlgorithm);
        TestSeq.AreEqual(new byte[] { 1, 2, 3 }, tlog.PublicKeyBytes.ToArray());
        Assert.AreEqual(PublicKeyDetails.PkixEcdsaP256Sha256, tlog.KeyDetails);
        TestSeq.AreEqual(new byte[] { 4, 5, 6 }, tlog.LogId.ToArray());
        Assert.IsNotNull(tlog.ValidFrom);
        Assert.IsNull(tlog.ValidTo);
    }

    [TestMethod]
    public void Deserialize_ParsesCertificateAuthorities()
    {
        var root = TrustedRoot.Deserialize(TrustedRootJson);

        TestSeq.Single(root.CertificateAuthorities);
        var ca = root.CertificateAuthorities[0];
        Assert.AreEqual(new Uri("https://fulcio.sigstore.dev"), ca.Uri);
        TestSeq.Single(ca.CertificateChain);
        TestSeq.AreEqual(new byte[] { 7, 8, 9 }, ca.CertificateChain[0].ToArray());
        Assert.IsNotNull(ca.ValidFrom);
        Assert.IsNotNull(ca.ValidTo);
    }

    [TestMethod]
    public void Deserialize_ParsesCtLogs()
    {
        var root = TrustedRoot.Deserialize(TrustedRootJson);

        TestSeq.Single(root.CtLogs);
        Assert.AreEqual(new Uri("https://ctfe.sigstore.dev/test"), root.CtLogs[0].BaseUrl);
    }

    [TestMethod]
    public void Deserialize_EmptyTimestampAuthorities()
    {
        var root = TrustedRoot.Deserialize(TrustedRootJson);

        Assert.IsEmpty(root.TimestampAuthorities);
    }

    [TestMethod]
    public void Deserialize_InvalidJson_Throws()
    {
        Assert.ThrowsExactly<JsonException>(() => TrustedRoot.Deserialize("not json"));
    }

    [TestMethod]
    public void Deserialize_MinimalTrustedRoot_HandlesGracefully()
    {
        var json = """
            {
              "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
              "tlogs": [],
              "certificateAuthorities": [],
              "ctlogs": [],
              "timestampAuthorities": []
            }
            """;

        var root = TrustedRoot.Deserialize(json);

        Assert.IsEmpty(root.TransparencyLogs);
        Assert.IsEmpty(root.CertificateAuthorities);
        Assert.IsEmpty(root.CtLogs);
        Assert.IsEmpty(root.TimestampAuthorities);
    }

    [TestMethod]
    public void Deserialize_TimestampAuthorities_ParsesCorrectly()
    {
        var json = """
            {
              "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
              "tlogs": [],
              "certificateAuthorities": [],
              "ctlogs": [],
              "timestampAuthorities": [
                {
                  "uri": "https://timestamp.sigstore.dev",
                  "certChain": {
                    "certificates": [{"rawBytes": "AQID"}]
                  },
                  "validFor": {
                    "start": "2023-01-01T00:00:00Z"
                  }
                }
              ]
            }
            """;

        var root = TrustedRoot.Deserialize(json);

        TestSeq.Single(root.TimestampAuthorities);
        var tsa = root.TimestampAuthorities[0];
        Assert.AreEqual(new Uri("https://timestamp.sigstore.dev"), tsa.Uri);
        TestSeq.Single(tsa.CertificateChain);
        Assert.IsNotNull(tsa.ValidFrom);
        Assert.IsNull(tsa.ValidTo);
    }
}
