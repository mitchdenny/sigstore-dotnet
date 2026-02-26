using System.Text.Json;
using Sigstore.TrustRoot;
using Sigstore.Common;

namespace Sigstore.Tests.TrustRoot;

public class TrustedRootTests
{
    [Fact]
    public void DefaultMediaType_IsV02()
    {
        var root = new TrustedRoot();

        Assert.Equal("application/vnd.dev.sigstore.trustedroot.v0.2+json", root.MediaType);
    }

    [Fact]
    public void NewTrustedRoot_HasEmptyCollections()
    {
        var root = new TrustedRoot();

        Assert.Empty(root.TransparencyLogs);
        Assert.Empty(root.CertificateAuthorities);
        Assert.Empty(root.CtLogs);
        Assert.Empty(root.TimestampAuthorities);
    }

    [Fact]
    public void TransparencyLogInfo_SetsProperties()
    {
        var logInfo = new TransparencyLogInfo
        {
            BaseUrl = "https://rekor.sigstore.dev",
            HashAlgorithm = HashAlgorithmType.Sha2_256,
            PublicKeyBytes = [1, 2, 3],
            LogId = [4, 5, 6],
            Operator = "sigstore.dev"
        };

        Assert.Equal("https://rekor.sigstore.dev", logInfo.BaseUrl);
        Assert.Equal(HashAlgorithmType.Sha2_256, logInfo.HashAlgorithm);
        Assert.Equal("sigstore.dev", logInfo.Operator);
    }

    [Fact]
    public void CertificateAuthorityInfo_SetsProperties()
    {
        var caInfo = new CertificateAuthorityInfo
        {
            Uri = "https://fulcio.sigstore.dev",
            CertChain = [[1, 2, 3]],
            Operator = "sigstore.dev",
            ValidFrom = DateTimeOffset.Parse("2022-01-01T00:00:00Z"),
            ValidTo = DateTimeOffset.Parse("2030-01-01T00:00:00Z")
        };

        Assert.Equal("https://fulcio.sigstore.dev", caInfo.Uri);
        Assert.Single(caInfo.CertChain);
        Assert.NotNull(caInfo.ValidFrom);
        Assert.NotNull(caInfo.ValidTo);
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

    [Fact]
    public void Deserialize_ParsesMediaType()
    {
        var root = Sigstore.TrustRoot.TrustedRoot.Deserialize(TrustedRootJson);

        Assert.Equal("application/vnd.dev.sigstore.trustedroot+json;version=0.1", root.MediaType);
    }

    [Fact]
    public void Deserialize_ParsesTransparencyLogs()
    {
        var root = Sigstore.TrustRoot.TrustedRoot.Deserialize(TrustedRootJson);

        Assert.Single(root.TransparencyLogs);
        var tlog = root.TransparencyLogs[0];
        Assert.Equal("https://rekor.sigstore.dev", tlog.BaseUrl);
        Assert.Equal(HashAlgorithmType.Sha2_256, tlog.HashAlgorithm);
        Assert.Equal(new byte[] { 1, 2, 3 }, tlog.PublicKeyBytes);
        Assert.Equal(PublicKeyDetails.PkixEcdsaP256Sha256, tlog.KeyDetails);
        Assert.Equal(new byte[] { 4, 5, 6 }, tlog.LogId);
        Assert.NotNull(tlog.ValidFrom);
        Assert.Null(tlog.ValidTo);
    }

    [Fact]
    public void Deserialize_ParsesCertificateAuthorities()
    {
        var root = Sigstore.TrustRoot.TrustedRoot.Deserialize(TrustedRootJson);

        Assert.Single(root.CertificateAuthorities);
        var ca = root.CertificateAuthorities[0];
        Assert.Equal("https://fulcio.sigstore.dev", ca.Uri);
        Assert.Single(ca.CertChain);
        Assert.Equal(new byte[] { 7, 8, 9 }, ca.CertChain[0]);
        Assert.NotNull(ca.ValidFrom);
        Assert.NotNull(ca.ValidTo);
    }

    [Fact]
    public void Deserialize_ParsesCtLogs()
    {
        var root = Sigstore.TrustRoot.TrustedRoot.Deserialize(TrustedRootJson);

        Assert.Single(root.CtLogs);
        Assert.Equal("https://ctfe.sigstore.dev/test", root.CtLogs[0].BaseUrl);
    }

    [Fact]
    public void Deserialize_EmptyTimestampAuthorities()
    {
        var root = Sigstore.TrustRoot.TrustedRoot.Deserialize(TrustedRootJson);

        Assert.Empty(root.TimestampAuthorities);
    }

    [Fact]
    public void Deserialize_InvalidJson_Throws()
    {
        Assert.Throws<JsonException>(() => Sigstore.TrustRoot.TrustedRoot.Deserialize("not json"));
    }

    [Fact]
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

        var root = Sigstore.TrustRoot.TrustedRoot.Deserialize(json);

        Assert.Empty(root.TransparencyLogs);
        Assert.Empty(root.CertificateAuthorities);
        Assert.Empty(root.CtLogs);
        Assert.Empty(root.TimestampAuthorities);
    }

    [Fact]
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

        var root = Sigstore.TrustRoot.TrustedRoot.Deserialize(json);

        Assert.Single(root.TimestampAuthorities);
        var tsa = root.TimestampAuthorities[0];
        Assert.Equal("https://timestamp.sigstore.dev", tsa.Uri);
        Assert.Single(tsa.CertChain);
        Assert.NotNull(tsa.ValidFrom);
        Assert.Null(tsa.ValidTo);
    }
}
