using Sigstore;

namespace Sigstore.Tests.Signing;

[TestClass]
public class SigningConfigTests
{
    private const string SampleConfig = """
    {
      "mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
      "caUrls": [
        {
          "url": "https://fulcio.sigstage.dev",
          "majorApiVersion": 2,
          "validFor": {
            "start": "2020-01-01T00:00:00Z"
          }
        }
      ],
      "rekorTlogUrls": [
        {
          "url": "https://rekor.sigstage.dev",
          "majorApiVersion": 1,
          "validFor": {
            "start": "2020-01-01T00:00:00Z",
            "end": "2024-01-01T00:00:00Z"
          }
        },
        {
          "url": "https://rekor-new.sigstage.dev",
          "majorApiVersion": 2,
          "validFor": {
            "start": "2024-01-01T00:00:00Z"
          }
        }
      ],
      "tsaUrls": [
        {
          "url": "https://timestamp.sigstage.dev",
          "majorApiVersion": 1,
          "validFor": {
            "start": "2020-01-01T00:00:00Z"
          }
        }
      ]
    }
    """;

    [TestMethod]
    public void Deserialize_ParsesAllServiceLists()
    {
        var config = SigningConfig.Deserialize(SampleConfig);

        TestSeq.Single(config.CaUrls);
        Assert.AreEqual(2, config.RekorTlogUrls.Count);
        TestSeq.Single(config.TsaUrls);
    }

    [TestMethod]
    public void Deserialize_ParsesUrls()
    {
        var config = SigningConfig.Deserialize(SampleConfig);

        Assert.AreEqual(new Uri("https://fulcio.sigstage.dev"), config.CaUrls[0].Url);
        Assert.AreEqual(new Uri("https://rekor.sigstage.dev"), config.RekorTlogUrls[0].Url);
        Assert.AreEqual(new Uri("https://rekor-new.sigstage.dev"), config.RekorTlogUrls[1].Url);
    }

    [TestMethod]
    public void Deserialize_ParsesApiVersions()
    {
        var config = SigningConfig.Deserialize(SampleConfig);

        Assert.AreEqual(2, config.CaUrls[0].MajorApiVersion);
        Assert.AreEqual(1, config.RekorTlogUrls[0].MajorApiVersion);
        Assert.AreEqual(2, config.RekorTlogUrls[1].MajorApiVersion);
    }

    [TestMethod]
    public void Deserialize_ParsesValidityPeriods()
    {
        var config = SigningConfig.Deserialize(SampleConfig);

        Assert.AreEqual(new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero), config.CaUrls[0].ValidFrom);
        Assert.IsNull(config.CaUrls[0].ValidTo);

        Assert.AreEqual(new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero), config.RekorTlogUrls[0].ValidTo);
    }

    [TestMethod]
    public void SelectBest_ReturnsHighestApiVersion()
    {
        var config = SigningConfig.Deserialize(SampleConfig);
        var best = SigningConfig.SelectBest(config.RekorTlogUrls);

        Assert.IsNotNull(best);
        Assert.AreEqual(new Uri("https://rekor-new.sigstage.dev"), best.Url);
        Assert.AreEqual(2, best.MajorApiVersion);
    }

    [TestMethod]
    public void SelectBest_FiltersExpiredEndpoints()
    {
        var endpoints = new List<SigningServiceEndpoint>
        {
            new()
            {
                Url = new Uri("https://old.example.com"),
                MajorApiVersion = 2,
                ValidFrom = new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero),
                ValidTo = new DateTimeOffset(2021, 1, 1, 0, 0, 0, TimeSpan.Zero)
            },
            new()
            {
                Url = new Uri("https://current.example.com"),
                MajorApiVersion = 1,
                ValidFrom = new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero),
                ValidTo = null
            }
        };

        var best = SigningConfig.SelectBest(endpoints);

        Assert.IsNotNull(best);
        Assert.AreEqual(new Uri("https://current.example.com"), best.Url);
    }

    [TestMethod]
    public void SelectBest_ReturnsNull_WhenNoValidEndpoints()
    {
        var endpoints = new List<SigningServiceEndpoint>
        {
            new()
            {
                Url = new Uri("https://expired.example.com"),
                MajorApiVersion = 1,
                ValidFrom = new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero),
                ValidTo = new DateTimeOffset(2021, 1, 1, 0, 0, 0, TimeSpan.Zero)
            }
        };

        var best = SigningConfig.SelectBest(endpoints);
        Assert.IsNull(best);
    }

    [TestMethod]
    public void Deserialize_EmptyConfig()
    {
        var config = SigningConfig.Deserialize("{}");

        Assert.IsEmpty(config.CaUrls);
        Assert.IsEmpty(config.RekorTlogUrls);
        Assert.IsEmpty(config.TsaUrls);
    }

    [TestMethod]
    public void Deserialize_DefaultApiVersion_Is1()
    {
        var json = """
        {
          "caUrls": [
            {
              "url": "https://fulcio.example.com",
              "validFor": { "start": "2020-01-01T00:00:00Z" }
            }
          ]
        }
        """;

        var config = SigningConfig.Deserialize(json);
        Assert.AreEqual(1, config.CaUrls[0].MajorApiVersion);
    }
}
