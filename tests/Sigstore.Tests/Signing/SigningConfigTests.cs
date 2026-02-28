using Sigstore.Signing;

namespace Sigstore.Tests.Signing;

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

    [Fact]
    public void Deserialize_ParsesAllServiceLists()
    {
        var config = SigningConfig.Deserialize(SampleConfig);

        Assert.Single(config.CaUrls);
        Assert.Equal(2, config.RekorTlogUrls.Count);
        Assert.Single(config.TsaUrls);
    }

    [Fact]
    public void Deserialize_ParsesUrls()
    {
        var config = SigningConfig.Deserialize(SampleConfig);

        Assert.Equal("https://fulcio.sigstage.dev", config.CaUrls[0].Url);
        Assert.Equal("https://rekor.sigstage.dev", config.RekorTlogUrls[0].Url);
        Assert.Equal("https://rekor-new.sigstage.dev", config.RekorTlogUrls[1].Url);
    }

    [Fact]
    public void Deserialize_ParsesApiVersions()
    {
        var config = SigningConfig.Deserialize(SampleConfig);

        Assert.Equal(2, config.CaUrls[0].MajorApiVersion);
        Assert.Equal(1, config.RekorTlogUrls[0].MajorApiVersion);
        Assert.Equal(2, config.RekorTlogUrls[1].MajorApiVersion);
    }

    [Fact]
    public void Deserialize_ParsesValidityPeriods()
    {
        var config = SigningConfig.Deserialize(SampleConfig);

        Assert.Equal(new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero), config.CaUrls[0].ValidFrom);
        Assert.Null(config.CaUrls[0].ValidTo);

        Assert.Equal(new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero), config.RekorTlogUrls[0].ValidTo);
    }

    [Fact]
    public void SelectBest_ReturnsHighestApiVersion()
    {
        var config = SigningConfig.Deserialize(SampleConfig);
        var best = SigningConfig.SelectBest(config.RekorTlogUrls);

        Assert.NotNull(best);
        Assert.Equal("https://rekor-new.sigstage.dev", best.Url);
        Assert.Equal(2, best.MajorApiVersion);
    }

    [Fact]
    public void SelectBest_FiltersExpiredEndpoints()
    {
        var endpoints = new List<ServiceEndpoint>
        {
            new()
            {
                Url = "https://old.example.com",
                MajorApiVersion = 2,
                ValidFrom = new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero),
                ValidTo = new DateTimeOffset(2021, 1, 1, 0, 0, 0, TimeSpan.Zero)
            },
            new()
            {
                Url = "https://current.example.com",
                MajorApiVersion = 1,
                ValidFrom = new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero),
                ValidTo = null
            }
        };

        var best = SigningConfig.SelectBest(endpoints);

        Assert.NotNull(best);
        Assert.Equal("https://current.example.com", best.Url);
    }

    [Fact]
    public void SelectBest_ReturnsNull_WhenNoValidEndpoints()
    {
        var endpoints = new List<ServiceEndpoint>
        {
            new()
            {
                Url = "https://expired.example.com",
                MajorApiVersion = 1,
                ValidFrom = new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero),
                ValidTo = new DateTimeOffset(2021, 1, 1, 0, 0, 0, TimeSpan.Zero)
            }
        };

        var best = SigningConfig.SelectBest(endpoints);
        Assert.Null(best);
    }

    [Fact]
    public void Deserialize_EmptyConfig()
    {
        var config = SigningConfig.Deserialize("{}");

        Assert.Empty(config.CaUrls);
        Assert.Empty(config.RekorTlogUrls);
        Assert.Empty(config.TsaUrls);
    }

    [Fact]
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
        Assert.Equal(1, config.CaUrls[0].MajorApiVersion);
    }
}
