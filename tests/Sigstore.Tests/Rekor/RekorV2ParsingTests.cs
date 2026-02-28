using Sigstore.Rekor;

namespace Sigstore.Tests.Rekor;

public class RekorV2ParsingTests
{
    [Fact]
    public void ParseV2LogEntry_FullResponse()
    {
        var json = """
        {
          "logIndex": "42",
          "logId": {
            "keyId": "dGVzdGxvZ2lk"
          },
          "kindVersion": {
            "kind": "hashedrekord",
            "version": "0.0.2"
          },
          "integratedTime": "1700000000",
          "inclusionPromise": {
            "signedEntryTimestamp": "c2lnbmVk"
          },
          "inclusionProof": {
            "logIndex": "42",
            "rootHash": "cm9vdGhhc2g=",
            "treeSize": "100",
            "hashes": ["aGFzaDE=", "aGFzaDI="],
            "checkpoint": {
              "envelope": "rekor.sigstore.dev - 123\n42\nroothash\n\n— sig\n"
            }
          },
          "canonicalizedBody": "Ym9keQ=="
        }
        """;

        var entry = RekorHttpClient.ParseV2LogEntry(json);

        Assert.Equal(42, entry.LogIndex);
        Assert.Equal("testlogid", System.Text.Encoding.UTF8.GetString(entry.LogId));
        Assert.Equal("hashedrekord", entry.Kind);
        Assert.Equal("0.0.2", entry.KindVersion);
        Assert.Equal(1700000000, entry.IntegratedTime);
        Assert.NotNull(entry.InclusionPromise);
        Assert.Equal("signed", System.Text.Encoding.UTF8.GetString(entry.InclusionPromise));
        Assert.NotNull(entry.InclusionProof);
        Assert.Equal(42, entry.InclusionProof.LogIndex);
        Assert.Equal(100, entry.InclusionProof.TreeSize);
        Assert.Equal(2, entry.InclusionProof.Hashes.Count);
        Assert.Contains("rekor.sigstore.dev", entry.InclusionProof.Checkpoint);
        Assert.Equal("body", System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(entry.Body!)));
    }

    [Fact]
    public void ParseV2LogEntry_NullInclusionPromise()
    {
        var json = """
        {
          "logIndex": "1",
          "logId": { "keyId": "dGVzdA==" },
          "kindVersion": { "kind": "hashedrekord", "version": "0.0.2" },
          "integratedTime": "1700000000",
          "inclusionPromise": null,
          "inclusionProof": {
            "logIndex": "1",
            "rootHash": "cm9vdA==",
            "treeSize": "10",
            "hashes": [],
            "checkpoint": { "envelope": "checkpoint" }
          },
          "canonicalizedBody": "Ym9keQ=="
        }
        """;

        var entry = RekorHttpClient.ParseV2LogEntry(json);

        Assert.Null(entry.InclusionPromise);
        Assert.NotNull(entry.InclusionProof);
    }

    [Fact]
    public void ParseV2LogEntry_NumericValues()
    {
        // protobuf-JSON may encode int64 as number instead of string
        var json = """
        {
          "logIndex": 99,
          "logId": { "keyId": "dGVzdA==" },
          "kindVersion": { "kind": "hashedrekord", "version": "0.0.2" },
          "integratedTime": 1700000000,
          "canonicalizedBody": "Ym9keQ=="
        }
        """;

        var entry = RekorHttpClient.ParseV2LogEntry(json);

        Assert.Equal(99, entry.LogIndex);
        Assert.Equal(1700000000, entry.IntegratedTime);
    }

    [Fact]
    public void ParseV2LogEntry_MissingOptionalFields()
    {
        var json = """
        {
          "logIndex": "1",
          "logId": { "keyId": "dGVzdA==" },
          "kindVersion": { "kind": "hashedrekord", "version": "0.0.2" },
          "integratedTime": "1700000000",
          "canonicalizedBody": "Ym9keQ=="
        }
        """;

        var entry = RekorHttpClient.ParseV2LogEntry(json);

        Assert.Null(entry.InclusionPromise);
        Assert.Null(entry.InclusionProof);
    }

    [Fact]
    public void ParseV2LogEntry_NullLogId()
    {
        var json = """
        {
          "logIndex": "1",
          "logId": null,
          "kindVersion": { "kind": "hashedrekord", "version": "0.0.2" },
          "integratedTime": "1700000000",
          "canonicalizedBody": "Ym9keQ=="
        }
        """;

        var entry = RekorHttpClient.ParseV2LogEntry(json);

        Assert.Empty(entry.LogId);
    }

    [Fact]
    public void ParseV2LogEntry_NullKindVersion()
    {
        var json = """
        {
          "logIndex": "1",
          "logId": { "keyId": "dGVzdA==" },
          "kindVersion": null,
          "integratedTime": "1700000000",
          "canonicalizedBody": "Ym9keQ=="
        }
        """;

        var entry = RekorHttpClient.ParseV2LogEntry(json);

        Assert.Null(entry.Kind);
        Assert.Null(entry.KindVersion);
    }

    [Fact]
    public void ParseV2LogEntry_NullCheckpoint()
    {
        var json = """
        {
          "logIndex": "1",
          "logId": { "keyId": "dGVzdA==" },
          "kindVersion": { "kind": "hashedrekord", "version": "0.0.2" },
          "integratedTime": "1700000000",
          "inclusionProof": {
            "logIndex": "1",
            "rootHash": "cm9vdA==",
            "treeSize": "10",
            "hashes": [],
            "checkpoint": null
          },
          "canonicalizedBody": "Ym9keQ=="
        }
        """;

        var entry = RekorHttpClient.ParseV2LogEntry(json);

        Assert.NotNull(entry.InclusionProof);
        Assert.Null(entry.InclusionProof.Checkpoint);
    }
}
