using Sigstore;

namespace Sigstore.Tests.Rekor;

[TestClass]
public class RekorV2ParsingTests
{
    [TestMethod]
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

        Assert.AreEqual(42, entry.LogIndex);
        Assert.AreEqual("testlogid", System.Text.Encoding.UTF8.GetString(entry.LogId.Span));
        Assert.AreEqual("hashedrekord", entry.Kind);
        Assert.AreEqual("0.0.2", entry.KindVersion);
        Assert.AreEqual(1700000000, entry.IntegratedTime);
        Assert.IsNotNull(entry.InclusionPromise);
        Assert.AreEqual("signed", System.Text.Encoding.UTF8.GetString(entry.InclusionPromise.Value.Span));
        Assert.IsNotNull(entry.InclusionProof);
        Assert.AreEqual(42, entry.InclusionProof.LogIndex);
        Assert.AreEqual(100, entry.InclusionProof.TreeSize);
        Assert.AreEqual(2, entry.InclusionProof.Hashes.Count);
        Assert.Contains("rekor.sigstore.dev", entry.InclusionProof.Checkpoint!);
        Assert.AreEqual("body", System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(entry.Body!)));
    }

    [TestMethod]
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

        Assert.IsNull(entry.InclusionPromise);
        Assert.IsNotNull(entry.InclusionProof);
    }

    [TestMethod]
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

        Assert.AreEqual(99, entry.LogIndex);
        Assert.AreEqual(1700000000, entry.IntegratedTime);
    }

    [TestMethod]
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

        Assert.IsNull(entry.InclusionPromise);
        Assert.IsNull(entry.InclusionProof);
    }

    [TestMethod]
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

        Assert.IsTrue(entry.LogId.Length == 0);
    }

    [TestMethod]
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

        Assert.IsNull(entry.Kind);
        Assert.IsNull(entry.KindVersion);
    }

    [TestMethod]
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

        Assert.IsNotNull(entry.InclusionProof);
        Assert.IsNull(entry.InclusionProof.Checkpoint);
    }
}
