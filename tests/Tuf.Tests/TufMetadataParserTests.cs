using Tuf.Serialization;

namespace Tuf.Tests;

[TestClass]
public class TufMetadataParserTests
{
    private static byte[] LoadFixture(string name)
    {
        var path = Path.Combine("Fixtures", name);
        return File.ReadAllBytes(path);
    }

    [TestMethod]
    public void ParseRoot_ValidSigstoreRoot_ReturnsRootMetadata()
    {
        var json = LoadFixture("root.json");
        var result = TufMetadataParser.ParseRoot(json);

        Assert.AreEqual("root", result.Signed.Type);
        Assert.AreEqual("1.0", result.Signed.SpecVersion);
        Assert.IsTrue(result.Signed.Version > 0);
        Assert.IsTrue(result.Signed.ConsistentSnapshot);
        Assert.IsTrue(result.Signed.Expires > DateTimeOffset.UnixEpoch);

        Assert.IsNotEmpty(result.Signed.Keys);

        // Should have 4 roles
        Assert.AreEqual(4, result.Signed.Roles.Count);
        Assert.Contains("root", result.Signed.Roles.Keys);
        Assert.Contains("targets", result.Signed.Roles.Keys);
        Assert.Contains("snapshot", result.Signed.Roles.Keys);
        Assert.Contains("timestamp", result.Signed.Roles.Keys);

        var rootRole = result.Signed.Roles["root"];
        Assert.IsTrue(rootRole.Threshold > 0);
        Assert.IsTrue(rootRole.KeyIds.Count >= rootRole.Threshold);

        // Timestamp/snapshot use online key with threshold 1
        Assert.AreEqual(1, result.Signed.Roles["timestamp"].Threshold);
        Assert.AreEqual(1, result.Signed.Roles["snapshot"].Threshold);

        Assert.IsTrue(result.Signatures.Count >= rootRole.Threshold);
        TestSeq.All(result.Signatures, s => Assert.IsNotEmpty(s.KeyId));

        // SignedBytes should be non-empty (used for signature verification)
        Assert.IsNotEmpty(result.SignedBytes);
    }

    [TestMethod]
    public void ParseRoot_KeysHaveCorrectStructure()
    {
        var json = LoadFixture("root.json");
        var result = TufMetadataParser.ParseRoot(json);

        foreach (var (keyId, key) in result.Signed.Keys)
        {
            Assert.IsNotEmpty(keyId);
            Assert.IsNotEmpty(key.KeyType);
            Assert.IsNotEmpty(key.Scheme);
            Assert.IsNotEmpty(key.KeyVal);
            Assert.IsTrue(key.KeyVal.ContainsKey("public"), $"Key {keyId} missing 'public' keyval");
        }
    }

    [TestMethod]
    public void ParseTimestamp_ValidSigstoreTimestamp_ReturnsTimestampMetadata()
    {
        var json = LoadFixture("timestamp.json");
        var result = TufMetadataParser.ParseTimestamp(json);

        Assert.AreEqual("timestamp", result.Signed.Type);
        Assert.AreEqual("1.0", result.Signed.SpecVersion);
        Assert.IsTrue(result.Signed.Version > 0);
        Assert.IsTrue(result.Signed.Expires > DateTimeOffset.UnixEpoch);

        // Should reference snapshot.json
        Assert.IsTrue(result.Signed.SnapshotMeta.Version > 0);

        // Should have at least 1 signature
        Assert.IsNotEmpty(result.Signatures);
        Assert.IsNotEmpty(result.SignedBytes);
    }

    [TestMethod]
    public void ParseSnapshot_ValidSigstoreSnapshot_ReturnsSnapshotMetadata()
    {
        var json = LoadFixture("snapshot.json");
        var result = TufMetadataParser.ParseSnapshot(json);

        Assert.AreEqual("snapshot", result.Signed.Type);
        Assert.AreEqual("1.0", result.Signed.SpecVersion);
        Assert.IsTrue(result.Signed.Version > 0);
        Assert.IsTrue(result.Signed.Expires > DateTimeOffset.UnixEpoch);

        // Should have meta entries including targets.json
        Assert.IsNotEmpty(result.Signed.Meta);
        Assert.Contains("targets.json", result.Signed.Meta.Keys);

        var targetsMeta = result.Signed.Meta["targets.json"];
        Assert.IsTrue(targetsMeta.Version > 0);

        Assert.IsNotEmpty(result.Signatures);
        Assert.IsNotEmpty(result.SignedBytes);
    }

    [TestMethod]
    public void ParseTargets_ValidSigstoreTargets_ReturnsTargetsMetadata()
    {
        var json = LoadFixture("targets.json");
        var result = TufMetadataParser.ParseTargets(json);

        Assert.AreEqual("targets", result.Signed.Type);
        Assert.AreEqual("1.0", result.Signed.SpecVersion);
        Assert.IsTrue(result.Signed.Version > 0);
        Assert.IsTrue(result.Signed.Expires > DateTimeOffset.UnixEpoch);

        // Should have targets including trusted_root.json
        Assert.IsNotEmpty(result.Signed.Targets);
        Assert.Contains("trusted_root.json", result.Signed.Targets.Keys);

        var trustedRoot = result.Signed.Targets["trusted_root.json"];
        Assert.IsTrue(trustedRoot.Length > 0);
        Assert.IsNotEmpty(trustedRoot.Hashes);
        Assert.Contains("sha256", trustedRoot.Hashes.Keys);

        Assert.IsNotEmpty(result.Signatures);
        Assert.IsNotEmpty(result.SignedBytes);
    }

    [TestMethod]
    public void ParseTargets_HasDelegations()
    {
        var json = LoadFixture("targets.json");
        var result = TufMetadataParser.ParseTargets(json);

        // Sigstore targets metadata has delegations (to rekor, registry.npmjs.org, etc.)
        Assert.IsNotNull(result.Signed.Delegations);
        Assert.IsNotEmpty(result.Signed.Delegations.Keys);
        Assert.IsNotEmpty(result.Signed.Delegations.Roles);
    }

    [TestMethod]
    public void ParseRoot_WrongType_ThrowsJsonException()
    {
        // Create a fake "root" that has _type: "timestamp"
        var json = """
        {
            "signatures": [],
            "signed": {
                "_type": "timestamp",
                "spec_version": "1.0",
                "version": 1,
                "expires": "2030-01-01T00:00:00Z",
                "meta": {}
            }
        }
        """u8.ToArray();

        Assert.ThrowsExactly<System.Text.Json.JsonException>(() => TufMetadataParser.ParseRoot(json));
    }

    [TestMethod]
    public void ParseRoot_MissingExpires_ThrowsJsonException()
    {
        var json = """
        {
            "signatures": [],
            "signed": {
                "_type": "root",
                "spec_version": "1.0",
                "version": 1,
                "consistent_snapshot": false,
                "keys": {},
                "roles": {}
            }
        }
        """u8.ToArray();

        Assert.ThrowsExactly<System.Text.Json.JsonException>(() => TufMetadataParser.ParseRoot(json));
    }

    [TestMethod]
    public void ParseRoot_MissingVersion_ThrowsJsonException()
    {
        var json = """
        {
            "signatures": [],
            "signed": {
                "_type": "root",
                "spec_version": "1.0",
                "expires": "2030-01-01T00:00:00Z",
                "consistent_snapshot": false,
                "keys": {},
                "roles": {}
            }
        }
        """u8.ToArray();

        Assert.ThrowsExactly<System.Text.Json.JsonException>(() => TufMetadataParser.ParseRoot(json));
    }

    [TestMethod]
    public void ParseRoot_UnrecognizedFields_AreIgnored()
    {
        var json = """
        {
            "signatures": [],
            "signed": {
                "_type": "root",
                "spec_version": "1.0",
                "version": 1,
                "expires": "2030-01-01T00:00:00Z",
                "consistent_snapshot": false,
                "keys": {},
                "roles": {},
                "x-custom-field": "should be ignored",
                "x-tuf-on-ci-expiry-period": 197
            }
        }
        """u8.ToArray();

        var result = TufMetadataParser.ParseRoot(json);
        Assert.AreEqual(1, result.Signed.Version);
    }

    [TestMethod]
    public void ParseRoot_DeprecatedKeyIdHashAlgorithms_IsIgnored()
    {
        var json = """
        {
            "signatures": [],
            "signed": {
                "_type": "root",
                "spec_version": "1.0",
                "version": 1,
                "expires": "2030-01-01T00:00:00Z",
                "consistent_snapshot": false,
                "keys": {
                    "keyid": {
                        "keytype": "ed25519",
                        "scheme": "ed25519",
                        "keyval": {
                            "public": "test"
                        },
                        "keyid_hash_algorithms": "md5"
                    }
                },
                "roles": {
                    "root": {
                        "keyids": ["keyid"],
                        "threshold": 1
                    }
                }
            }
        }
        """u8.ToArray();

        var result = TufMetadataParser.ParseRoot(json);

        TestSeq.Single(result.Signed.Keys);
        Assert.AreEqual("ed25519", result.Signed.Keys["keyid"].KeyType);
    }

}
