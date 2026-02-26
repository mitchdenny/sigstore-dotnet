using Tuf.Serialization;

namespace Tuf.Tests;

public class TufMetadataParserTests
{
    private static byte[] LoadFixture(string name)
    {
        var path = Path.Combine("Fixtures", name);
        return File.ReadAllBytes(path);
    }

    [Fact]
    public void ParseRoot_ValidSigstoreRoot_ReturnsRootMetadata()
    {
        var json = LoadFixture("root.json");
        var result = TufMetadataParser.ParseRoot(json);

        Assert.Equal("root", result.Signed.Type);
        Assert.Equal("1.0", result.Signed.SpecVersion);
        Assert.Equal(14, result.Signed.Version);
        Assert.True(result.Signed.ConsistentSnapshot);
        Assert.True(result.Signed.Expires > DateTimeOffset.UnixEpoch);

        // Should have 6 keys (5 root/targets signers + 1 online)
        Assert.Equal(6, result.Signed.Keys.Count);

        // Should have 4 roles
        Assert.Equal(4, result.Signed.Roles.Count);
        Assert.Contains("root", result.Signed.Roles.Keys);
        Assert.Contains("targets", result.Signed.Roles.Keys);
        Assert.Contains("snapshot", result.Signed.Roles.Keys);
        Assert.Contains("timestamp", result.Signed.Roles.Keys);

        // Root role should have threshold 3 with 5 keyids
        var rootRole = result.Signed.Roles["root"];
        Assert.Equal(3, rootRole.Threshold);
        Assert.Equal(5, rootRole.KeyIds.Count);

        // Timestamp/snapshot use online key with threshold 1
        Assert.Equal(1, result.Signed.Roles["timestamp"].Threshold);
        Assert.Equal(1, result.Signed.Roles["snapshot"].Threshold);

        // Should have 5 signatures (one per root key holder)
        Assert.Equal(5, result.Signatures.Count);
        Assert.All(result.Signatures, s => Assert.NotEmpty(s.KeyId));

        // SignedBytes should be non-empty (used for signature verification)
        Assert.NotEmpty(result.SignedBytes);
    }

    [Fact]
    public void ParseRoot_KeysHaveCorrectStructure()
    {
        var json = LoadFixture("root.json");
        var result = TufMetadataParser.ParseRoot(json);

        foreach (var (keyId, key) in result.Signed.Keys)
        {
            Assert.NotEmpty(keyId);
            Assert.NotEmpty(key.KeyType);
            Assert.NotEmpty(key.Scheme);
            Assert.NotEmpty(key.KeyVal);
            Assert.True(key.KeyVal.ContainsKey("public"), $"Key {keyId} missing 'public' keyval");
        }
    }

    [Fact]
    public void ParseTimestamp_ValidSigstoreTimestamp_ReturnsTimestampMetadata()
    {
        var json = LoadFixture("timestamp.json");
        var result = TufMetadataParser.ParseTimestamp(json);

        Assert.Equal("timestamp", result.Signed.Type);
        Assert.Equal("1.0", result.Signed.SpecVersion);
        Assert.True(result.Signed.Version > 0);
        Assert.True(result.Signed.Expires > DateTimeOffset.UnixEpoch);

        // Should reference snapshot.json
        Assert.True(result.Signed.SnapshotMeta.Version > 0);

        // Should have at least 1 signature
        Assert.NotEmpty(result.Signatures);
        Assert.NotEmpty(result.SignedBytes);
    }

    [Fact]
    public void ParseSnapshot_ValidSigstoreSnapshot_ReturnsSnapshotMetadata()
    {
        var json = LoadFixture("snapshot.json");
        var result = TufMetadataParser.ParseSnapshot(json);

        Assert.Equal("snapshot", result.Signed.Type);
        Assert.Equal("1.0", result.Signed.SpecVersion);
        Assert.True(result.Signed.Version > 0);
        Assert.True(result.Signed.Expires > DateTimeOffset.UnixEpoch);

        // Should have meta entries including targets.json
        Assert.NotEmpty(result.Signed.Meta);
        Assert.Contains("targets.json", result.Signed.Meta.Keys);

        var targetsMeta = result.Signed.Meta["targets.json"];
        Assert.True(targetsMeta.Version > 0);

        Assert.NotEmpty(result.Signatures);
        Assert.NotEmpty(result.SignedBytes);
    }

    [Fact]
    public void ParseTargets_ValidSigstoreTargets_ReturnsTargetsMetadata()
    {
        var json = LoadFixture("targets.json");
        var result = TufMetadataParser.ParseTargets(json);

        Assert.Equal("targets", result.Signed.Type);
        Assert.Equal("1.0", result.Signed.SpecVersion);
        Assert.True(result.Signed.Version > 0);
        Assert.True(result.Signed.Expires > DateTimeOffset.UnixEpoch);

        // Should have targets including trusted_root.json
        Assert.NotEmpty(result.Signed.Targets);
        Assert.Contains("trusted_root.json", result.Signed.Targets.Keys);

        var trustedRoot = result.Signed.Targets["trusted_root.json"];
        Assert.True(trustedRoot.Length > 0);
        Assert.NotEmpty(trustedRoot.Hashes);
        Assert.Contains("sha256", trustedRoot.Hashes.Keys);

        Assert.NotEmpty(result.Signatures);
        Assert.NotEmpty(result.SignedBytes);
    }

    [Fact]
    public void ParseTargets_HasDelegations()
    {
        var json = LoadFixture("targets.json");
        var result = TufMetadataParser.ParseTargets(json);

        // Sigstore targets metadata has delegations (to rekor, registry.npmjs.org, etc.)
        Assert.NotNull(result.Signed.Delegations);
        Assert.NotEmpty(result.Signed.Delegations.Keys);
        Assert.NotEmpty(result.Signed.Delegations.Roles);
    }

    [Fact]
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

        Assert.Throws<System.Text.Json.JsonException>(() => TufMetadataParser.ParseRoot(json));
    }

    [Fact]
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

        Assert.Throws<System.Text.Json.JsonException>(() => TufMetadataParser.ParseRoot(json));
    }

    [Fact]
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
        Assert.Equal(1, result.Signed.Version);
    }

    [Fact]
    public void DebugCanonicalJsonHash()
    {
        var json = LoadFixture("root.json");
        var result = TufMetadataParser.ParseRoot(json);
        var hash = System.Security.Cryptography.SHA256.HashData(result.SignedBytes);
        var hashHex = Convert.ToHexString(hash).ToLower();

        // Expected OLPC canonical JSON hash (securesystemslib format):
        Assert.Equal("ffffdfdd0d8747dcc3f8f73c6055d75f2bf36062664ccf98fdd6760ab578d85c", hashHex);
    }
}
