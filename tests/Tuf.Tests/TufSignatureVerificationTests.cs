using Tuf.Serialization;

namespace Tuf.Tests;

public class TufSignatureVerificationTests
{
    private static byte[] LoadFixture(string name)
    {
        var path = Path.Combine("Fixtures", name);
        return File.ReadAllBytes(path);
    }

    [Fact]
    public void VerifyThreshold_SigstoreRoot_ThresholdMet()
    {
        // Parse the real Sigstore root.json and verify its own signatures
        var json = LoadFixture("root.json");
        var root = TufMetadataParser.ParseRoot(json);

        // Root role has threshold 3, and we have 4 valid signatures (1 empty)
        var rootRole = root.Signed.Roles["root"];

        var result = TufMetadataVerifier.VerifyThreshold(
            root.Signatures,
            root.SignedBytes,
            rootRole,
            root.Signed.Keys);

        Assert.True(result, "Root metadata should pass threshold verification with real Sigstore signatures.");
    }

    [Fact]
    public void VerifyThreshold_SigstoreTimestamp_ThresholdMet()
    {
        // First parse root to get keys and roles
        var rootJson = LoadFixture("root.json");
        var root = TufMetadataParser.ParseRoot(rootJson);

        // Parse timestamp
        var tsJson = LoadFixture("timestamp.json");
        var timestamp = TufMetadataParser.ParseTimestamp(tsJson);

        var timestampRole = root.Signed.Roles["timestamp"];

        var result = TufMetadataVerifier.VerifyThreshold(
            timestamp.Signatures,
            timestamp.SignedBytes,
            timestampRole,
            root.Signed.Keys);

        Assert.True(result, "Timestamp should pass threshold verification.");
    }

    [Fact]
    public void VerifyThreshold_SigstoreSnapshot_ThresholdMet()
    {
        var rootJson = LoadFixture("root.json");
        var root = TufMetadataParser.ParseRoot(rootJson);

        var snapJson = LoadFixture("snapshot.json");
        var snapshot = TufMetadataParser.ParseSnapshot(snapJson);

        var snapshotRole = root.Signed.Roles["snapshot"];

        var result = TufMetadataVerifier.VerifyThreshold(
            snapshot.Signatures,
            snapshot.SignedBytes,
            snapshotRole,
            root.Signed.Keys);

        Assert.True(result, "Snapshot should pass threshold verification.");
    }

    [Fact]
    public void VerifyThreshold_SigstoreTargets_ThresholdMet()
    {
        var rootJson = LoadFixture("root.json");
        var root = TufMetadataParser.ParseRoot(rootJson);

        var targetsJson = LoadFixture("targets.json");
        var targets = TufMetadataParser.ParseTargets(targetsJson);

        var targetsRole = root.Signed.Roles["targets"];

        var result = TufMetadataVerifier.VerifyThreshold(
            targets.Signatures,
            targets.SignedBytes,
            targetsRole,
            root.Signed.Keys);

        Assert.True(result, "Targets should pass threshold verification.");
    }

    [Fact]
    public void VerifyThreshold_EmptySignatures_Fails()
    {
        var rootJson = LoadFixture("root.json");
        var root = TufMetadataParser.ParseRoot(rootJson);

        var rootRole = root.Signed.Roles["root"];

        var result = TufMetadataVerifier.VerifyThreshold(
            [],
            root.SignedBytes,
            rootRole,
            root.Signed.Keys);

        Assert.False(result, "Empty signatures should not meet threshold.");
    }

    [Fact]
    public void VerifyThreshold_TamperedData_Fails()
    {
        var rootJson = LoadFixture("root.json");
        var root = TufMetadataParser.ParseRoot(rootJson);

        var rootRole = root.Signed.Roles["root"];

        // Tamper with the signed bytes
        var tamperedBytes = (byte[])root.SignedBytes.Clone();
        tamperedBytes[10] ^= 0xFF;

        var result = TufMetadataVerifier.VerifyThreshold(
            root.Signatures,
            tamperedBytes,
            rootRole,
            root.Signed.Keys);

        Assert.False(result, "Tampered data should not pass verification.");
    }

    [Fact]
    public void VerifyThreshold_BelowThreshold_Fails()
    {
        var rootJson = LoadFixture("root.json");
        var root = TufMetadataParser.ParseRoot(rootJson);

        // Raise threshold to 10 (impossibly high)
        var strictRole = new Tuf.Metadata.TufRole
        {
            KeyIds = root.Signed.Roles["root"].KeyIds,
            Threshold = 10
        };

        var result = TufMetadataVerifier.VerifyThreshold(
            root.Signatures,
            root.SignedBytes,
            strictRole,
            root.Signed.Keys);

        Assert.False(result, "Should fail when threshold is impossibly high.");
    }

    [Fact]
    public void VerifyThreshold_ZeroThreshold_Fails()
    {
        var rootJson = LoadFixture("root.json");
        var root = TufMetadataParser.ParseRoot(rootJson);

        var zeroRole = new Tuf.Metadata.TufRole
        {
            KeyIds = root.Signed.Roles["root"].KeyIds,
            Threshold = 0
        };

        var result = TufMetadataVerifier.VerifyThreshold(
            root.Signatures,
            root.SignedBytes,
            zeroRole,
            root.Signed.Keys);

        Assert.False(result, "Zero threshold should always fail.");
    }

    [Fact]
    public void VerifyThreshold_CorruptedSignature_Fails()
    {
        var rootJson = LoadFixture("root.json");
        var root = TufMetadataParser.ParseRoot(rootJson);

        // Replace all signatures with corrupted values
        var corruptedSigs = root.Signatures.Select(s => new Tuf.Metadata.TufSignature
        {
            KeyId = s.KeyId,
            Sig = string.IsNullOrEmpty(s.Sig) ? "" : "deadbeef" + s.Sig[8..]
        }).ToList();

        var rootRole = root.Signed.Roles["root"];

        var result = TufMetadataVerifier.VerifyThreshold(
            corruptedSigs,
            root.SignedBytes,
            rootRole,
            root.Signed.Keys);

        Assert.False(result, "Corrupted signatures should not pass verification.");
    }

    [Fact]
    public void VerifyThreshold_UnauthorizedKeys_Fails()
    {
        var rootJson = LoadFixture("root.json");
        var root = TufMetadataParser.ParseRoot(rootJson);

        // Create a role with no authorized key IDs
        var noKeysRole = new Tuf.Metadata.TufRole
        {
            KeyIds = ["nonexistent-key-id"],
            Threshold = 1
        };

        var result = TufMetadataVerifier.VerifyThreshold(
            root.Signatures,
            root.SignedBytes,
            noKeysRole,
            root.Signed.Keys);

        Assert.False(result, "Signatures from unauthorized keys should not count.");
    }
}
