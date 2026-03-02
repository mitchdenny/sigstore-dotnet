using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using Sigstore;

namespace Sigstore.Benchmarks;

/// <summary>
/// Benchmarks covering the top-level conformance test verification scenarios.
/// Each benchmark category mirrors the conformance test structure.
/// </summary>
[MemoryDiagnoser]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class BundleVerifyBenchmarks
{
    private static readonly string AssetsDir = GetAssetsDir();

    // Pre-loaded test data to avoid I/O in benchmarks
    private readonly Dictionary<string, (SigstoreBundle Bundle, byte[] Artifact, ITrustRootProvider TrustRoot, VerificationPolicy Policy)> _testData = new();

    static string GetAssetsDir()
    {
        // Try walking up from base directory first
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var candidate = Path.Combine(dir.FullName, "tests", "sigstore-conformance", "test", "assets", "bundle-verify");
            if (Directory.Exists(candidate))
                return candidate;
            dir = dir.Parent;
        }
        // Fallback: walk up from current directory
        dir = new DirectoryInfo(Directory.GetCurrentDirectory());
        while (dir != null)
        {
            var candidate = Path.Combine(dir.FullName, "tests", "sigstore-conformance", "test", "assets", "bundle-verify");
            if (Directory.Exists(candidate))
                return candidate;
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("Could not find conformance test assets directory");
    }

    private static readonly string DefaultArtifactPath = Path.Combine(AssetsDir, "a.txt");

    [GlobalSetup]
    public void Setup()
    {
        // Pre-load all test data to isolate benchmark from I/O
        var testCases = new[]
        {
            // Happy path
            "happy-path",
            "happy-path-v0.3",
            "happy-path-intoto-in-dsse-v3",

            // Failure cases (v1/hashedrekord)
            "bundle-empty-certificate-chain_fail",
            "bundle-from-wrong-instance_fail",
            "bundle-invalid-base64-signature_fail",
            "bundle-malformed-json_fail",
            "bundle-negative-log-index_fail",
            "bundle-unknown-version_fail",
            "bundle-with-root-cert_fail",
            "checkpoint-bad-keyhint_fail",
            "checkpoint-wrong-roothash_fail",
            "dsse-invalid-sig_fail",
            "dsse-mismatch-envelope_fail",
            "dsse-mismatch-sig_fail",
            "inclusion-proof-corrupted-hash_fail",
            "incorrect-public-key_fail",
            "integrated-time-in-future_fail",
            "invalid-checkpoint-signature_fail",
            "invalid-inclusion-proof_fail",
            "message-digest-mismatch_fail",
            "signature-mismatch_fail",
            "wrong-hashedrekord-artifact_fail",
            "wrong-hashedrekord-cert-and-sig_fail",
            "wrong-hashedrekord-entry_fail",
            "wrong-material_fail",

            // Rekor v2
            "rekor2-happy-path",
            "rekor2-dsse-happy-path",
            "rekor2-checkpoint-cosigned",
            "rekor2-checkpoint-multiple-cosigs",
            "rekor2-checkpoint-origin-not-first",
            "rekor2-checkpoint-two-sigs-cosigned",
            "rekor2-checkpoint-two-sigs-from-origin",
            "rekor2-timestamp-with-embedded-cert",
            "rekor2-timestamp-without-embedded-cert",
            "rekor2-timestamp-with-expired-cert-chain",
            "rekor2-checkpoint-missing-log-signature_fail",
            "rekor2-checkpoint-missing-origin_fail",
            "rekor2-checkpoint-missing-root-hash_fail",
            "rekor2-checkpoint-missing-size_fail",
            "rekor2-checkpoint-no-matching-signature_fail",
            "rekor2-dsse-invalid-sig_fail",
            "rekor2-dsse-mismatch-envelope_fail",
            "rekor2-dsse-mismatch-sig_fail",
            "rekor2-no-inclusion-proof_fail",
            "rekor2-no-timestamp_fail",
            "rekor2-timestamp-outside-trust-root-tsa-validity_fail",
            "rekor2-timestamp-outside-tsa-cert-validity_fail",
            "rekor2-timestamp-payload-mismatch_fail",
            "rekor2-timestamp-untrusted-tsa-with-embedded-cert_fail",
            "rekor2-timestamp-untrusted-tsa-without-embedded-cert_fail",
            "rekor2-timestamp-with-incorrect-time_fail",

            // In-toto/DSSE
            "intoto-with-custom-trust-root",
            "intoto-expired-certificate_fail",
            "intoto-log-entry-mismatch_fail",
            "intoto-missing-inclusion-proof_fail",
            "intoto-set-outside-signing-cert-validity_fail",
            "intoto-tsa-timestamp-outside-cert-validity_fail",

            // Managed keys
            "managed-key-happy-path",
            "managed-key-and-trusted-root",
            "managed-key-wrong-key_fail",

            // Other
            "bundle-with-sct-with-extensions",
            "invalid-ct-key_fail",
        };

        foreach (var testCase in testCases)
        {
            var testDir = Path.Combine(AssetsDir, testCase);
            if (!Directory.Exists(testDir))
                continue;

            var bundlePath = Path.Combine(testDir, "bundle.sigstore.json");
            var bundleJson = File.ReadAllText(bundlePath);

            SigstoreBundle? bundle;
            try
            {
                bundle = SigstoreBundle.Deserialize(bundleJson);
            }
            catch
            {
                // Store null for malformed bundles - we'll benchmark deserialization separately
                _testData[testCase] = default;
                continue;
            }

            var artifactPath = Path.Combine(testDir, "artifact");
            if (!File.Exists(artifactPath))
                artifactPath = DefaultArtifactPath;
            var artifact = File.ReadAllBytes(artifactPath);

            var trustedRootPath = Path.Combine(testDir, "trusted_root.json");
            ITrustRootProvider trustRootProvider = File.Exists(trustedRootPath)
                ? new FileTrustRootProvider(new FileInfo(trustedRootPath))
                : new TufTrustRootProvider(TufTrustRootProvider.ProductionUrl);

            var policy = new VerificationPolicy();

            var keyPubPath = Path.Combine(testDir, "key.pub");
            if (File.Exists(keyPubPath))
            {
                var pem = File.ReadAllText(keyPubPath);
                var base64 = pem
                    .Replace("-----BEGIN PUBLIC KEY-----", "")
                    .Replace("-----END PUBLIC KEY-----", "")
                    .Replace("\n", "").Replace("\r", "").Trim();
                policy.PublicKey = Convert.FromBase64String(base64);
            }

            _testData[testCase] = (bundle, artifact, trustRootProvider, policy);
        }
    }

    private async Task<(bool, VerificationResult?)> RunVerify(string testCase)
    {
        var (bundle, artifact, trustRoot, policy) = _testData[testCase];
        var verifier = new SigstoreVerifier(trustRoot);
        using var stream = new MemoryStream(artifact);
        return await verifier.TryVerifyStreamAsync(stream, bundle, policy);
    }

    // ========================================================================
    // Happy Path (should succeed)
    // ========================================================================

    [Benchmark(Description = "happy-path")]
    [BenchmarkCategory("HappyPath")]
    public Task HappyPath() => RunVerify("happy-path");

    [Benchmark(Description = "happy-path-v0.3")]
    [BenchmarkCategory("HappyPath")]
    public Task HappyPathV03() => RunVerify("happy-path-v0.3");

    [Benchmark(Description = "happy-path-intoto-in-dsse-v3")]
    [BenchmarkCategory("HappyPath")]
    public Task HappyPathIntotoDsseV3() => RunVerify("happy-path-intoto-in-dsse-v3");

    // ========================================================================
    // Failure Cases — v1/hashedrekord (should fail)
    // ========================================================================

    [Benchmark(Description = "bundle-empty-cert-chain")]
    [BenchmarkCategory("FailureCases")]
    public Task BundleEmptyCertChain() => RunVerify("bundle-empty-certificate-chain_fail");

    [Benchmark(Description = "bundle-from-wrong-instance")]
    [BenchmarkCategory("FailureCases")]
    public Task BundleFromWrongInstance() => RunVerify("bundle-from-wrong-instance_fail");

    [Benchmark(Description = "bundle-negative-log-index")]
    [BenchmarkCategory("FailureCases")]
    public Task BundleNegativeLogIndex() => RunVerify("bundle-negative-log-index_fail");

    [Benchmark(Description = "bundle-unknown-version")]
    [BenchmarkCategory("FailureCases")]
    public Task BundleUnknownVersion() => RunVerify("bundle-unknown-version_fail");

    [Benchmark(Description = "bundle-with-root-cert")]
    [BenchmarkCategory("FailureCases")]
    public Task BundleWithRootCert() => RunVerify("bundle-with-root-cert_fail");

    [Benchmark(Description = "checkpoint-bad-keyhint")]
    [BenchmarkCategory("FailureCases")]
    public Task CheckpointBadKeyhint() => RunVerify("checkpoint-bad-keyhint_fail");

    [Benchmark(Description = "checkpoint-wrong-roothash")]
    [BenchmarkCategory("FailureCases")]
    public Task CheckpointWrongRoothash() => RunVerify("checkpoint-wrong-roothash_fail");

    [Benchmark(Description = "dsse-invalid-sig")]
    [BenchmarkCategory("FailureCases")]
    public Task DsseInvalidSig() => RunVerify("dsse-invalid-sig_fail");

    [Benchmark(Description = "dsse-mismatch-envelope")]
    [BenchmarkCategory("FailureCases")]
    public Task DsseMismatchEnvelope() => RunVerify("dsse-mismatch-envelope_fail");

    [Benchmark(Description = "dsse-mismatch-sig")]
    [BenchmarkCategory("FailureCases")]
    public Task DsseMismatchSig() => RunVerify("dsse-mismatch-sig_fail");

    [Benchmark(Description = "inclusion-proof-corrupted-hash")]
    [BenchmarkCategory("FailureCases")]
    public Task InclusionProofCorruptedHash() => RunVerify("inclusion-proof-corrupted-hash_fail");

    [Benchmark(Description = "incorrect-public-key")]
    [BenchmarkCategory("FailureCases")]
    public Task IncorrectPublicKey() => RunVerify("incorrect-public-key_fail");

    [Benchmark(Description = "integrated-time-in-future")]
    [BenchmarkCategory("FailureCases")]
    public Task IntegratedTimeInFuture() => RunVerify("integrated-time-in-future_fail");

    [Benchmark(Description = "invalid-checkpoint-signature")]
    [BenchmarkCategory("FailureCases")]
    public Task InvalidCheckpointSignature() => RunVerify("invalid-checkpoint-signature_fail");

    [Benchmark(Description = "invalid-inclusion-proof")]
    [BenchmarkCategory("FailureCases")]
    public Task InvalidInclusionProof() => RunVerify("invalid-inclusion-proof_fail");

    [Benchmark(Description = "message-digest-mismatch")]
    [BenchmarkCategory("FailureCases")]
    public Task MessageDigestMismatch() => RunVerify("message-digest-mismatch_fail");

    [Benchmark(Description = "signature-mismatch")]
    [BenchmarkCategory("FailureCases")]
    public Task SignatureMismatch() => RunVerify("signature-mismatch_fail");

    [Benchmark(Description = "wrong-hashedrekord-artifact")]
    [BenchmarkCategory("FailureCases")]
    public Task WrongHashedrekordArtifact() => RunVerify("wrong-hashedrekord-artifact_fail");

    [Benchmark(Description = "wrong-hashedrekord-cert-and-sig")]
    [BenchmarkCategory("FailureCases")]
    public Task WrongHashedrekordCertAndSig() => RunVerify("wrong-hashedrekord-cert-and-sig_fail");

    [Benchmark(Description = "wrong-hashedrekord-entry")]
    [BenchmarkCategory("FailureCases")]
    public Task WrongHashedrekordEntry() => RunVerify("wrong-hashedrekord-entry_fail");

    [Benchmark(Description = "wrong-material")]
    [BenchmarkCategory("FailureCases")]
    public Task WrongMaterial() => RunVerify("wrong-material_fail");

    // ========================================================================
    // Rekor v2 (happy path + failure cases)
    // ========================================================================

    [Benchmark(Description = "rekor2-happy-path")]
    [BenchmarkCategory("RekorV2")]
    public Task Rekor2HappyPath() => RunVerify("rekor2-happy-path");

    [Benchmark(Description = "rekor2-dsse-happy-path")]
    [BenchmarkCategory("RekorV2")]
    public Task Rekor2DsseHappyPath() => RunVerify("rekor2-dsse-happy-path");

    [Benchmark(Description = "rekor2-checkpoint-cosigned")]
    [BenchmarkCategory("RekorV2")]
    public Task Rekor2CheckpointCosigned() => RunVerify("rekor2-checkpoint-cosigned");

    [Benchmark(Description = "rekor2-checkpoint-two-sigs-cosigned")]
    [BenchmarkCategory("RekorV2")]
    public Task Rekor2CheckpointTwoSigsCosigned() => RunVerify("rekor2-checkpoint-two-sigs-cosigned");

    [Benchmark(Description = "rekor2-timestamp-with-embedded-cert")]
    [BenchmarkCategory("RekorV2")]
    public Task Rekor2TimestampWithEmbeddedCert() => RunVerify("rekor2-timestamp-with-embedded-cert");

    [Benchmark(Description = "rekor2-timestamp-without-embedded-cert")]
    [BenchmarkCategory("RekorV2")]
    public Task Rekor2TimestampWithoutEmbeddedCert() => RunVerify("rekor2-timestamp-without-embedded-cert");

    [Benchmark(Description = "rekor2-checkpoint-missing-log-sig")]
    [BenchmarkCategory("RekorV2")]
    public Task Rekor2CheckpointMissingLogSig() => RunVerify("rekor2-checkpoint-missing-log-signature_fail");

    [Benchmark(Description = "rekor2-no-inclusion-proof")]
    [BenchmarkCategory("RekorV2")]
    public Task Rekor2NoInclusionProof() => RunVerify("rekor2-no-inclusion-proof_fail");

    [Benchmark(Description = "rekor2-no-timestamp")]
    [BenchmarkCategory("RekorV2")]
    public Task Rekor2NoTimestamp() => RunVerify("rekor2-no-timestamp_fail");

    [Benchmark(Description = "rekor2-timestamp-payload-mismatch")]
    [BenchmarkCategory("RekorV2")]
    public Task Rekor2TimestampPayloadMismatch() => RunVerify("rekor2-timestamp-payload-mismatch_fail");

    // ========================================================================
    // In-Toto / DSSE
    // ========================================================================

    [Benchmark(Description = "intoto-with-custom-trust-root")]
    [BenchmarkCategory("InTotoDSSE")]
    public Task IntotoWithCustomTrustRoot() => RunVerify("intoto-with-custom-trust-root");

    [Benchmark(Description = "intoto-expired-certificate")]
    [BenchmarkCategory("InTotoDSSE")]
    public Task IntotoExpiredCertificate() => RunVerify("intoto-expired-certificate_fail");

    [Benchmark(Description = "intoto-log-entry-mismatch")]
    [BenchmarkCategory("InTotoDSSE")]
    public Task IntotoLogEntryMismatch() => RunVerify("intoto-log-entry-mismatch_fail");

    [Benchmark(Description = "intoto-missing-inclusion-proof")]
    [BenchmarkCategory("InTotoDSSE")]
    public Task IntotoMissingInclusionProof() => RunVerify("intoto-missing-inclusion-proof_fail");

    [Benchmark(Description = "intoto-set-outside-signing-cert")]
    [BenchmarkCategory("InTotoDSSE")]
    public Task IntotoSetOutsideCertValidity() => RunVerify("intoto-set-outside-signing-cert-validity_fail");

    [Benchmark(Description = "intoto-tsa-timestamp-outside-cert")]
    [BenchmarkCategory("InTotoDSSE")]
    public Task IntotoTsaTimestampOutsideCert() => RunVerify("intoto-tsa-timestamp-outside-cert-validity_fail");

    // ========================================================================
    // Managed Keys
    // ========================================================================

    [Benchmark(Description = "managed-key-happy-path")]
    [BenchmarkCategory("ManagedKeys")]
    public Task ManagedKeyHappyPath() => RunVerify("managed-key-happy-path");

    [Benchmark(Description = "managed-key-and-trusted-root")]
    [BenchmarkCategory("ManagedKeys")]
    public Task ManagedKeyAndTrustedRoot() => RunVerify("managed-key-and-trusted-root");

    [Benchmark(Description = "managed-key-wrong-key")]
    [BenchmarkCategory("ManagedKeys")]
    public Task ManagedKeyWrongKey() => RunVerify("managed-key-wrong-key_fail");

    // ========================================================================
    // Other / Edge Cases
    // ========================================================================

    [Benchmark(Description = "bundle-with-sct-with-extensions")]
    [BenchmarkCategory("Other")]
    public Task BundleWithSctExtensions() => RunVerify("bundle-with-sct-with-extensions");

    [Benchmark(Description = "invalid-ct-key")]
    [BenchmarkCategory("Other")]
    public Task InvalidCtKey() => RunVerify("invalid-ct-key_fail");
}
