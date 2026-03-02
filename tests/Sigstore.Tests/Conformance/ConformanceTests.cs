using Sigstore;

namespace Sigstore.Tests.Conformance;

public class ConformanceTests
{
    private static readonly string AssetsDir = GetTestAssetsDir();

    static string GetTestAssetsDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "Sigstore.slnx")))
            dir = dir.Parent;
        return Path.Combine(dir!.FullName, "tests", "sigstore-conformance", "test", "assets", "bundle-verify");
    }

    public static IEnumerable<object[]> TestCases()
    {
        if (!Directory.Exists(AssetsDir))
            yield break;

        foreach (var testDir in Directory.GetDirectories(AssetsDir).OrderBy(d => d))
        {
            var name = Path.GetFileName(testDir);
            yield return new object[] { name };
        }
    }

    [Theory]
    [MemberData(nameof(TestCases))]
    public async Task BundleVerify(string testCaseName)
    {
        var testDir = Path.Combine(AssetsDir, testCaseName);
        bool expectFailure = testCaseName.EndsWith("_fail");

        var bundlePath = Path.Combine(testDir, "bundle.sigstore.json");
        var bundleJson = await File.ReadAllTextAsync(bundlePath);

        // Deserialize bundle — for _fail cases, a deserialization error counts as expected failure
        SigstoreBundle bundle;
        try
        {
            bundle = SigstoreBundle.Deserialize(bundleJson);
        }
        catch when (expectFailure)
        {
            // Deserialization failure is a valid way to fail verification
            return;
        }

        // Determine artifact
        var artifactPath = Path.Combine(testDir, "artifact");
        if (!File.Exists(artifactPath))
            artifactPath = Path.Combine(AssetsDir, "a.txt");

        // Determine trust root provider
        var trustedRootPath = Path.Combine(testDir, "trusted_root.json");
        ITrustRootProvider trustRootProvider = File.Exists(trustedRootPath)
            ? new FileTrustRootProvider(new FileInfo(trustedRootPath))
            : new TufTrustRootProvider(TufTrustRootProvider.ProductionUrl);

        var verifier = new SigstoreVerifier(trustRootProvider);
        var policy = new VerificationPolicy();

        // Load public key for managed-key verification
        var keyPubPath = Path.Combine(testDir, "key.pub");
        if (File.Exists(keyPubPath))
        {
            var pem = await File.ReadAllTextAsync(keyPubPath);
            var base64 = pem
                .Replace("-----BEGIN PUBLIC KEY-----", "")
                .Replace("-----END PUBLIC KEY-----", "")
                .Replace("\n", "").Replace("\r", "").Trim();
            policy.PublicKey = Convert.FromBase64String(base64);
        }

        using var artifactStream = File.OpenRead(artifactPath);
        var (success, result) = await verifier.TryVerifyStreamAsync(artifactStream, bundle, policy);

        if (expectFailure)
        {
            Assert.False(success, $"Expected verification to fail for '{testCaseName}' but it succeeded");
        }
        else
        {
            Assert.True(success,
                $"Expected verification to succeed for '{testCaseName}' but it failed: {result?.FailureReason}");
        }
    }
}
