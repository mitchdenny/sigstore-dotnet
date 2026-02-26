using Sigstore.Common;
using Sigstore.TrustRoot;
using Sigstore.Verification;

namespace Sigstore.Tests.Conformance;

public class ConformanceTests
{
    private static readonly string AssetsDir = GetTestAssetsDir();

    static string GetTestAssetsDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "sigstore-dotnet.slnx")))
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
            // Key-based verification not yet implemented — skip test cases with key.pub
            if (File.Exists(Path.Combine(testDir, "key.pub")))
                continue;
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
            ? new FileTrustRootProvider(trustedRootPath)
            : new PublicGoodTrustRootProvider();

        var verifier = new SigstoreVerifier(trustRootProvider);
        var policy = new VerificationPolicy();

        using var artifactStream = File.OpenRead(artifactPath);
        var (success, result) = await verifier.TryVerifyAsync(artifactStream, bundle, policy);

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
