using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using Sigstore;

namespace Sigstore.Benchmarks;

/// <summary>
/// Isolates individual verification phases to identify bottlenecks.
/// Compares full cert-chain verification vs managed-key (no cert chain) to
/// quantify the cost of X509Chain.Build().
/// </summary>
[MemoryDiagnoser]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class VerificationPhaseBenchmarks
{
    private static readonly string AssetsDir = GetAssetsDir();
    private string _happyPathBundleJson = null!;
    private SigstoreBundle _happyPathBundle = null!;
    private byte[] _artifact = null!;
    private ITrustRootProvider _trustRootProvider = null!;

    private SigstoreBundle _managedKeyBundle = null!;
    private VerificationPolicy _managedKeyPolicy = null!;

    static string GetAssetsDir()
    {
        foreach (var start in new[] { AppContext.BaseDirectory, Directory.GetCurrentDirectory() })
        {
            var dir = new DirectoryInfo(start);
            while (dir != null)
            {
                var candidate = Path.Combine(dir.FullName, "tests", "sigstore-conformance", "test", "assets", "bundle-verify");
                if (Directory.Exists(candidate)) return candidate;
                dir = dir.Parent;
            }
        }
        throw new DirectoryNotFoundException("Could not find conformance test assets directory");
    }

    [GlobalSetup]
    public void Setup()
    {
        // Happy path data
        var testDir = Path.Combine(AssetsDir, "happy-path");
        _happyPathBundleJson = File.ReadAllText(Path.Combine(testDir, "bundle.sigstore.json"));
        _happyPathBundle = SigstoreBundle.Deserialize(_happyPathBundleJson);
        _artifact = File.ReadAllBytes(Path.Combine(AssetsDir, "a.txt"));
        _trustRootProvider = new TufTrustRootProvider(TufTrustRootProvider.ProductionUrl);

        // Managed key data (pre-load to avoid I/O in benchmark)
        var mkDir = Path.Combine(AssetsDir, "managed-key-happy-path");
        _managedKeyBundle = SigstoreBundle.Deserialize(
            File.ReadAllText(Path.Combine(mkDir, "bundle.sigstore.json")));
        var pem = File.ReadAllText(Path.Combine(mkDir, "key.pub"));
        var base64 = pem.Replace("-----BEGIN PUBLIC KEY-----", "")
            .Replace("-----END PUBLIC KEY-----", "")
            .Replace("\n", "").Replace("\r", "").Trim();
        _managedKeyPolicy = new VerificationPolicy { PublicKey = Convert.FromBase64String(base64) };

        // Warm the TUF cache
        _trustRootProvider.GetTrustRootAsync(CancellationToken.None).GetAwaiter().GetResult();
    }

    [Benchmark(Description = "1. Bundle Deserialization")]
    [BenchmarkCategory("Phase")]
    public SigstoreBundle BundleDeserialization()
        => SigstoreBundle.Deserialize(_happyPathBundleJson);

    [Benchmark(Description = "2. Trust Root Load (cached TUF)")]
    [BenchmarkCategory("Phase")]
    public async Task<TrustedRoot> TrustRootLoad()
        => await _trustRootProvider.GetTrustRootAsync(CancellationToken.None);

    [Benchmark(Description = "3. Full Verification (happy-path)")]
    [BenchmarkCategory("Phase")]
    public async Task FullVerification()
    {
        var verifier = new SigstoreVerifier(_trustRootProvider);
        using var stream = new MemoryStream(_artifact);
        await verifier.TryVerifyStreamAsync(stream, _happyPathBundle, new VerificationPolicy());
    }

    [Benchmark(Description = "4. Managed Key Verify (no cert chain)")]
    [BenchmarkCategory("Phase")]
    public async Task ManagedKeyVerify()
    {
        var verifier = new SigstoreVerifier(_trustRootProvider);
        using var stream = new MemoryStream(_artifact);
        await verifier.TryVerifyStreamAsync(stream, _managedKeyBundle, _managedKeyPolicy);
    }
}
