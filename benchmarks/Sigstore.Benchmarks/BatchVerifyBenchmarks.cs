using BenchmarkDotNet.Attributes;
using Sigstore;

namespace Sigstore.Benchmarks;

/// <summary>
/// Benchmarks batch verification scenarios (multiple bundles verified with the
/// same SigstoreVerifier instance) to measure the benefit of trust store caching.
/// This mirrors the CPython release bundle test which verifies 100+ bundles.
/// </summary>
[MemoryDiagnoser]
public class BatchVerifyBenchmarks
{
    private static readonly string AssetsDir = GetAssetsDir();
    private SigstoreBundle _bundle = null!;
    private byte[] _artifact = null!;
    private ITrustRootProvider _trustRootProvider = null!;

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
        _bundle = SigstoreBundle.Deserialize(
            File.ReadAllText(Path.Combine(AssetsDir, "happy-path", "bundle.sigstore.json")));
        _artifact = File.ReadAllBytes(Path.Combine(AssetsDir, "a.txt"));
        _trustRootProvider = new TufTrustRootProvider(TufTrustRootProvider.ProductionUrl);
        _trustRootProvider.GetTrustRootAsync(CancellationToken.None).GetAwaiter().GetResult();
    }

    [Benchmark(Description = "Verify 100 bundles (same verifier instance)")]
    public async Task Batch100Verifications()
    {
        var verifier = new SigstoreVerifier(_trustRootProvider);
        var policy = new VerificationPolicy();

        for (int i = 0; i < 100; i++)
        {
            using var stream = new MemoryStream(_artifact);
            await verifier.TryVerifyStreamAsync(stream, _bundle, policy);
        }
    }

    [Benchmark(Description = "Verify 100 bundles (new verifier each time)")]
    public async Task Batch100VerificationsNewVerifier()
    {
        var policy = new VerificationPolicy();

        for (int i = 0; i < 100; i++)
        {
            var verifier = new SigstoreVerifier(_trustRootProvider);
            using var stream = new MemoryStream(_artifact);
            await verifier.TryVerifyStreamAsync(stream, _bundle, policy);
        }
    }
}
