using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using Sigstore;

namespace Sigstore.Benchmarks;

/// <summary>
/// Benchmarks for bundle deserialization — isolates JSON parsing from verification.
/// </summary>
[MemoryDiagnoser]
public class BundleDeserializeBenchmarks
{
    private static readonly string AssetsDir = GetAssetsDir();
    private readonly Dictionary<string, string> _bundleJsons = new();

    static string GetAssetsDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var candidate = Path.Combine(dir.FullName, "tests", "sigstore-conformance", "test", "assets", "bundle-verify");
            if (Directory.Exists(candidate))
                return candidate;
            dir = dir.Parent;
        }
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

    [GlobalSetup]
    public void Setup()
    {
        foreach (var name in new[] { "happy-path", "happy-path-v0.3", "happy-path-intoto-in-dsse-v3",
            "rekor2-happy-path", "rekor2-dsse-happy-path", "managed-key-happy-path",
            "rekor2-timestamp-with-embedded-cert" })
        {
            var path = Path.Combine(AssetsDir, name, "bundle.sigstore.json");
            if (File.Exists(path))
                _bundleJsons[name] = File.ReadAllText(path);
        }
    }

    [Benchmark(Description = "v1 hashedrekord bundle")]
    public SigstoreBundle DeserializeV1() => SigstoreBundle.Deserialize(_bundleJsons["happy-path"]);

    [Benchmark(Description = "v0.3 bundle")]
    public SigstoreBundle DeserializeV03() => SigstoreBundle.Deserialize(_bundleJsons["happy-path-v0.3"]);

    [Benchmark(Description = "v3 intoto DSSE bundle")]
    public SigstoreBundle DeserializeIntotoDsse() => SigstoreBundle.Deserialize(_bundleJsons["happy-path-intoto-in-dsse-v3"]);

    [Benchmark(Description = "rekor2 bundle")]
    public SigstoreBundle DeserializeRekor2() => SigstoreBundle.Deserialize(_bundleJsons["rekor2-happy-path"]);

    [Benchmark(Description = "rekor2 DSSE bundle")]
    public SigstoreBundle DeserializeRekor2Dsse() => SigstoreBundle.Deserialize(_bundleJsons["rekor2-dsse-happy-path"]);

    [Benchmark(Description = "managed key bundle")]
    public SigstoreBundle DeserializeManagedKey() => SigstoreBundle.Deserialize(_bundleJsons["managed-key-happy-path"]);

    [Benchmark(Description = "rekor2 with TSA timestamp")]
    public SigstoreBundle DeserializeRekor2Tsa() => SigstoreBundle.Deserialize(_bundleJsons["rekor2-timestamp-with-embedded-cert"]);
}
