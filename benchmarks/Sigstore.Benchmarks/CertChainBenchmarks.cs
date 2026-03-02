using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using Sigstore;

namespace Sigstore.Benchmarks;

/// <summary>
/// Isolates the cost of X509Chain.Build() with a pre-built trust store
/// vs rebuilding the trust store from scratch each time.
/// This quantifies how much we can save by caching the trust store.
/// </summary>
[MemoryDiagnoser]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class CertChainBenchmarks
{
    private static readonly string AssetsDir = GetAssetsDir();
    private TrustedRoot _trustRoot = null!;
    private X509Certificate2 _leafCert = null!;
    private X509Certificate2Collection? _intermediates;
    private DateTimeOffset _signatureTime;

    // Pre-built trust store components
    private X509Certificate2Collection _preBuiltRoots = null!;
    private X509Certificate2Collection _preBuiltIntermediates = null!;

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
        var trustRootProvider = new TufTrustRootProvider(TufTrustRootProvider.ProductionUrl);
        _trustRoot = trustRootProvider.GetTrustRootAsync(CancellationToken.None).GetAwaiter().GetResult();

        var bundleJson = File.ReadAllText(Path.Combine(AssetsDir, "happy-path", "bundle.sigstore.json"));
        var bundle = SigstoreBundle.Deserialize(bundleJson);

        var leafCertBytes = bundle.VerificationMaterial!.Certificate
            ?? bundle.VerificationMaterial.CertificateChain![0];
        _leafCert = X509CertificateLoader.LoadCertificate(leafCertBytes.Span);

        if (bundle.VerificationMaterial.CertificateChain is { Count: > 1 })
        {
            _intermediates = new X509Certificate2Collection();
            for (int i = 1; i < bundle.VerificationMaterial.CertificateChain.Count; i++)
                _intermediates.Add(X509CertificateLoader.LoadCertificate(
                    bundle.VerificationMaterial.CertificateChain[i].Span));
        }

        // Use a time within the cert validity
        _signatureTime = _leafCert.NotBefore.AddSeconds(1);

        // Pre-build trust store
        _preBuiltRoots = new X509Certificate2Collection();
        _preBuiltIntermediates = new X509Certificate2Collection();
        foreach (var ca in _trustRoot.CertificateAuthorities)
        {
            foreach (var certBytes in ca.CertificateChain)
            {
                var cert = X509CertificateLoader.LoadCertificate(certBytes.Span);
                if (cert.SubjectName.RawData.SequenceEqual(cert.IssuerName.RawData))
                    _preBuiltRoots.Add(cert);
                else
                    _preBuiltIntermediates.Add(cert);
            }
        }
    }

    [Benchmark(Description = "Current: rebuild trust store + chain build")]
    [BenchmarkCategory("ChainBuild")]
    public bool CurrentApproach()
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationTime = _signatureTime.UtcDateTime;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;

        // This is what happens today — reload certs from bytes every time
        foreach (var ca in _trustRoot.CertificateAuthorities)
        {
            foreach (var certBytes in ca.CertificateChain)
            {
                var cert = X509CertificateLoader.LoadCertificate(certBytes.Span);
                if (cert.SubjectName.RawData.SequenceEqual(cert.IssuerName.RawData))
                    chain.ChainPolicy.CustomTrustStore.Add(cert);
                else
                    chain.ChainPolicy.ExtraStore.Add(cert);
            }
        }

        if (_intermediates != null)
            chain.ChainPolicy.ExtraStore.AddRange(_intermediates);

        return chain.Build(_leafCert);
    }

    [Benchmark(Description = "Optimized: pre-built trust store + chain build")]
    [BenchmarkCategory("ChainBuild")]
    public bool OptimizedApproach()
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationTime = _signatureTime.UtcDateTime;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;

        // Pre-built: just add already-parsed certs
        chain.ChainPolicy.CustomTrustStore.AddRange(_preBuiltRoots);
        chain.ChainPolicy.ExtraStore.AddRange(_preBuiltIntermediates);

        if (_intermediates != null)
            chain.ChainPolicy.ExtraStore.AddRange(_intermediates);

        return chain.Build(_leafCert);
    }

    [Benchmark(Description = "Trust store setup only (no chain build)")]
    [BenchmarkCategory("TrustStoreSetup")]
    public int TrustStoreSetupOnly()
    {
        int count = 0;
        foreach (var ca in _trustRoot.CertificateAuthorities)
        {
            foreach (var certBytes in ca.CertificateChain)
            {
                using var cert = X509CertificateLoader.LoadCertificate(certBytes.Span);
                if (cert.SubjectName.RawData.SequenceEqual(cert.IssuerName.RawData))
                    count++;
            }
        }
        return count;
    }

    [Benchmark(Description = "X509Chain.Build only (pre-built store)")]
    [BenchmarkCategory("TrustStoreSetup")]
    public bool ChainBuildOnly()
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationTime = _signatureTime.UtcDateTime;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(_preBuiltRoots);
        chain.ChainPolicy.ExtraStore.AddRange(_preBuiltIntermediates);
        if (_intermediates != null)
            chain.ChainPolicy.ExtraStore.AddRange(_intermediates);
        return chain.Build(_leafCert);
    }
}
