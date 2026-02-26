// VerifyGitHubActions — Verify a Sigstore bundle from a GitHub Actions workflow
//
// Usage:
//   dotnet run -- <artifact-path> <bundle-path> <repository>
//
// Example:
//   dotnet run -- release.tar.gz release.tar.gz.sigstore.json sigstore/sigstore-go

using Sigstore.Common;
using Sigstore.Verification;

if (args.Length < 3)
{
    Console.Error.WriteLine("Usage: VerifyGitHubActions <artifact> <bundle.sigstore.json> <repository>");
    Console.Error.WriteLine();
    Console.Error.WriteLine("Arguments:");
    Console.Error.WriteLine("  artifact    Path to the artifact file to verify");
    Console.Error.WriteLine("  bundle      Path to the Sigstore bundle (.sigstore.json)");
    Console.Error.WriteLine("  repository  GitHub repository (e.g., owner/repo)");
    Console.Error.WriteLine();
    Console.Error.WriteLine("Example:");
    Console.Error.WriteLine("  dotnet run -- release.tar.gz release.tar.gz.sigstore.json sigstore/sigstore-go");
    return 1;
}

string artifactPath = args[0];
string bundlePath = args[1];
string repository = args[2];

// 1. Load the bundle
string bundleJson = await File.ReadAllTextAsync(bundlePath);
SigstoreBundle bundle = SigstoreBundle.Deserialize(bundleJson);

Console.WriteLine($"Loaded bundle: {bundle.MediaType}");
Console.WriteLine($"Verifying against repository: {repository}");

// 2. Create a verification policy for GitHub Actions
//    CertificateIdentity.ForGitHubActions() sets up:
//    - OIDC issuer: https://token.actions.githubusercontent.com
//    - SAN pattern: https://github.com/{repository}/.*
var policy = new VerificationPolicy
{
    CertificateIdentity = CertificateIdentity.ForGitHubActions(repository)
};

// 3. Verify
var verifier = new SigstoreVerifier(new FileTrustRootProvider("trusted_root.json"));
await using var artifactStream = File.OpenRead(artifactPath);

try
{
    var result = await verifier.VerifyAsync(artifactStream, bundle, policy);

    Console.WriteLine("✅ Verification succeeded!");
    Console.WriteLine($"   Signer: {result.SignerIdentity?.SubjectAlternativeName}");
    Console.WriteLine($"   Issuer: {result.SignerIdentity?.Issuer}");
    Console.WriteLine($"   This artifact was signed by a GitHub Actions workflow in {repository}");
    return 0;
}
catch (VerificationException ex)
{
    Console.Error.WriteLine("❌ Verification failed!");
    Console.Error.WriteLine($"   {ex.Message}");
    return 1;
}

// --- Helper ---

class FileTrustRootProvider : ITrustRootProvider
{
    private readonly string _path;
    public FileTrustRootProvider(string path) => _path = path;

    public async Task<Sigstore.TrustRoot.TrustedRoot> GetTrustRootAsync(CancellationToken ct = default)
    {
        string json = await File.ReadAllTextAsync(_path, ct);
        return Sigstore.TrustRoot.TrustedRoot.Deserialize(json);
    }
}
