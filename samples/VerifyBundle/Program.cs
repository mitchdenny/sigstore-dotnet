// VerifyBundle — Verify a Sigstore bundle against an artifact
//
// Usage:
//   dotnet run -- <artifact-path> <bundle-path> <expected-identity> <expected-issuer>
//
// Example:
//   dotnet run -- myfile.txt myfile.txt.sigstore.json user@example.com https://accounts.google.com

using Sigstore.Common;
using Sigstore.Verification;

if (args.Length < 4)
{
    Console.Error.WriteLine("Usage: VerifyBundle <artifact> <bundle.sigstore.json> <identity> <issuer>");
    Console.Error.WriteLine();
    Console.Error.WriteLine("Arguments:");
    Console.Error.WriteLine("  artifact    Path to the artifact file to verify");
    Console.Error.WriteLine("  bundle      Path to the Sigstore bundle (.sigstore.json)");
    Console.Error.WriteLine("  identity    Expected signer identity (email or URI)");
    Console.Error.WriteLine("  issuer      Expected OIDC issuer URL");
    Console.Error.WriteLine();
    Console.Error.WriteLine("Example:");
    Console.Error.WriteLine("  dotnet run -- myfile.txt myfile.txt.sigstore.json user@example.com https://accounts.google.com");
    return 1;
}

string artifactPath = args[0];
string bundlePath = args[1];
string expectedIdentity = args[2];
string expectedIssuer = args[3];

// 1. Load the bundle from disk
string bundleJson = await File.ReadAllTextAsync(bundlePath);
SigstoreBundle bundle = SigstoreBundle.Deserialize(bundleJson);

Console.WriteLine($"Loaded bundle: {bundle.MediaType}");

// 2. Set up the verification policy — who do we expect signed this?
var policy = new VerificationPolicy
{
    CertificateIdentity = new CertificateIdentity
    {
        SubjectAlternativeName = expectedIdentity,
        Issuer = expectedIssuer
    }
};

// 3. Create a verifier with the trusted root
//    In production, you'd use a TUF-based trust root provider.
//    For this sample, we construct the verifier with a trust root provider.
var verifier = new SigstoreVerifier(new FileTrustRootProvider("trusted_root.json"));

// 4. Verify the bundle against the artifact
await using var artifactStream = File.OpenRead(artifactPath);

var (success, result) = await verifier.TryVerifyAsync(artifactStream, bundle, policy);

if (success)
{
    Console.WriteLine("✅ Verification succeeded!");
    Console.WriteLine($"   Signer: {result!.SignerIdentity?.SubjectAlternativeName}");
    Console.WriteLine($"   Issuer: {result.SignerIdentity?.Issuer}");
    foreach (var ts in result.VerifiedTimestamps)
    {
        Console.WriteLine($"   Timestamp ({ts.Source}): {ts.Timestamp:O}");
    }
    return 0;
}
else
{
    Console.Error.WriteLine("❌ Verification failed!");
    Console.Error.WriteLine($"   Reason: {result?.FailureReason}");
    return 1;
}

// --- Helper: A simple trust root provider that loads from a JSON file ---

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
