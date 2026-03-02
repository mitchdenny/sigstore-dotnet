// VerifyGitHubActions — Verify a Sigstore bundle from a GitHub Actions workflow
//
// Usage:
//   dotnet run -- <artifact-path> <bundle-path> <org-or-user> <repository>
//
// Example:
//   dotnet run -- release.tar.gz release.tar.gz.sigstore.json sigstore sigstore-go

using Sigstore;

if (args.Length < 4)
{
    Console.Error.WriteLine("Usage: VerifyGitHubActions <artifact> <bundle.sigstore.json> <org-or-user> <repository>");
    Console.Error.WriteLine();
    Console.Error.WriteLine("Arguments:");
    Console.Error.WriteLine("  artifact      Path to the artifact file to verify");
    Console.Error.WriteLine("  bundle        Path to the Sigstore bundle (.sigstore.json)");
    Console.Error.WriteLine("  org-or-user   GitHub organization or user (e.g., sigstore)");
    Console.Error.WriteLine("  repository    GitHub repository name (e.g., sigstore-go)");
    Console.Error.WriteLine();
    Console.Error.WriteLine("Example:");
    Console.Error.WriteLine("  dotnet run -- release.tar.gz release.tar.gz.sigstore.json sigstore sigstore-go");
    return 1;
}

string artifactPath = args[0];
string bundlePath = args[1];
string organizationOrUser = args[2];
string repository = args[3];

// 1. Load the bundle
string bundleJson = await File.ReadAllTextAsync(bundlePath);
SigstoreBundle bundle = SigstoreBundle.Deserialize(bundleJson);

Console.WriteLine($"Loaded bundle: {bundle.MediaType}");
Console.WriteLine($"Verifying against repository: {organizationOrUser}/{repository}");

// 2. Create a verification policy for GitHub Actions
//    CertificateIdentity.ForGitHubActions() sets up:
//    - OIDC issuer: https://token.actions.githubusercontent.com
//    - SAN pattern: https://github.com/{organizationOrUser}/{repository}/.*
var policy = new VerificationPolicy
{
    CertificateIdentity = CertificateIdentity.ForGitHubActions(organizationOrUser, repository)
};

// 3. Verify — default constructor downloads Sigstore public-good trust root
var verifier = new SigstoreVerifier();
await using var artifactStream = File.OpenRead(artifactPath);

try
{
    var result = await verifier.VerifyAsync(artifactStream, bundle, policy);

    Console.WriteLine("✅ Verification succeeded!");
    Console.WriteLine($"   Signer: {result.SignerIdentity?.SubjectAlternativeName}");
    Console.WriteLine($"   Issuer: {result.SignerIdentity?.Issuer}");
    Console.WriteLine($"   This artifact was signed by a GitHub Actions workflow in {organizationOrUser}/{repository}");
    return 0;
}
catch (VerificationException ex)
{
    Console.Error.WriteLine("❌ Verification failed!");
    Console.Error.WriteLine($"   {ex.Message}");
    return 1;
}


