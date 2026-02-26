// VerifyWithCustomTrustRoot — Verify using a custom trust root (private Sigstore instance)
//
// Usage:
//   dotnet run -- <artifact-path> <bundle-path> <trust-root-path> <identity> <issuer>
//
// Example:
//   dotnet run -- myfile.txt myfile.txt.sigstore.json my-trust-root.json user@corp.com https://idp.corp.com

using Sigstore.Common;
using Sigstore.TrustRoot;
using Sigstore.Verification;

if (args.Length < 5)
{
    Console.Error.WriteLine("Usage: VerifyWithCustomTrustRoot <artifact> <bundle> <trust-root> <identity> <issuer>");
    Console.Error.WriteLine();
    Console.Error.WriteLine("Arguments:");
    Console.Error.WriteLine("  artifact     Path to the artifact file to verify");
    Console.Error.WriteLine("  bundle       Path to the Sigstore bundle (.sigstore.json)");
    Console.Error.WriteLine("  trust-root   Path to a custom trusted root JSON file");
    Console.Error.WriteLine("  identity     Expected signer identity (email or URI)");
    Console.Error.WriteLine("  issuer       Expected OIDC issuer URL");
    Console.Error.WriteLine();
    Console.Error.WriteLine("This sample demonstrates verification against a private Sigstore");
    Console.Error.WriteLine("deployment that uses its own Fulcio CA, Rekor instance, and TSA.");
    return 1;
}

string artifactPath = args[0];
string bundlePath = args[1];
string trustRootPath = args[2];
string expectedIdentity = args[3];
string expectedIssuer = args[4];

// 1. Load the custom trusted root
//    A private Sigstore deployment distributes its own trusted root containing:
//    - Certificate authorities (Fulcio CAs)
//    - Transparency logs (Rekor instances)
//    - CT logs
//    - Timestamp authorities
Console.WriteLine($"Loading custom trust root: {trustRootPath}");
string trustRootJson = await File.ReadAllTextAsync(trustRootPath);
TrustedRoot trustRoot = TrustedRoot.Deserialize(trustRootJson);

Console.WriteLine($"  Trust root media type: {trustRoot.MediaType}");
Console.WriteLine($"  Certificate authorities: {trustRoot.CertificateAuthorities.Count}");
Console.WriteLine($"  Transparency logs: {trustRoot.TransparencyLogs.Count}");
Console.WriteLine($"  CT logs: {trustRoot.CtLogs.Count}");
Console.WriteLine($"  Timestamp authorities: {trustRoot.TimestampAuthorities.Count}");

// 2. Load the bundle
string bundleJson = await File.ReadAllTextAsync(bundlePath);
SigstoreBundle bundle = SigstoreBundle.Deserialize(bundleJson);

// 3. Create a verifier with the custom trust root
//    The InMemoryTrustRootProvider wraps a pre-loaded TrustedRoot.
var verifier = new SigstoreVerifier(new InMemoryTrustRootProvider(trustRoot));

// 4. Verify with identity policy
var policy = new VerificationPolicy
{
    CertificateIdentity = new CertificateIdentity
    {
        SubjectAlternativeName = expectedIdentity,
        Issuer = expectedIssuer
    }
};

await using var artifactStream = File.OpenRead(artifactPath);
var (success, result) = await verifier.TryVerifyAsync(artifactStream, bundle, policy);

if (success)
{
    Console.WriteLine();
    Console.WriteLine("✅ Verification succeeded with custom trust root!");
    Console.WriteLine($"   Signer: {result!.SignerIdentity?.SubjectAlternativeName}");
    Console.WriteLine($"   Issuer: {result.SignerIdentity?.Issuer}");
    return 0;
}
else
{
    Console.Error.WriteLine();
    Console.Error.WriteLine("❌ Verification failed!");
    Console.Error.WriteLine($"   Reason: {result?.FailureReason}");
    return 1;
}

// --- Helper: Wraps an already-loaded TrustedRoot ---

class InMemoryTrustRootProvider(TrustedRoot trustRoot) : ITrustRootProvider
{
    public Task<TrustedRoot> GetTrustRootAsync(CancellationToken ct = default)
        => Task.FromResult(trustRoot);
}
