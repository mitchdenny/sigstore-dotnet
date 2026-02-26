// SignArtifact — Sign a file using Sigstore keyless signing
//
// Usage:
//   dotnet run -- <artifact-path>
//
// This will:
//   1. Authenticate via OIDC (opens a browser)
//   2. Generate an ephemeral signing key
//   3. Obtain a short-lived certificate from Fulcio
//   4. Sign the artifact
//   5. Timestamp the signature via RFC 3161
//   6. Record the signing event in Rekor
//   7. Write the bundle to <artifact-path>.sigstore.json
//
// Example:
//   dotnet run -- myfile.txt
//   # Produces myfile.txt.sigstore.json

using Sigstore.Common;
using Sigstore.Signing;

if (args.Length < 1)
{
    Console.Error.WriteLine("Usage: SignArtifact <artifact-path>");
    Console.Error.WriteLine();
    Console.Error.WriteLine("Signs the artifact using Sigstore keyless signing and writes");
    Console.Error.WriteLine("the bundle to <artifact-path>.sigstore.json");
    Console.Error.WriteLine();
    Console.Error.WriteLine("Example:");
    Console.Error.WriteLine("  dotnet run -- myfile.txt");
    return 1;
}

string artifactPath = args[0];
string bundlePath = $"{artifactPath}.sigstore.json";

if (!File.Exists(artifactPath))
{
    Console.Error.WriteLine($"Error: File not found: {artifactPath}");
    return 1;
}

Console.WriteLine($"Signing: {artifactPath}");

// 1. Create a signer
//    The default constructor uses the Sigstore public good instance.
//    In production, this would wire up real Fulcio, Rekor, TSA, and OIDC clients.
//
//    For custom deployments, inject your own service implementations:
//    var signer = new SigstoreSigner(myFulcio, myRekor, myTsa, myOidc);
var signer = new SigstoreSigner();

// 2. Sign the artifact
Console.WriteLine("Authenticating and signing...");
await using var stream = File.OpenRead(artifactPath);
SigstoreBundle bundle = await signer.SignAsync(stream);

// 3. Write the bundle to disk
string bundleJson = bundle.Serialize();
await File.WriteAllTextAsync(bundlePath, bundleJson);

Console.WriteLine($"✅ Signed successfully!");
Console.WriteLine($"   Bundle written to: {bundlePath}");
Console.WriteLine($"   Media type: {bundle.MediaType}");

if (bundle.VerificationMaterial?.TlogEntries.Count > 0)
{
    var entry = bundle.VerificationMaterial.TlogEntries[0];
    Console.WriteLine($"   Rekor log index: {entry.LogIndex}");
}

return 0;
