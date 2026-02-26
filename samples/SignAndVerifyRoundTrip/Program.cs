// SignAndVerifyRoundTrip — Sign an artifact and immediately verify the result
//
// Usage:
//   dotnet run -- <artifact-path>
//
// This demonstrates the full lifecycle:
//   1. Sign the artifact → produces a bundle
//   2. Verify the bundle against the same artifact
//
// Example:
//   dotnet run -- myfile.txt

using Sigstore.Common;
using Sigstore.Signing;
using Sigstore.Verification;

if (args.Length < 1)
{
    Console.Error.WriteLine("Usage: SignAndVerifyRoundTrip <artifact-path>");
    Console.Error.WriteLine();
    Console.Error.WriteLine("Signs an artifact with Sigstore, then immediately verifies the bundle.");
    Console.Error.WriteLine("Demonstrates the full sign → verify lifecycle.");
    Console.Error.WriteLine();
    Console.Error.WriteLine("Example:");
    Console.Error.WriteLine("  dotnet run -- myfile.txt");
    return 1;
}

string artifactPath = args[0];

if (!File.Exists(artifactPath))
{
    Console.Error.WriteLine($"Error: File not found: {artifactPath}");
    return 1;
}

// ========================================
// STEP 1: Sign the artifact
// ========================================
Console.WriteLine("=== SIGNING ===");
Console.WriteLine($"Artifact: {artifactPath}");

var signer = new SigstoreSigner();

await using (var signStream = File.OpenRead(artifactPath))
{
    SigstoreBundle bundle = await signer.SignAsync(signStream);

    Console.WriteLine($"Bundle media type: {bundle.MediaType}");

    if (bundle.VerificationMaterial?.TlogEntries.Count > 0)
    {
        Console.WriteLine($"Rekor log index: {bundle.VerificationMaterial.TlogEntries[0].LogIndex}");
    }

    if (bundle.VerificationMaterial?.Rfc3161Timestamps.Count > 0)
    {
        Console.WriteLine($"Timestamps: {bundle.VerificationMaterial.Rfc3161Timestamps.Count}");
    }

    // Serialize the bundle (as you would write to disk)
    string bundleJson = bundle.Serialize();
    Console.WriteLine($"Bundle size: {bundleJson.Length} bytes");

    // Save to disk for inspection
    string bundlePath = $"{artifactPath}.sigstore.json";
    await File.WriteAllTextAsync(bundlePath, bundleJson);
    Console.WriteLine($"Bundle saved to: {bundlePath}");
    Console.WriteLine();

    // ========================================
    // STEP 2: Verify the bundle
    // ========================================
    Console.WriteLine("=== VERIFICATION ===");

    // Re-parse the bundle from JSON (simulates loading from disk)
    SigstoreBundle parsedBundle = SigstoreBundle.Deserialize(bundleJson);

    // Create verifier — default constructor downloads Sigstore public-good trust root
    var verifier = new SigstoreVerifier();

    // For the round-trip, we don't enforce a specific identity —
    // in production, you would always check the signer's identity.
    var policy = new VerificationPolicy
    {
        // No identity check for this demo — just verify the cryptographic chain
        CertificateIdentity = null
    };

    // Verify
    await using var verifyStream = File.OpenRead(artifactPath);
    var (success, result) = await verifier.TryVerifyAsync(verifyStream, parsedBundle, policy);

    if (success)
    {
        Console.WriteLine("✅ Round-trip verification succeeded!");
        if (result?.SignerIdentity != null)
        {
            Console.WriteLine($"   Signer: {result.SignerIdentity.SubjectAlternativeName}");
            Console.WriteLine($"   Issuer: {result.SignerIdentity.Issuer}");
        }
        foreach (var ts in result!.VerifiedTimestamps)
        {
            Console.WriteLine($"   Timestamp ({ts.Source}): {ts.Timestamp:O}");
        }
        return 0;
    }
    else
    {
        Console.Error.WriteLine("❌ Round-trip verification failed!");
        Console.Error.WriteLine($"   Reason: {result?.FailureReason}");
        return 1;
    }
}


