# Sign Artifacts Interactively

This guide shows how to sign artifacts from a developer workstation using browser-based OIDC authentication.

## Quick Start

```csharp
using Sigstore;

var signer = new SigstoreSigner(fulcioClient, rekorClient, tsaClient, oidcProvider);

await using var artifact = File.OpenRead("my-release.tar.gz");
var bundle = await signer.SignAsync(artifact);

await bundle.SaveAsync(new FileInfo("my-release.tar.gz.sigstore.json"));
Console.WriteLine("Signed! Bundle saved.");
```

When you run this, the library will:
1. Open your browser to authenticate with an OIDC provider (e.g., Google, GitHub, Microsoft)
2. Generate an ephemeral keypair
3. Request a signing certificate from Fulcio
4. Sign the artifact
5. Record the signature in Rekor's transparency log
6. Package everything into a `.sigstore.json` bundle

## Signing a File by Path

```csharp
var bundle = await signer.SignAsync(new FileInfo("my-release.tar.gz"));
await bundle.SaveAsync(new FileInfo("my-release.tar.gz.sigstore.json"));
```

## Verifying Your Signature

After signing, verify the bundle works:

```csharp
var verifier = new SigstoreVerifier();

var policy = new VerificationPolicy
{
    CertificateIdentity = new CertificateIdentity
    {
        SubjectAlternativeName = "you@example.com",
        Issuer = "https://accounts.google.com"
    }
};

var result = await verifier.VerifyFileAsync(
    new FileInfo("my-release.tar.gz"),
    new FileInfo("my-release.tar.gz.sigstore.json"),
    policy);

Console.WriteLine($"✓ Verified — signed by {result.SignerIdentity!.SubjectAlternativeName}");
```

## See Also

- [Sign in CI/CD](sign-in-ci.md) — automated signing in CI pipelines
- [Verify a Bundle](verify-bundle.md) — verification options and policies
