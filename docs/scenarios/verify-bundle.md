# Verify a Sigstore Bundle

This guide covers the most common verification scenario: checking that an artifact was signed by a specific identity.

## Basic Verification

```csharp
using Sigstore;

// Create a verifier — downloads the Sigstore trusted root on first use
var verifier = new SigstoreVerifier();

// Load the bundle
var bundle = await SigstoreBundle.LoadAsync(new FileInfo("artifact.sigstore.json"));

// Define who you expect signed it
var policy = new VerificationPolicy
{
    CertificateIdentity = new CertificateIdentity
    {
        SubjectAlternativeName = "release-bot@myorg.iam.gserviceaccount.com",
        Issuer = "https://accounts.google.com"
    }
};

// Verify
await using var artifact = File.OpenRead("artifact.tar.gz");
var result = await verifier.VerifyStreamAsync(artifact, bundle, policy);

Console.WriteLine($"Signed by: {result.SignerIdentity!.SubjectAlternativeName}");
Console.WriteLine($"Timestamps: {result.VerifiedTimestamps.Count}");
```

## Pattern Matching on Identity

Use regex patterns when you can't predict the exact SAN value:

```csharp
var policy = new VerificationPolicy
{
    CertificateIdentity = new CertificateIdentity
    {
        SubjectAlternativeNamePattern = @".*@myorg\.com",
        Issuer = "https://accounts.google.com"
    }
};
```

## File-Path Shorthand

For the common case of verifying files on disk:

```csharp
var result = await verifier.VerifyFileAsync(
    artifact: new FileInfo("artifact.tar.gz"),
    bundle: new FileInfo("artifact.sigstore.json"),
    policy);
```

## Non-Throwing Verification (Try Pattern)

```csharp
var (success, result) = await verifier.TryVerifyStreamAsync(artifact, bundle, policy);
if (!success)
{
    Console.Error.WriteLine($"Verification failed: {result?.FailureReason}");
    return 1;
}
```

## Pre-Computed Digest Verification

If you've already hashed the artifact (e.g., for large files or streaming scenarios):

```csharp
var digest = SHA256.HashData(artifactBytes);
var (success, result) = await verifier.TryVerifyDigestAsync(
    new ReadOnlyMemory<byte>(digest),
    HashAlgorithmType.Sha256,
    bundle,
    policy);
```

## Require Signed Timestamps

For higher assurance, require RFC 3161 signed timestamps:

```csharp
var policy = new VerificationPolicy
{
    CertificateIdentity = identity,
    RequireSignedTimestamps = true,
    SignedTimestampThreshold = 1
};
```

## Verification Policy Options

| Property | Default | Description |
|---|---|---|
| `CertificateIdentity` | `null` | Expected signer identity (SAN + OIDC issuer) |
| `RequireTransparencyLog` | `true` | Require verified transparency log entry |
| `TransparencyLogThreshold` | `1` | Minimum verified tlog entries |
| `RequireSignedTimestamps` | `false` | Require RFC 3161 TSA timestamps |
| `SignedTimestampThreshold` | `1` | Minimum signed timestamps when required |
| `RequireSignedCertificateTimestamps` | `true` | Require SCT verification |
| `PublicKey` | `null` | SPKI public key for managed-key verification |

## See Also

- [Verify GitHub Actions Artifacts](verify-github-actions.md) — specialized GitHub Actions verification
- [Custom Trust Root](custom-trust-root.md) — private Sigstore deployments
