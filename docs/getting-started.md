# Getting Started

## Installation

Install the Sigstore NuGet package:

```bash
dotnet add package Sigstore
```

## Verifying a Sigstore Bundle

The most common use case is verifying that an artifact was signed by an expected identity.

### Basic Verification

```csharp
using Sigstore;

// Create a verifier (downloads the Sigstore public-good trusted root on first use)
var verifier = new SigstoreVerifier();

// Load the bundle
var bundle = SigstoreBundle.Deserialize(File.ReadAllText("artifact.sigstore.json"));

// Define verification policy
var policy = new VerificationPolicy
{
    CertificateIdentity = new CertificateIdentity
    {
        SubjectAlternativeName = "user@example.com",
        Issuer = "https://accounts.google.com"
    }
};

// Verify
using var artifact = File.OpenRead("artifact.tar.gz");
var result = await verifier.VerifyAsync(artifact, bundle, policy);

Console.WriteLine($"Signed by: {result.SignerIdentity!.SubjectAlternativeName}");
Console.WriteLine($"Issuer: {result.SignerIdentity.Issuer}");
Console.WriteLine($"Timestamps: {result.VerifiedTimestamps.Count}");
```

### Verifying GitHub Actions Signatures

Use the convenience factory for GitHub Actions workflows:

```csharp
var policy = new VerificationPolicy
{
    CertificateIdentity = CertificateIdentity.ForGitHubActions(
        repository: "owner/repo",
        workflowRef: "refs/heads/main")
};
```

### Using a Custom Trust Root

For private Sigstore deployments or testing:

```csharp
using Sigstore;

var trustRoot = TrustedRoot.Deserialize(File.ReadAllText("custom-trusted-root.json"));
var verifier = new SigstoreVerifier(new InMemoryTrustRootProvider(trustRoot));
```

### Try-Pattern (No Exceptions)

If you prefer to handle failures without exceptions:

```csharp
var (success, result) = await verifier.TryVerifyAsync(artifact, bundle, policy);
if (success)
{
    Console.WriteLine($"Verified: {result!.SignerIdentity!.SubjectAlternativeName}");
}
else
{
    Console.WriteLine($"Failed: {result?.FailureReason}");
}
```

## Verification Policy Options

| Property | Default | Description |
|---|---|---|
| `CertificateIdentity` | `null` | Expected signer identity (SAN + OIDC issuer) |
| `RequireTransparencyLog` | `true` | Require at least one verified tlog entry |
| `TransparencyLogThreshold` | `1` | Minimum number of verified tlog entries |
| `RequireSignedTimestamps` | `false` | Require RFC 3161 TSA timestamps |
| `SignedTimestampThreshold` | `1` | Minimum signed timestamps (when required) |
| `RequireSignedCertificateTimestamps` | `true` | Require SCT verification |
| `IsOffline` | `false` | Skip network calls (all material must be in bundle) |

## Next Steps

- **[Verify GitHub Actions Artifacts](scenarios/verify-github-actions.md)** — the most common verification scenario
- **[Sign Artifacts in CI/CD](scenarios/sign-in-ci.md)** — automated signing in pipelines
- **[Custom Trust Root](scenarios/custom-trust-root.md)** — private Sigstore deployments
- **[ASP.NET Core Integration](scenarios/aspnet-integration.md)** — using with dependency injection
- **[Troubleshooting](scenarios/troubleshooting.md)** — common issues and fixes
- See the [Design Overview](design-overview.md) for architecture details
- Browse the [API Reference](../api/index.md) for complete type documentation
- Check the [samples/](https://github.com/mitchdenny/sigstore-dotnet/tree/main/samples) directory for runnable examples
