# Verify GitHub Actions Artifacts

This guide shows how to verify that an artifact was signed by a specific GitHub Actions workflow.

## Scenario

Your CI/CD pipeline signs build artifacts using Sigstore. You want to verify that a downloaded artifact was genuinely produced by a specific repository's GitHub Actions workflow before deploying it.

## Quick Start

```csharp
using Sigstore;

var verifier = new SigstoreVerifier();

var policy = new VerificationPolicy
{
    CertificateIdentity = CertificateIdentity.ForGitHubActions(
        owner: "myorg",
        repository: "myapp")
};

var result = await verifier.VerifyFileAsync(
    new FileInfo("myapp-1.0.0.tar.gz"),
    new FileInfo("myapp-1.0.0.tar.gz.sigstore.json"),
    policy);

Console.WriteLine($"Signed by: {result.SignerIdentity!.SubjectAlternativeName}");
Console.WriteLine($"Issuer: {result.SignerIdentity.Issuer}");
```

## Pin to a Specific Branch

To verify the artifact was signed from a specific branch (e.g., `main`):

```csharp
var policy = new VerificationPolicy
{
    CertificateIdentity = CertificateIdentity.ForGitHubActions(
        owner: "myorg",
        repository: "myapp",
        workflowRef: "refs/heads/main")
};
```

## Pin to a Specific Workflow

To match a specific workflow file and branch:

```csharp
var policy = new VerificationPolicy
{
    CertificateIdentity = new CertificateIdentity
    {
        SubjectAlternativeNamePattern =
            @"https://github\.com/myorg/myapp/\.github/workflows/release\.yml@refs/tags/v.*",
        Issuer = "https://token.actions.githubusercontent.com"
    }
};
```

## Handle Verification Failures

Use `TryVerifyFileAsync` for non-throwing verification:

```csharp
var (success, result) = await verifier.TryVerifyFileAsync(
    new FileInfo("myapp-1.0.0.tar.gz"),
    new FileInfo("myapp-1.0.0.tar.gz.sigstore.json"),
    policy);

if (success)
{
    Console.WriteLine($"✓ Verified: {result!.SignerIdentity!.SubjectAlternativeName}");
    foreach (var ts in result.VerifiedTimestamps)
        Console.WriteLine($"  Timestamp ({ts.Source}): {ts.Timestamp}");
}
else
{
    Console.WriteLine($"✗ Verification failed: {result?.FailureReason}");
    Environment.Exit(1);
}
```

## How It Works

When you call `CertificateIdentity.ForGitHubActions("myorg", "myapp")`, it creates a policy that:

1. Sets the expected OIDC issuer to `https://token.actions.githubusercontent.com`
2. Sets a Subject Alternative Name pattern matching `https://github.com/myorg/myapp/.*`

During verification, the library checks that:
- The signing certificate was issued by Sigstore's Fulcio CA
- The certificate's OIDC issuer extension matches GitHub Actions
- The certificate's SAN matches your repository pattern
- The signature is recorded in the Rekor transparency log
- All timestamps are valid and verified

## See Also

- [Verify a Bundle](verify-bundle.md) — generic bundle verification
- [Sign Artifacts in CI](sign-in-ci.md) — signing artifacts in GitHub Actions
