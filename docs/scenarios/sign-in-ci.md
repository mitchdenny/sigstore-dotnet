# Sign Artifacts in CI/CD

This guide shows how to sign artifacts in CI/CD pipelines using ambient OIDC credentials.

## GitHub Actions

In GitHub Actions, the workflow automatically has an OIDC identity token available. Sigstore uses this to issue a short-lived signing certificate — no long-lived secrets needed.

### Workflow Setup

```yaml
# .github/workflows/release.yml
name: Release
on:
  push:
    tags: ['v*']

permissions:
  id-token: write  # Required for Sigstore OIDC
  contents: read

jobs:
  build-and-sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-dotnet@v4
        with:
          dotnet-version: '10.0'

      - name: Build
        run: dotnet build -c Release

      - name: Sign artifact
        run: dotnet run --project tools/sign -- artifacts/myapp.tar.gz
```

### Signing Code

```csharp
using Sigstore;

// In CI, SigstoreSigner automatically detects ambient OIDC credentials
var signer = new SigstoreSigner(fulcioClient, rekorClient, tsaClient, oidcProvider);

await using var artifact = File.OpenRead(args[0]);
var bundle = await signer.SignAsync(artifact);

await bundle.SaveAsync($"{args[0]}.sigstore.json");
Console.WriteLine($"Signed! Rekor log index: {bundle.VerificationMaterial?.TlogEntries[0].LogIndex}");
```

### Verifying the Signed Artifact

Consumers verify by pinning to your repository:

```csharp
var verifier = new SigstoreVerifier();
var policy = new VerificationPolicy
{
    CertificateIdentity = CertificateIdentity.ForGitHubActions(
        repository: "myorg/myapp",
        workflowRef: "refs/tags/v1.0.0")
};

var result = await verifier.VerifyAsync(
    "myapp.tar.gz",
    "myapp.tar.gz.sigstore.json",
    policy);
```

## Signing DSSE Attestations (In-Toto)

For supply chain attestations (SLSA provenance, SBOMs):

```csharp
var statement = """
{
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [{"name": "myapp.tar.gz", "digest": {"sha256": "abc123..."}}],
    "predicateType": "https://slsa.dev/provenance/v1",
    "predicate": { ... }
}
""";

var bundle = await signer.AttestAsync(statement);
await bundle.SaveAsync("myapp.tar.gz.intoto.sigstore.json");
```

## What Happens During Signing

1. **OIDC Authentication** — obtains an identity token from the CI provider
2. **Ephemeral Key** — generates a one-time ECDSA P-256 keypair
3. **Certificate** — Fulcio issues a short-lived certificate binding the OIDC identity
4. **Sign** — signs the artifact hash with the ephemeral private key
5. **Timestamp** — gets an RFC 3161 signed timestamp
6. **Transparency Log** — records the signing event in Rekor
7. **Bundle** — packages everything into a `.sigstore.json` file
8. **Key Destruction** — the ephemeral private key is destroyed

## See Also

- [Sign Interactively](sign-interactive.md) — signing from a developer workstation
- [Verify GitHub Actions Artifacts](verify-github-actions.md) — verifying signed CI artifacts
