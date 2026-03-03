# Asserting on Attestations

After verifying a Sigstore bundle, you often need to inspect the attestation content — checking which repository built the artifact, what workflow was used, or extracting SLSA provenance details. This guide covers how to use the attestation helper APIs to do this without manual JSON parsing.

## Understanding the Layers

A verified Sigstore bundle contains attestation information at two levels:

1. **Certificate extensions** — Fulcio embeds CI/CD identity claims (source repository, workflow, runner environment) directly into the signing certificate as X.509 extensions. These are available on `VerifiedIdentity.Extensions`.

2. **DSSE envelope payload** — For in-toto attestation bundles, the DSSE envelope contains a full in-toto statement with subjects and a predicate (typically SLSA provenance). This is available on `VerificationResult.Statement`.

## Inspecting Certificate Extensions

Every Sigstore signing certificate issued by Fulcio contains extensions that describe who signed the artifact and from where. After verification, these are parsed automatically:

```csharp
using Sigstore;

var verifier = new SigstoreVerifier();
var policy = new VerificationPolicy
{
    CertificateIdentity = CertificateIdentity.ForGitHubActions("myorg", "myapp")
};

var result = await verifier.VerifyFileAsync(
    new FileInfo("artifact.tar.gz"),
    new FileInfo("artifact.sigstore.json"),
    policy);

// Access rich identity information from the signing certificate
var extensions = result.SignerIdentity!.Extensions!;

Console.WriteLine($"Source repository:  {extensions.SourceRepositoryUri}");
Console.WriteLine($"Repository ref:    {extensions.SourceRepositoryRef}");
Console.WriteLine($"Build signer:      {extensions.BuildSignerUri}");
Console.WriteLine($"Runner:            {extensions.RunnerEnvironment}");
Console.WriteLine($"Build trigger:     {extensions.BuildTrigger}");
Console.WriteLine($"Build config:      {extensions.BuildConfigUri}");
Console.WriteLine($"Run invocation:    {extensions.RunInvocationUri}");
Console.WriteLine($"Visibility:        {extensions.SourceRepositoryVisibilityAtSigning}");
Console.WriteLine($"Repo owner:        {extensions.SourceRepositoryOwnerUri}");
Console.WriteLine($"Repo digest:       {extensions.SourceRepositoryDigest}");
```

### Available Certificate Extensions

| Property | OID | Description |
|---|---|---|
| `Issuer` | 1.3.6.1.4.1.57264.1.8 | OIDC issuer (e.g., GitHub Actions token issuer) |
| `SourceRepositoryUri` | 1.3.6.1.4.1.57264.1.12 | Source repository URL |
| `SourceRepositoryDigest` | 1.3.6.1.4.1.57264.1.13 | Git commit SHA |
| `SourceRepositoryRef` | 1.3.6.1.4.1.57264.1.14 | Git ref (e.g., `refs/tags/v1.0`) |
| `SourceRepositoryIdentifier` | 1.3.6.1.4.1.57264.1.15 | Numeric repository ID |
| `SourceRepositoryOwnerUri` | 1.3.6.1.4.1.57264.1.16 | Repository owner URL |
| `SourceRepositoryOwnerIdentifier` | 1.3.6.1.4.1.57264.1.17 | Numeric owner/org ID |
| `BuildSignerUri` | 1.3.6.1.4.1.57264.1.9 | Build instructions reference |
| `BuildSignerDigest` | 1.3.6.1.4.1.57264.1.10 | Build instructions version |
| `BuildConfigUri` | 1.3.6.1.4.1.57264.1.18 | Workflow/build config URL |
| `BuildConfigDigest` | 1.3.6.1.4.1.57264.1.19 | Workflow/build config version |
| `BuildTrigger` | 1.3.6.1.4.1.57264.1.20 | Event that triggered the build |
| `RunInvocationUri` | 1.3.6.1.4.1.57264.1.21 | Unique build execution URL |
| `RunnerEnvironment` | 1.3.6.1.4.1.57264.1.11 | `github-hosted` or `self-hosted` |
| `SourceRepositoryVisibilityAtSigning` | 1.3.6.1.4.1.57264.1.22 | `public` or `private` |

## Enforcing Extension Policies

You can require specific certificate extension values as part of your verification policy, going beyond just SAN and issuer matching:

```csharp
var policy = new VerificationPolicy
{
    CertificateIdentity = new CertificateIdentity
    {
        Issuer = "https://token.actions.githubusercontent.com",
        SubjectAlternativeNamePattern = @"https://github\.com/myorg/myapp/.*",
        Extensions = new CertificateExtensionPolicy
        {
            SourceRepositoryUri = "https://github.com/myorg/myapp",
            RunnerEnvironment = "github-hosted",
            SourceRepositoryVisibilityAtSigning = "public"
        }
    }
};
```

This is particularly useful for supply chain security, ensuring that:
- The artifact was built from a specific repository (not a fork)
- The build ran on trusted infrastructure (GitHub-hosted runners, not self-hosted)
- The repository was public at signing time (preventing visibility-flip attacks)

### Example: Require a Specific Tag

```csharp
var policy = new VerificationPolicy
{
    CertificateIdentity = new CertificateIdentity
    {
        Issuer = "https://token.actions.githubusercontent.com",
        SubjectAlternativeNamePattern = @"https://github\.com/myorg/myapp/.*",
        Extensions = new CertificateExtensionPolicy
        {
            SourceRepositoryUri = "https://github.com/myorg/myapp",
            SourceRepositoryRef = "refs/tags/v1.0.0"
        }
    }
};
```

## Extracting In-Toto Statements

When the bundle contains a DSSE envelope with an in-toto attestation (common for SLSA provenance), the parsed statement is available directly on the verification result:

```csharp
var result = await verifier.VerifyFileAsync(artifact, bundleFile, policy);

if (result.Statement is { } statement)
{
    Console.WriteLine($"Statement type: {statement.Type}");
    Console.WriteLine($"Predicate type: {statement.PredicateType}");

    // Inspect attestation subjects (the artifacts being attested)
    foreach (var subject in statement.Subject)
    {
        Console.WriteLine($"Subject: {subject.Name}");
        foreach (var (algo, digest) in subject.Digest)
            Console.WriteLine($"  {algo}: {digest}");
    }
}
```

### Navigating SLSA Provenance

For SLSA provenance attestations, the `Predicate` property gives you a `JsonElement` you can navigate to extract build details:

```csharp
if (result.Statement?.PredicateType == "https://slsa.dev/provenance/v1"
    && result.Statement.Predicate is { } predicate)
{
    var buildDef = predicate.GetProperty("buildDefinition");
    var buildType = buildDef.GetProperty("buildType").GetString();

    // Extract workflow information
    var workflow = buildDef.GetProperty("externalParameters").GetProperty("workflow");
    var sourceRepo = workflow.GetProperty("repository").GetString();
    var workflowPath = workflow.GetProperty("path").GetString();
    var workflowRef = workflow.GetProperty("ref").GetString();

    // Extract builder identity
    var builderId = predicate
        .GetProperty("runDetails")
        .GetProperty("builder")
        .GetProperty("id")
        .GetString();

    Console.WriteLine($"Build type:    {buildType}");
    Console.WriteLine($"Source repo:   {sourceRepo}");
    Console.WriteLine($"Workflow:      {workflowPath}");
    Console.WriteLine($"Workflow ref:  {workflowRef}");
    Console.WriteLine($"Builder:       {builderId}");
}
```

### Working with the DSSE Envelope Directly

You can also parse the statement directly from the bundle's DSSE envelope, without going through verification first (e.g., for inspection or debugging):

```csharp
var bundle = SigstoreBundle.Deserialize(File.ReadAllText("bundle.sigstore.json"));

if (bundle.DsseEnvelope?.GetStatement() is { } statement)
{
    Console.WriteLine($"Predicate type: {statement.PredicateType}");
    Console.WriteLine($"Subjects: {statement.Subject.Count}");
}
```

> **Note:** Always verify the bundle before trusting its content. The `GetStatement()` method only parses — it does not verify the signature.

## Real-World Example: npm Package Provenance

Here's how you might verify an npm package and assert on its SLSA provenance, similar to what the Aspire CLI does:

```csharp
using Sigstore;

var verifier = new SigstoreVerifier();

// Policy: must be signed by the expected repository
var policy = new VerificationPolicy
{
    CertificateIdentity = new CertificateIdentity
    {
        Issuer = "https://token.actions.githubusercontent.com",
        SubjectAlternativeNamePattern = @"https://github\.com/microsoft/playwright-cli/.*",
        Extensions = new CertificateExtensionPolicy
        {
            SourceRepositoryUri = "https://github.com/microsoft/playwright-cli",
            RunnerEnvironment = "github-hosted"
        }
    }
};

// Verify the attestation bundle
var result = await verifier.VerifyStreamAsync(tarballStream, bundle, policy);

// Assert on provenance details from the in-toto statement
if (result.Statement?.PredicateType == "https://slsa.dev/provenance/v1"
    && result.Statement.Predicate is { } predicate)
{
    var workflow = predicate
        .GetProperty("buildDefinition")
        .GetProperty("externalParameters")
        .GetProperty("workflow");

    var workflowPath = workflow.GetProperty("path").GetString();
    if (workflowPath != ".github/workflows/publish.yml")
        throw new Exception($"Unexpected workflow: {workflowPath}");

    var workflowRef = workflow.GetProperty("ref").GetString();
    if (!workflowRef!.StartsWith("refs/tags/"))
        throw new Exception($"Expected a tag ref, got: {workflowRef}");
}

// Also check certificate extensions for defense-in-depth
var ext = result.SignerIdentity!.Extensions!;
Console.WriteLine($"✓ Built from: {ext.SourceRepositoryUri}");
Console.WriteLine($"✓ At ref:     {ext.SourceRepositoryRef}");
Console.WriteLine($"✓ Runner:     {ext.RunnerEnvironment}");
Console.WriteLine($"✓ Trigger:    {ext.BuildTrigger}");
```

## See Also

- [Verify GitHub Actions Artifacts](verify-github-actions.md) — basic GitHub Actions verification
- [Verify a Bundle](verify-bundle.md) — general bundle verification
- [API Reference: FulcioCertificateExtensions](../api/Sigstore.FulcioCertificateExtensions.html)
- [API Reference: InTotoStatement](../api/Sigstore.InTotoStatement.html)
- [API Reference: CertificateExtensionPolicy](../api/Sigstore.CertificateExtensionPolicy.html)
- [Fulcio OID documentation](https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md)
