# Custom Trust Root

This guide shows how to use a private Sigstore deployment with a custom trust root.

## When You Need This

- You run your own Sigstore infrastructure (Fulcio, Rekor, TSA)
- You're testing against the Sigstore staging environment
- You need to verify bundles signed with a non-standard trust root

## Verification with a Custom Trust Root

```csharp
using Sigstore;

// Load your custom trusted root
var trustRootJson = await File.ReadAllTextAsync("my-trusted-root.json");
var trustRoot = TrustedRoot.Deserialize(trustRootJson);

// Create a verifier with the custom trust root
var verifier = new SigstoreVerifier(new InMemoryTrustRootProvider(trustRoot));

var policy = new VerificationPolicy
{
    CertificateIdentity = new CertificateIdentity
    {
        SubjectAlternativeName = "builder@internal.corp",
        Issuer = "https://idp.internal.corp"
    }
};

var result = await verifier.VerifyAsync(
    new FileInfo("artifact.tar.gz"),
    new FileInfo("artifact.sigstore.json"),
    policy);
```

## Loading Trust Root from a File

```csharp
var verifier = new SigstoreVerifier(new FileTrustRootProvider(new FileInfo("path/to/trusted_root.json")));
```

## Using the Sigstore Staging Environment

```csharp
var stagingProvider = new TufTrustRootProvider(TufTrustRootProvider.StagingUrl);
var verifier = new SigstoreVerifier(stagingProvider);
```

## Inspecting a Trust Root

```csharp
var trustRoot = TrustedRoot.Deserialize(json);

Console.WriteLine($"Certificate Authorities: {trustRoot.CertificateAuthorities.Count}");
foreach (var ca in trustRoot.CertificateAuthorities)
    Console.WriteLine($"  CA: {ca.Uri} (valid {ca.ValidFrom} - {ca.ValidTo})");

Console.WriteLine($"Transparency Logs: {trustRoot.TransparencyLogs.Count}");
foreach (var tlog in trustRoot.TransparencyLogs)
    Console.WriteLine($"  Log: {tlog.BaseUrl} (valid {tlog.ValidFrom} - {tlog.ValidTo})");

Console.WriteLine($"Timestamp Authorities: {trustRoot.TimestampAuthorities.Count}");
Console.WriteLine($"CT Logs: {trustRoot.CtLogs.Count}");
```

## Trust Root Providers

| Provider | Use Case |
|----------|----------|
| `TufTrustRootProvider(ProductionUrl)` | Default — downloads from Sigstore public-good TUF |
| `TufTrustRootProvider(StagingUrl)` | Sigstore staging environment |
| `FileTrustRootProvider(FileInfo)` | Load from a JSON file |
| `InMemoryTrustRootProvider(root)` | Wrap an already-parsed `TrustedRoot` |

## See Also

- [Verify a Bundle](verify-bundle.md) — standard verification
- [Verify GitHub Actions](verify-github-actions.md) — GitHub Actions verification
