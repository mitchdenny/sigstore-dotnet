---
_layout: landing
---

# Sigstore for .NET

A .NET library for generating and verifying [Sigstore](https://sigstore.dev) signatures.

## Quick Start

Install the NuGet package:

```bash
dotnet add package Sigstore
```

Verify a Sigstore bundle:

```csharp
using Sigstore.Verification;

var verifier = new SigstoreVerifier();
var bundle = SigstoreBundle.Deserialize(File.ReadAllText("artifact.sigstore.json"));

var policy = new VerificationPolicy
{
    CertificateIdentity = CertificateIdentity.ForGitHubActions("owner/repo")
};

using var artifact = File.OpenRead("artifact.tar.gz");
var result = await verifier.VerifyAsync(artifact, bundle, policy);

Console.WriteLine($"Verified: signed by {result.SignerIdentity!.SubjectAlternativeName}");
```

## Features

- **Verify** Sigstore bundles (v0.1, v0.2, v0.3) with full conformance
- **Sign** artifacts using keyless Sigstore signing (Fulcio + Rekor)
- **DSSE** envelope support for in-toto attestations
- **RFC 3161** timestamp verification
- **SCT** (Signed Certificate Timestamp) verification
- **Rekor v1 and v2** transparency log verification
- **Ed25519 and ECDSA** signature algorithms
- **Extensible** trust root and certificate validation

## Documentation

- [Getting Started](docs/getting-started.md)
- [Design Overview](docs/design-overview.md)
- [API Reference](api/index.md)

## License

This project is licensed under the MIT License. See [LICENSE](https://github.com/mitchdenny/sigstore-dotnet/blob/main/LICENSE) for details.
