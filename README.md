# sigstore-dotnet

A .NET library for generating and verifying [Sigstore](https://www.sigstore.dev/) signatures.

[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Overview

`sigstore-dotnet` is a pure .NET implementation of the [Sigstore Client Specification](https://github.com/sigstore/architecture-docs/blob/main/client-spec.md). It supports keyless signing and verification using the Sigstore public good instance (Fulcio, Rekor, RFC 3161 TSA) — no external tools required.

## Features

- **Keyless signing** — ephemeral ECDSA P-256 keys tied to OIDC identities
- **Bundle verification** — full Sigstore bundle verification (v0.1, v0.2, v0.3)
- **Certificate validation** — hybrid time model per RFC 5280
- **Transparency log** — Merkle inclusion proof and checkpoint verification
- **RFC 3161 timestamps** — timestamp authority integration
- **DSSE attestations** — in-toto statement signing and verification
- **DI-friendly** — constructor injection with sensible defaults

## Quick Start

### Verification

```csharp
using Sigstore;

// Default constructor uses Sigstore public good instance
var verifier = new SigstoreVerifier(trustRootProvider);

var policy = new VerificationPolicy
{
    CertificateIdentity = CertificateIdentity.ForGitHubActions(
        owner: "owner",
        repository: "repo")
};

// Throws VerificationException on failure
var result = await verifier.VerifyStreamAsync(artifactStream, bundle, policy);

// Or use TryVerifyStreamAsync for non-throwing verification
var (success, result) = await verifier.TryVerifyStreamAsync(artifactStream, bundle, policy);
```

### Signing

```csharp

var signer = new SigstoreSigner(fulcioClient, rekorClient, tsaClient, oidcProvider);

SigstoreBundle bundle = await signer.SignAsync(artifactStream);
string json = bundle.Serialize();
```

### Bundle I/O

```csharp

// Parse a bundle
SigstoreBundle bundle = SigstoreBundle.Deserialize(json);

// Serialize a bundle
string json = bundle.Serialize();
```

## Architecture

The library is organized in three layers:

| Layer | Purpose | Examples |
|-------|---------|----------|
| **High-level** | Orchestrate complete workflows | `SigstoreSigner`, `SigstoreVerifier` |
| **Service clients** | Interact with Sigstore infrastructure | `IFulcioClient`, `IRekorClient`, `ITimestampAuthority`, `IOidcTokenProvider` |
| **Primitives** | Pure computation, no I/O | `MerkleVerifier`, `CheckpointVerifier`, `TimestampParser`, `BundleSerializer` |

## Building

```bash
dotnet build Sigstore.slnx
```

## Testing

```bash
dotnet test Sigstore.slnx
```

## License

MIT — see [LICENSE](LICENSE).
