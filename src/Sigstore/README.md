# Sigstore

A .NET library for generating and verifying [Sigstore](https://www.sigstore.dev/) signatures.

## Overview

`Sigstore` is a pure .NET implementation of the [Sigstore Client Specification](https://github.com/sigstore/architecture-docs/blob/main/client-spec.md). It supports keyless signing and verification using the Sigstore public good instance (Fulcio, Rekor, RFC 3161 TSA) — no external tools required.

## Features

- **Keyless signing** — ephemeral ECDSA P-256 keys tied to OIDC identities
- **Bundle verification** — full Sigstore bundle verification (v0.1, v0.2, v0.3)
- **Certificate validation** — hybrid time model per RFC 5280
- **Transparency log** — Merkle inclusion proof and checkpoint verification
- **RFC 3161 timestamps** — timestamp authority integration
- **DSSE attestations** — in-toto statement signing and verification
- **DI-friendly** — constructor injection with sensible defaults
- **AOT-compatible** — fully trimmer and NativeAOT safe

## Quick Start

### Verification

```csharp
using Sigstore;

var verifier = new SigstoreVerifier(trustRootProvider);

var policy = new VerificationPolicy
{
    CertificateIdentity = CertificateIdentity.ForGitHubActions(
        owner: "owner",
        repository: "repo")
};

var result = await verifier.VerifyStreamAsync(artifactStream, bundle, policy);
```

### Signing

```csharp
var signer = new SigstoreSigner(fulcioClient, rekorClient, tsaClient, oidcProvider);

SigstoreBundle bundle = await signer.SignAsync(artifactStream);
string json = bundle.Serialize();
```

### Bundle I/O

```csharp
SigstoreBundle bundle = SigstoreBundle.Deserialize(json);
string json = bundle.Serialize();
```

## Documentation

📖 [Full documentation](https://mitchdenny.github.io/sigstore-dotnet/)

## License

MIT — see [LICENSE](https://github.com/mitchdenny/sigstore-dotnet/blob/main/LICENSE).
