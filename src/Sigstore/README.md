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
- **OpenTelemetry-ready** — emits native .NET activities and metrics without an exporter dependency

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

## Telemetry

The package emits diagnostics through the built-in `System.Diagnostics`
APIs. Applications choose how to collect and export them; the package does not
initialize OpenTelemetry or install an exporter.

```csharp
services.AddOpenTelemetry()
    .WithTracing(tracing => tracing
        .AddSource(SigstoreTelemetry.ActivitySourceName)
        .AddSource(TufTelemetry.ActivitySourceName))
    .WithMetrics(metrics => metrics
        .AddMeter(SigstoreTelemetry.MeterName)
        .AddMeter(TufTelemetry.MeterName));
```

The `Sigstore` activity source emits top-level `sigstore.sign`,
`sigstore.attest`, and `sigstore.verify` activities, with child activities for
OIDC, Fulcio, Rekor, timestamp, trust-root, certificate, transparency-log, and
signature work. Its principal metrics are:

- `sigstore.sign.duration` and `sigstore.sign.active`
- `sigstore.attest.duration` and `sigstore.attest.active`
- `sigstore.verify.duration` and `sigstore.verify.active`

Duration instruments use seconds. Failed operations include the standard
`error.type` attribute. The package does not emit identities, tokens,
certificates, signatures, artifact digests, file paths, or service response
bodies as telemetry attributes.

Enable the standard .NET HTTP client instrumentation alongside these sources
to observe individual network requests without duplicate Sigstore HTTP
metrics.

## Documentation

📖 [Full documentation](https://mitchdenny.github.io/sigstore-dotnet/)

## License

MIT — see [LICENSE](https://github.com/mitchdenny/sigstore-dotnet/blob/main/LICENSE).
