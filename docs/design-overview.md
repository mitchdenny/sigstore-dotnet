# sigstore-dotnet — Implementation Plan

## Problem Statement

Build a first-class .NET library (`Sigstore.dll`, published as a NuGet package) that can **generate and verify Sigstore signatures** using the public Sigstore infrastructure (Fulcio, Rekor, RFC 3161 TSA) — entirely in managed .NET code with no shelling out to external tools. The library should have excellent ergonomics, follow the official [Sigstore Client Specification](https://github.com/sigstore/architecture-docs/blob/main/client-spec.md), and be extensible as the Sigstore spec evolves.

## Sigstore Background (Research Summary)

### What Is Sigstore?

Sigstore is an open-source project (under OpenSSF / Linux Foundation) that simplifies software artifact signing and verification. Instead of long-lived keypairs, Sigstore uses **ephemeral keys** tied to **OIDC identities** (email, GitHub Actions workflow, etc.), with all signing events recorded in a **tamper-resistant transparency log**.

### Core Components

| Component | Role | Interaction from client |
|-----------|------|------------------------|
| **Fulcio** | Certificate Authority — issues short-lived X.509 signing certificates bound to an OIDC identity | HTTPS REST/gRPC: send CSR + OIDC token → receive certificate chain |
| **Rekor** (v1 & v2) | Transparency Log — immutable, append-only ledger of signing metadata | HTTPS REST/gRPC: submit signing metadata → receive `TransparencyLogEntry` with inclusion proof + signed checkpoint |
| **RFC 3161 TSA** | Timestamp Authority — provides trusted timestamps on signatures | HTTPS: send `TimeStampReq` → receive `TimeStampResp` |
| **CT Log** | Certificate Transparency Log — records all issued certificates | Embedded SCTs in Fulcio certs; verified during signing & verification |
| **TUF** | Trust distribution — distributes root certificates, log keys, etc. | Fetch trusted root material (out-of-band) |
| **OIDC IdP** | Identity Provider — authenticates signers | OAuth2/OIDC flows for token acquisition |

### Signing Flow (per client spec)

1. **Authenticate** with OIDC IdP → receive identity token
2. **Generate ephemeral keypair** (ECDSA P-256, Ed25519, etc.)
3. **Request certificate** from Fulcio (CSR + OIDC token) → receive short-lived cert with SCT
4. **Sign the artifact** with ephemeral private key
5. **Timestamp** the signature via RFC 3161 TSA
6. **Submit metadata** to Rekor transparency log → receive log entry with inclusion proof
7. **Package** everything into a Sigstore Bundle (protobuf-based, serialized as JSON)
8. **Destroy** the ephemeral private key

### Verification Flow (per client spec)

1. **Establish time** for the signature from TSA timestamp and/or Rekor log entry
2. **Validate certificate chain** (path validation per RFC 5280 using established time — "hybrid model")
3. **Verify SCT** embedded in the leaf certificate (per RFC 6962)
4. **Check certificate identity** against verification policy (SAN, OIDC issuer)
5. **Verify Rekor log entry** — parse body, check signature/cert/artifact match, verify inclusion proof
6. **Verify signature** on the artifact using the public key from the certificate

### Wire Format

- **Sigstore Bundle** (`application/vnd.dev.sigstore.bundle.v0.3+json`) — the canonical format for distributing verification materials
- Defined via [protobuf-specs](https://github.com/sigstore/protobuf-specs) and serialized to JSON
- Contains: verification material (cert or key), signature, transparency log entries, RFC 3161 timestamps
- File extension: `.sigstore.json`

### Key Data Structures (from protobuf-specs)

- `Bundle` — top-level container
- `VerificationMaterial` — cert chain or public key + tlog entries + timestamps
- `MessageSignature` — digest + raw signature bytes
- `TrustedRoot` — complete set of trusted CAs, logs, TSAs (distributed via TUF)
- `TransparencyLogEntry` — log entry with inclusion proof and checkpoint
- DSSE `Envelope` — for in-toto attestations

### Supported Algorithms

- ECDSA P-256/SHA-256, P-384/SHA-384, P-521/SHA-512
- Ed25519
- RSA PKCS#1v1.5 and PSS (2048, 3072, 4096 with SHA-256)
- ML-DSA-65, ML-DSA-87 (post-quantum, experimental)
- Hash: SHA2-256, SHA2-384, SHA2-512, SHA3-256, SHA3-384

### Existing Implementations (for reference)

- **sigstore-go** — minimal Go client, our closest architectural reference
- **sigstore-python** — full CLI + importable API
- **sigstore-java** — `KeylessSigner` / `KeylessVerifier` builder pattern, good ergonomic reference
- **sigstore-conformance** — official test suite with CLI protocol; we MUST pass this

## Proposed Approach

### Design Principles

1. **Spec-first**: Follow the Sigstore Client Specification faithfully
2. **Extensible**: Abstract service interactions behind interfaces so new algorithms, log formats, or CA providers can be added
3. **Ergonomic**: Builder-pattern APIs (inspired by sigstore-java), sensible defaults, minimal ceremony for common cases
4. **Pure .NET**: Use `System.Security.Cryptography`, `System.Net.Http`, `System.Text.Json` — no native dependencies
5. **Conformance**: Target passing the `sigstore-conformance` test suite from day one
6. **Testable**: All external service interactions behind interfaces for unit testing

### Project Structure

```
sigstore-dotnet/
├── docs/                           # Design documents (source of truth)
│   ├── design-overview.md          # High-level architecture
│   ├── signing-design.md           # Signing workflow details
│   ├── verification-design.md      # Verification workflow details
│   ├── bundle-format.md            # Bundle serialization details
│   ├── trust-root.md               # TUF / trusted root management
│   └── api-surface.md              # Public API design
├── src/
│   └── Sigstore/                   # Main library project (Sigstore.csproj)
│       ├── Signing/                # Signing workflow
│       ├── Verification/           # Verification workflow
│       ├── Bundle/                 # Bundle serialization/deserialization
│       ├── Fulcio/                 # Fulcio client
│       ├── Rekor/                  # Rekor client (v1 + v2)
│       ├── Timestamp/              # RFC 3161 TSA client
│       ├── Transparency/           # Merkle tree / inclusion proof verification
│       ├── TrustRoot/              # Trusted root management (TUF)
│       ├── Oidc/                   # OIDC token acquisition
│       ├── Crypto/                 # Crypto helpers (key generation, cert validation)
│       └── Common/                 # Shared types, enums, constants
├── tests/
│   └── Sigstore.Tests/             # Extensive test suite (Sigstore.Tests.csproj)
│       ├── Signing/                # Signing workflow tests
│       ├── Verification/           # Verification workflow tests
│       ├── Bundle/                 # Bundle round-trip & compatibility tests
│       ├── Fulcio/                 # Fulcio client tests (mocked HTTP)
│       ├── Rekor/                  # Rekor client tests (mocked HTTP)
│       ├── Timestamp/              # RFC 3161 timestamp tests
│       ├── Transparency/           # Merkle proof / inclusion proof tests
│       ├── TrustRoot/              # Trusted root parsing tests
│       ├── Crypto/                 # Crypto helper tests
│       ├── Conformance/            # Tests using sigstore-conformance test vectors
│       └── TestData/               # Embedded test fixtures (bundles, certs, keys)
├── Directory.Build.props
├── sigstore-dotnet.sln
└── README.md
```

### Test Strategy

The `tests/Sigstore.Tests/` project will be the single, comprehensive test project covering all layers:

| Test Category | What It Covers | Approach |
|---------------|----------------|----------|
| **Bundle round-trip** | Serialize → deserialize → re-serialize produces identical JSON | Use real bundles from sigstore-conformance test assets |
| **Bundle compatibility** | Parse v0.1, v0.2, v0.3 bundles | Test vectors from protobuf-specs / conformance suite |
| **Trusted root parsing** | Load and validate TrustedRoot JSON | Use production + staging trusted roots |
| **Certificate validation** | Chain building, hybrid time model, SCT verification | Craft test certs with known validity windows |
| **Merkle proofs** | Inclusion proof verification, checkpoint signature verification | Known-good proofs from Rekor + crafted edge cases |
| **RFC 3161 timestamps** | Parse and verify TSA responses | Real TSA responses + hand-crafted invalid ones |
| **Rekor log entries** | Body parsing, signature/cert/artifact cross-checks | Real log entries from conformance suite |
| **Fulcio client** | CSR generation, certificate response handling | Mocked HTTP responses |
| **Rekor client** | Metadata submission, log entry retrieval | Mocked HTTP responses |
| **TSA client** | TimeStampReq creation, TimeStampResp parsing | Mocked HTTP responses |
| **OIDC** | Token parsing, ambient credential detection | Mocked token endpoints |
| **Signing workflow** | End-to-end signing with all services mocked | Integration-style with dependency injection |
| **Verification workflow** | End-to-end verification with real test vectors | Use sigstore-conformance verification assets |
| **Crypto helpers** | Key generation, signature creation/verification per algorithm | Property-based: sign → verify round-trip for all supported algorithms |
| **Identity policy** | SAN matching, OIDC issuer matching, regex patterns | Parameterized tests with identity/issuer combinations |
| **Error cases** | Expired certs, invalid proofs, tampered bundles, wrong identity | Negative tests for every verification step |
| **Conformance vectors** | Official sigstore-conformance test bundles | Import test vectors, verify expected pass/fail |

Test tooling:
- **xUnit** as the test framework
- **NSubstitute** or **Moq** for mocking interfaces (HTTP clients, service abstractions)
- **FluentAssertions** for readable assertions
- Embedded test data via `EmbeddedResource` in the test project

### API Design Decisions

Based on design discussions, the API follows these principles:

1. **Instance-based** — no static entry points; all operations on instances
2. **Constructor injection** — DI-container friendly; all dependencies are interfaces
3. **Default constructor wires defaults** — `new SigstoreVerifier()` just works out of the box
4. **Three layers** — high-level orchestrators, service client interfaces, pure computation primitives
5. **Dual verification pattern** — `VerifyAsync` throws on failure; `TryVerifyAsync` returns `bool` + result
6. **Layered** — each layer is independently usable; advanced users can compose their own workflows

### Key Public API Surface (Draft)

```csharp
// ============================================================
// LAYER 1: High-level orchestrators
// ============================================================

// --- Verification (the most common operation) ---

// Default constructor wires up production Sigstore public good instance
var verifier = new SigstoreVerifier();

// Or inject custom implementations for any/all dependencies
var verifier = new SigstoreVerifier(
    trustRoot: customTrustRoot,           // optional: custom trusted root
    rekorClient: myRekorClient,           // optional: custom Rekor client
    timestampAuthority: myTsa,            // optional: custom TSA
    certificateValidator: myValidator      // optional: custom cert validation
);

// Define what identity you expect the signer to have
var policy = new VerificationPolicy
{
    CertificateIdentity = new CertificateIdentity
    {
        SubjectAlternativeName = "user@example.com",
        Issuer = "https://accounts.google.com"
    }
};

// Option A: Throws VerificationException on failure (with detailed reason)
VerificationResult result = await verifier.VerifyAsync(artifact, bundle, policy);
// result.SignerIdentity, result.VerifiedTimestamps, result.Certificate, etc.

// Option B: Returns false on failure (no exception)
bool isValid = await verifier.TryVerifyAsync(artifact, bundle, policy, out VerificationResult? result);

// GitHub Actions identity verification (common use case, first-class support)
var policy = new VerificationPolicy
{
    CertificateIdentity = CertificateIdentity.ForGitHubActions(
        repository: "sigstore/sigstore-dotnet",
        issuer: "https://token.actions.githubusercontent.com"
    )
};

// --- Signing ---

// Default constructor wires up production Sigstore public good instance
var signer = new SigstoreSigner();

// Or with custom dependencies
var signer = new SigstoreSigner(
    fulcioClient: myFulcio,
    rekorClient: myRekor,
    timestampAuthority: myTsa,
    tokenProvider: myOidcProvider
);

// Sign an artifact (returns bundle containing all verification material)
SigstoreBundle bundle = await signer.SignAsync(artifactStream);
SigstoreBundle bundle = await signer.SignAsync(filePath);

// DSSE attestation signing (for in-toto statements)
SigstoreBundle bundle = await signer.AttestAsync(inTotoStatement);

// ============================================================
// LAYER 2: Service client interfaces (replaceable via DI)
// ============================================================

// Each external service interaction is behind an interface:

public interface IFulcioClient
{
    Task<CertificateResponse> GetSigningCertificateAsync(
        CertificateRequest request,
        CancellationToken cancellationToken = default);
}

public interface IRekorClient
{
    Task<TransparencyLogEntry> SubmitEntryAsync(
        RekorEntry entry,
        CancellationToken cancellationToken = default);
}

public interface ITimestampAuthority
{
    Task<TimestampResponse> GetTimestampAsync(
        ReadOnlyMemory<byte> signature,
        CancellationToken cancellationToken = default);
}

public interface IOidcTokenProvider
{
    Task<OidcToken> GetTokenAsync(
        CancellationToken cancellationToken = default);
}

public interface ITrustRootProvider
{
    Task<TrustedRoot> GetTrustRootAsync(
        CancellationToken cancellationToken = default);
}

// Default implementations provided:
//   FulcioHttpClient : IFulcioClient
//   RekorHttpClient : IRekorClient
//   Rfc3161TimestampAuthority : ITimestampAuthority
//   AmbientOidcTokenProvider : IOidcTokenProvider  (auto-detects CI environments)
//   InteractiveOidcTokenProvider : IOidcTokenProvider  (browser-based OAuth flow)
//   TufTrustRootProvider : ITrustRootProvider

// ============================================================
// LAYER 3: Pure computation primitives (no I/O)
// ============================================================

// --- Bundle I/O ---
SigstoreBundle bundle = SigstoreBundle.Deserialize(json);
SigstoreBundle bundle = SigstoreBundle.Deserialize(stream);
string json = bundle.Serialize();

// --- Certificate operations ---
public interface ICertificateValidator
{
    CertificateValidationResult ValidateChain(
        X509Certificate2 leaf,
        X509Certificate2Collection chain,
        TrustedRoot trustRoot,
        DateTimeOffset signatureTime);
}

// --- Merkle tree / transparency log ---
public static class MerkleVerifier
{
    public static bool VerifyInclusionProof(InclusionProof proof, ReadOnlySpan<byte> leafHash);
}

// --- Checkpoint verification ---
public static class CheckpointVerifier
{
    public static bool VerifyCheckpoint(SignedCheckpoint checkpoint, TrustedRoot trustRoot);
}

// --- RFC 3161 timestamp parsing (pure ASN.1, no network) ---
public static class TimestampParser
{
    public static TimestampInfo Parse(ReadOnlyMemory<byte> timestampResponse);
    public static bool Verify(TimestampInfo info, ReadOnlyMemory<byte> signature, TrustedRoot trustRoot);
}
```

### Key Design Insights from Existing Implementations

| Decision | Rationale |
|----------|-----------|
| **CancellationToken on all async methods** | Standard .NET async pattern; enables timeout/cancellation |
| **ReadOnlyMemory<byte> / ReadOnlySpan<byte> for binary data** | Zero-copy, avoids unnecessary allocations |
| **CertificateIdentity as a structured type** | Allows exact match, regex, and specialized factories (e.g., `ForGitHubActions`) |
| **VerificationResult as a rich object** | Returns verified identity, timestamps, certificate details — not just bool |
| **VerificationException with structured error** | Includes which step failed and why (expired cert, invalid proof, identity mismatch, etc.) |
| **Separate TrustRoot provider interface** | TUF-based trust root fetching is its own concern; can be cached, overridden, or loaded from disk |
| **Rekor v1 AND v2 support** | v2 is imminent (tile-based log); our interface abstracts the version difference |
| **Ambient OIDC detection** | Auto-detects GitHub Actions, GitLab CI, Google Cloud Build — critical for CI/CD ergonomics |

### .NET Crypto Mapping

| Sigstore Need | .NET API |
|---------------|----------|
| ECDSA P-256 key generation | `ECDsa.Create(ECCurve.NamedCurves.nistP256)` |
| Ed25519 | `System.Security.Cryptography.Ed25519` (.NET 10+) or BouncyCastle fallback |
| RSA | `RSA.Create(keySize)` |
| X.509 cert validation | `X509Chain`, `X509Certificate2` |
| PKCS#10 CSR | `CertificateRequest` class |
| SHA-256/384/512 | `SHA256`, `SHA384`, `SHA512` |
| ASN.1 / DER | `System.Formats.Asn1` |
| RFC 3161 | Manual implementation using ASN.1 APIs |
| Protobuf | Generate C# from protobuf-specs, or hand-craft JSON serialization |

## Implementation Phases

### Phase 1: Foundation & Design Docs
- Set up solution structure, Directory.Build.props, CI
- Create detailed design documents in `docs/`
- Define public API surface and get it reviewed
- Generate or define protobuf message types in C#

### Phase 2: Bundle & Trust Root
- Implement Sigstore Bundle serialization/deserialization
- Implement TrustedRoot parsing
- Implement certificate chain validation helpers

### Phase 3: Verification (Read Path)
- Implement full verification workflow per client spec
- Certificate path validation with hybrid time model
- SCT verification
- Rekor log entry verification (inclusion proofs, signed checkpoints)
- RFC 3161 timestamp verification
- Identity/policy checking
- Target: pass verification conformance tests

### Phase 4: Signing (Write Path)
- OIDC token acquisition (ambient + interactive)
- Fulcio client (CSR generation, certificate retrieval)
- RFC 3161 TSA client
- Rekor client (metadata submission, log entry retrieval)
- Ephemeral key management
- Target: pass signing conformance tests

### Phase 5: Polish & Ship
- NuGet packaging and publishing pipeline
- README, API documentation, samples
- Full conformance test suite integration
- Performance optimization
- Security review

## Current Step: Phase 1 — Design Documents

The immediate next step is to create the `docs/` folder with detailed design documents that will serve as our implementation guide. These documents will capture:

1. **Design Overview** — architecture, component interactions, dependency decisions
2. **API Surface** — the exact public API we want to ship
3. **Signing Design** — step-by-step signing workflow mapped to .NET code
4. **Verification Design** — step-by-step verification workflow mapped to .NET code
5. **Bundle Format** — how we'll serialize/deserialize the Sigstore bundle
6. **Trust Root** — how we'll manage TUF-distributed trust material
