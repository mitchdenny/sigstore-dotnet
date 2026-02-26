# Samples

Self-contained sample applications demonstrating how to use the `Sigstore` library.

Each sample is a standalone console app that can be run with `dotnet run`.

## Samples

| Sample | Description |
|--------|-------------|
| [VerifyBundle](VerifyBundle/) | Load a `.sigstore.json` bundle and verify it against an artifact with an identity policy |
| [SignArtifact](SignArtifact/) | Sign a file using Sigstore keyless signing and write the bundle to disk |
| [VerifyGitHubActions](VerifyGitHubActions/) | Verify a bundle signed by a GitHub Actions workflow |
| [VerifyWithCustomTrustRoot](VerifyWithCustomTrustRoot/) | Verify using a custom trusted root (private Sigstore instance) |
| [SignAndVerifyRoundTrip](SignAndVerifyRoundTrip/) | Sign a file then immediately verify the result |

## Running

```bash
# From the repository root:
cd samples/VerifyBundle
dotnet run -- <artifact> <bundle.sigstore.json> <identity> <issuer>
```

## Prerequisites

Each sample references the `Sigstore` library via `ProjectReference`. Build from the repository root first:

```bash
dotnet build sigstore-dotnet.slnx
```
