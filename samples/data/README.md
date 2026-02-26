# Sample Data

Real-world Sigstore attestation data from the npm registry for use with the sample applications.

## Files

| File | Description |
|------|-------------|
| `playwright-cli-0.1.1.tgz` | The `@playwright/cli@0.1.1` npm package tarball |
| `playwright-cli-0.1.1-attestations.json` | Raw npm attestations response containing both bundles |
| `playwright-cli-0.1.1-provenance.sigstore.json` | SLSA provenance bundle (v0.3) — extracted standalone Sigstore bundle |
| `playwright-cli-0.1.1-publish.sigstore.json` | npm publish attestation bundle (v0.2) — extracted standalone Sigstore bundle |

## Source

Downloaded from the npm registry:
- Package: `https://registry.npmjs.org/@playwright/cli/-/cli-0.1.1.tgz`
- Attestations: `https://registry.npmjs.org/-/npm/v1/attestations/@playwright%2fcli@0.1.1`

## Usage

The `VerifyBundle` sample can verify these bundles:

```bash
cd samples/VerifyBundle
dotnet run -- ../data/playwright-cli-0.1.1.tgz ../data/playwright-cli-0.1.1-provenance.sigstore.json \
  "https://github.com/nicolo-ribaudo/nicolo-nicolo-nicolo/<workflow>" \
  "https://token.actions.githubusercontent.com"
```
