# Third-Party Notices

This project incorporates components from the projects listed below.

---

## BouncyCastle.Cryptography

- **Version:** 2.7.0
- **License:** MIT
- **Project:** https://github.com/bcgit/bc-csharp
- **Copyright:** Copyright (c) 2000-2026 Legion of the Bouncy Castle Inc.

BouncyCastle.Cryptography is used for managed Ed25519 signature verification.

---

## sigstore-conformance (test submodule)

- **Project:** https://github.com/sigstore/sigstore-conformance
- **License:** Apache-2.0 (Sigstore project)
- **Usage:** Test data only — not included in the published NuGet package

The `tests/sigstore-conformance` Git submodule contains conformance test
vectors from the Sigstore project. This data is used exclusively for testing
and is not redistributed in the NuGet package.

---

## @playwright/cli (sample data)

- **Version:** 0.1.1
- **License:** Apache-2.0
- **Copyright:** Copyright (c) Microsoft Corporation
- **Usage:** Sample data only — not included in the published NuGet package

The file `samples/data/playwright-cli-0.1.1.tgz` and its associated
attestation files are included as sample data to demonstrate Sigstore
bundle verification. These files are not redistributed in the NuGet package.
