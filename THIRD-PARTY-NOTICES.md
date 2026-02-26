# Third-Party Notices

This project incorporates components from the projects listed below.

---

## NSec.Cryptography

- **Version:** 25.4.0
- **License:** MIT
- **Project:** https://github.com/ektrah/nsec
- **Copyright:** Copyright (c) 2025 Klaus Hartke

NSec.Cryptography is used for Ed25519 signature verification.

NSec itself includes code from libsodium (ISC License), RFC 6234 (Simplified BSD),
.NET Runtime (MIT), and Steve Thomas's hex/base64 implementation (MIT).
See the NSec NOTICE file for full details:
https://github.com/ektrah/nsec/blob/main/NOTICE

---

## libsodium

- **Version:** 1.0.20.1
- **License:** ISC
- **Project:** https://github.com/jedisct1/libsodium
- **Copyright:** Copyright (c) 2013-2025 Frank Denis

Transitive native dependency of NSec.Cryptography.

> Permission to use, copy, modify, and/or distribute this software for any
> purpose with or without fee is hereby granted, provided that the above
> copyright notice and this permission notice appear in all copies.
>
> THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
> WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
> MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
> ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
> WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
> ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
> OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

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
