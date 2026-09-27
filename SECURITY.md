# Security Policy

## Supported Versions

Security fixes are provided for the latest stable release of sigstore-dotnet,
including the `Sigstore` and `Tuf` packages.

| Version | Supported |
| --- | --- |
| Latest stable release | Yes |
| Older stable releases | Best effort only |
| Preview, prerelease, or pull-request packages | Best effort only |

Please upgrade to the latest stable release before reporting a vulnerability that
may already have been fixed.

## Reporting a Vulnerability

Please do not open a public GitHub issue for anything you believe may have a
security impact.

Report suspected vulnerabilities privately by using GitHub's private
vulnerability reporting for this repository:

<https://github.com/mitchdenny/sigstore-dotnet/security/advisories/new>

Include as much detail as you can safely provide:

- The affected package, sample, or component.
- The sigstore-dotnet package version or commit SHA you tested.
- Your operating system and .NET SDK or runtime version, if relevant.
- Steps to reproduce the issue.
- The expected and actual behavior.
- A proof of concept, logs, or sample artifacts and bundles, if they help explain the impact.
- Whether you used the Sigstore public good instance or a custom trust root and services.
- Whether the issue is already public or known to be actively exploited.

Do not include private keys, OIDC tokens, credentials, or other secrets in your
report. Use sanitized or synthetic artifacts and configuration where possible.

## What to Expect

You should receive an initial response within 7 days. After that, maintainers
will work with you to understand the issue, confirm affected versions, assess
severity, and coordinate a fix and disclosure timeline.

When a vulnerability is confirmed, fixes will be released through the normal
release process and documented in the appropriate advisory, release notes, or
both. Please avoid public disclosure until a fix is available and the advisory
has been published, unless we agree on another timeline.

## Bug Bounty

sigstore-dotnet does not currently offer a paid bug bounty program. Responsible reports
are appreciated and may be acknowledged publicly with the reporter's permission.
