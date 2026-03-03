# Tuf

A .NET implementation of [The Update Framework (TUF)](https://theupdateframework.io/) client for secure software update verification.

## Overview

`Tuf` provides a standards-compliant TUF client that securely downloads and verifies metadata from a TUF repository. It handles the full metadata verification workflow including root rotation, timestamp/snapshot freshness checks, and signature validation.

## Features

- **TUF specification compliant** — implements the client workflow from the [TUF specification](https://theupdateframework.github.io/specification/latest/)
- **Secure root rotation** — safely updates trust anchors across key rotations
- **Metadata verification** — validates signatures, expiration, and version consistency
- **Pluggable caching** — in-memory and file-system cache implementations included
- **Pluggable repository** — HTTP repository included, custom transports supported
- **AOT-compatible** — fully trimmer and NativeAOT safe

## Quick Start

```csharp
using Tuf;

// Create a TUF client with HTTP repository and file-system cache
var options = new TufClientOptions
{
    RepositoryUri = new Uri("https://tuf-repo-cdn.sigstore.dev"),
    Cache = new FileSystemTufCache("/path/to/cache")
};

var client = new TufClient(options);

// Refresh metadata (downloads and verifies latest metadata)
await client.RefreshAsync();
```

## Documentation

📖 [Full documentation](https://mitchdenny.github.io/sigstore-dotnet/)

## License

MIT — see [LICENSE](https://github.com/mitchdenny/sigstore-dotnet/blob/main/LICENSE).
