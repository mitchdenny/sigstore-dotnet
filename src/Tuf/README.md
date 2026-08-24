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
- **OpenTelemetry-ready** — emits native .NET activities and metrics without an exporter dependency

## Quick Start

```csharp
using Tuf;

// Create a TUF client with HTTP repository and file-system cache
var options = new TufClientOptions
{
    MetadataBaseUrl = new Uri("https://tuf-repo-cdn.sigstore.dev/"),
    TargetsBaseUrl = new Uri("https://tuf-repo-cdn.sigstore.dev/targets/"),
    TrustedRoot = await File.ReadAllBytesAsync("root.json"),
    Cache = new FileSystemTufCache("/path/to/cache")
};

var client = new TufClient(options);

// Get and verify the current trusted metadata
var metadata = await client.GetTrustedMetadataAsync();
```

## Telemetry

The package emits diagnostics through the built-in `System.Diagnostics`
APIs. Applications choose how to collect and export them; the package does not
initialize OpenTelemetry or install an exporter.

```csharp
services.AddOpenTelemetry()
    .WithTracing(tracing =>
        tracing.AddSource(TufTelemetry.ActivitySourceName))
    .WithMetrics(metrics =>
        metrics.AddMeter(TufTelemetry.MeterName));
```

The `Tuf` activity source emits `tuf.metadata.refresh` and `tuf.target.get`
activities. Metadata role updates, repository fetches, and delegated target
resolution appear as child activities.

The package emits these metrics:

- `tuf.metadata.refresh.duration`, `tuf.metadata.refresh.active`, and
  `tuf.metadata.refresh.queue.duration`
- `tuf.target.get.duration`, `tuf.target.get.active`, and
  `tuf.target.get.queue.duration`
- `tuf.target.size`

Duration instruments use seconds and target size uses bytes. Target
measurements include the bounded `tuf.target.cache_hit` attribute. Failed
operations include the standard `error.type` attribute. Target paths,
delegated role names, key IDs, hashes, and repository URLs are not emitted as
telemetry attributes.

Enable the standard .NET HTTP client instrumentation alongside this source to
observe individual network requests without duplicate TUF HTTP metrics.

## Documentation

📖 [Full documentation](https://mitchdenny.github.io/sigstore-dotnet/)

## License

MIT — see [LICENSE](https://github.com/mitchdenny/sigstore-dotnet/blob/main/LICENSE).
