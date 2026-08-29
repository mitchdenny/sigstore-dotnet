// Copyright (c) Sigstore contributors. Licensed under the Apache 2.0 license.
//
// The suite runs strictly serially: one test at a time, no parallelism.
// This trades wall-clock time for isolation, so tests are free to touch
// ambient state (telemetry listeners, environment, the filesystem) without
// coordinating with each other.

[assembly: DoNotParallelize]
