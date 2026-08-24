using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Sigstore;

internal static class SigstoreInstrumentation
{
    private static readonly Histogram<double> SignDuration =
        SigstoreTelemetry.Meter.CreateHistogram<double>(
            "sigstore.sign.duration",
            "s",
            "Duration of Sigstore artifact signing.");

    private static readonly SigstoreActiveOperationTracker SignActive =
        new(
            "sigstore.sign.active",
            "Number of Sigstore artifact signing operations currently in progress.");

    private static readonly Histogram<double> AttestDuration =
        SigstoreTelemetry.Meter.CreateHistogram<double>(
            "sigstore.attest.duration",
            "s",
            "Duration of Sigstore attestation signing.");

    private static readonly SigstoreActiveOperationTracker AttestActive =
        new(
            "sigstore.attest.active",
            "Number of Sigstore attestation signing operations currently in progress.");

    private static readonly Histogram<double> VerifyDuration =
        SigstoreTelemetry.Meter.CreateHistogram<double>(
            "sigstore.verify.duration",
            "s",
            "Duration of Sigstore bundle verification.");

    private static readonly SigstoreActiveOperationTracker VerifyActive =
        new(
            "sigstore.verify.active",
            "Number of Sigstore bundle verification operations currently in progress.");

    internal static SigstoreTelemetryOperation StartSign() =>
        StartOperation("sigstore.sign", SignDuration, SignActive);

    internal static SigstoreTelemetryOperation StartAttest() =>
        StartOperation("sigstore.attest", AttestDuration, AttestActive);

    internal static SigstoreTelemetryOperation StartVerify(
        string inputType,
        VerificationPolicy policy,
        SigstoreBundle? bundle = null)
    {
        TagList tags = default;
        tags.Add("sigstore.verify.input_type", inputType);
        tags.Add(
            "sigstore.verification.material",
            policy.PublicKey is null ? "certificate" : "public_key");
        if (bundle is not null)
        {
            tags.Add("sigstore.bundle.type", GetBundleType(bundle));
        }

        return StartOperation(
            "sigstore.verify",
            VerifyDuration,
            VerifyActive,
            tags);
    }

    internal static Activity? StartActivity(string name)
    {
        return SigstoreTelemetry.ActivitySource.StartActivity(
            name,
            ActivityKind.Internal);
    }

    internal static Activity? StartActivity(string name, TagList tags)
    {
        return SigstoreTelemetry.ActivitySource.StartActivity(
            name,
            ActivityKind.Internal,
            parentContext: default,
            tags);
    }

    internal static void SetError(
        Activity? activity,
        Exception exception,
        CancellationToken cancellationToken)
    {
        if (activity is null)
        {
            return;
        }

        activity.SetTag("error.type", GetErrorType(exception, cancellationToken));
        activity.SetStatus(ActivityStatusCode.Error);
    }

    internal static void SetError(Activity? activity, string errorType)
    {
        if (activity is null)
        {
            return;
        }

        activity.SetTag("error.type", errorType);
        activity.SetStatus(ActivityStatusCode.Error);
    }

    internal static string GetErrorType(
        Exception exception,
        CancellationToken cancellationToken) =>
        exception is OperationCanceledException
            ? cancellationToken.IsCancellationRequested ? "cancelled" : "timeout"
            : exception.GetType().FullName ?? exception.GetType().Name;

    internal static string GetBundleType(SigstoreBundle bundle) =>
        bundle.MessageSignature is not null
            ? "message_signature"
            : bundle.DsseEnvelope is not null
                ? "dsse"
                : "unknown";

    private static SigstoreTelemetryOperation StartOperation(
        string activityName,
        Histogram<double> duration,
        SigstoreActiveOperationTracker active,
        TagList tags = default)
    {
        SigstoreTelemetryOperationState? state = null;
        if (SigstoreTelemetry.ActivitySource.HasListeners() ||
            duration.Enabled)
        {
            state = new SigstoreTelemetryOperationState(
                activityName,
                duration,
                tags);
        }

        return new SigstoreTelemetryOperation(active, state);
    }
}

internal readonly struct SigstoreTelemetryOperation : IDisposable
{
    private readonly SigstoreActiveOperationTracker _active;
    private readonly SigstoreTelemetryOperationState? _state;

    internal SigstoreTelemetryOperation(
        SigstoreActiveOperationTracker active,
        SigstoreTelemetryOperationState? state)
    {
        _active = active;
        _state = state;
        active.Increment();
    }

    internal void SetTag(string name, object? value) =>
        _state?.SetTag(name, value);

    internal void SetError(string errorType) =>
        _state?.SetError(errorType);

    internal void SetError(
        Exception exception,
        CancellationToken cancellationToken) =>
        SetError(SigstoreInstrumentation.GetErrorType(exception, cancellationToken));

    public void Dispose()
    {
        _state?.Dispose();
        _active.Decrement();
    }
}

internal sealed class SigstoreTelemetryOperationState : IDisposable
{
    private readonly Histogram<double> _duration;
    private readonly Activity? _activity;
    private readonly long _startedAt;
    private TagList _tags;
    private bool _disposed;
    private bool _failed;

    internal SigstoreTelemetryOperationState(
        string activityName,
        Histogram<double> duration,
        TagList tags)
    {
        _duration = duration;
        _tags = tags;
        _startedAt = Stopwatch.GetTimestamp();
        _activity = SigstoreTelemetry.ActivitySource.StartActivity(
            activityName,
            ActivityKind.Internal,
            parentContext: default,
            tags);
    }

    internal void SetTag(string name, object? value)
    {
        _activity?.SetTag(name, value);
        _tags.Add(name, value);
    }

    internal void SetError(string errorType)
    {
        if (_failed)
        {
            return;
        }

        _failed = true;
        _activity?.SetTag("error.type", errorType);
        _activity?.SetStatus(ActivityStatusCode.Error);
        _tags.Add("error.type", errorType);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_duration.Enabled)
        {
            _duration.Record(
                Stopwatch.GetElapsedTime(_startedAt).TotalSeconds,
                in _tags);
        }

        _activity?.Dispose();
    }
}

internal sealed class SigstoreActiveOperationTracker
{
    private readonly ObservableGauge<long> _instrument;
    private long _count;

    internal SigstoreActiveOperationTracker(
        string name,
        string description)
    {
        _instrument = SigstoreTelemetry.Meter.CreateObservableGauge(
            name,
            Observe,
            "{operation}",
            description);
    }

    internal void Increment() => Interlocked.Increment(ref _count);

    internal void Decrement() => Interlocked.Decrement(ref _count);

    private long Observe() => Interlocked.Read(ref _count);
}
