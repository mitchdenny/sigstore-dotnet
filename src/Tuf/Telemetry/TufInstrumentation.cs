using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Tuf;

internal static class TufInstrumentation
{
    private static readonly Histogram<double> MetadataRefreshDuration =
        TufTelemetry.Meter.CreateHistogram<double>(
            "tuf.metadata.refresh.duration",
            "s",
            "Duration of TUF trusted metadata refresh operations.");

    private static readonly TufActiveOperationTracker MetadataRefreshActive =
        new(
            "tuf.metadata.refresh.active",
            "Number of TUF trusted metadata refresh operations currently in progress.");

    private static readonly Histogram<double> MetadataRefreshQueueDuration =
        TufTelemetry.Meter.CreateHistogram<double>(
            "tuf.metadata.refresh.queue.duration",
            "s",
            "Time TUF trusted metadata refresh operations spend waiting for the client operation gate.");

    private static readonly Histogram<double> TargetGetDuration =
        TufTelemetry.Meter.CreateHistogram<double>(
            "tuf.target.get.duration",
            "s",
            "Duration of TUF target acquisition and verification operations.");

    private static readonly TufActiveOperationTracker TargetGetActive =
        new(
            "tuf.target.get.active",
            "Number of TUF target acquisition and verification operations currently in progress.");

    private static readonly Histogram<double> TargetGetQueueDuration =
        TufTelemetry.Meter.CreateHistogram<double>(
            "tuf.target.get.queue.duration",
            "s",
            "Time TUF target operations spend waiting for the client operation gate.");

    private static readonly Histogram<long> TargetSize =
        TufTelemetry.Meter.CreateHistogram<long>(
            "tuf.target.size",
            "By",
            "Size of verified TUF targets.");

    internal static TufTelemetryOperation StartMetadataRefresh() =>
        StartOperation(
            "tuf.metadata.refresh",
            MetadataRefreshDuration,
            MetadataRefreshActive);

    internal static TufTelemetryOperation StartTargetGet() =>
        StartOperation(
            "tuf.target.get",
            TargetGetDuration,
            TargetGetActive);

    internal static void RecordMetadataRefreshQueue(
        long startedAt,
        string? errorType = null) =>
        RecordQueueDuration(MetadataRefreshQueueDuration, startedAt, errorType);

    internal static void RecordTargetGetQueue(
        long startedAt,
        string? errorType = null) =>
        RecordQueueDuration(TargetGetQueueDuration, startedAt, errorType);

    internal static void RecordTargetSize(long size, bool cacheHit)
    {
        if (!TargetSize.Enabled)
        {
            return;
        }

        TagList tags = default;
        tags.Add("tuf.target.cache_hit", cacheHit);
        TargetSize.Record(size, in tags);
    }

    internal static Activity? StartActivity(string name)
    {
        return TufTelemetry.ActivitySource.StartActivity(
            name,
            ActivityKind.Internal);
    }

    internal static Activity? StartActivity(string name, TagList tags)
    {
        return TufTelemetry.ActivitySource.StartActivity(
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
        exception switch
        {
            OperationCanceledException when cancellationToken.IsCancellationRequested => "cancelled",
            OperationCanceledException => "timeout",
            TufExpiredException => "expired",
            _ => exception.GetType().FullName ?? exception.GetType().Name
        };

    private static TufTelemetryOperation StartOperation(
        string activityName,
        Histogram<double> duration,
        TufActiveOperationTracker active)
    {
        TufTelemetryOperationState? state = null;
        if (TufTelemetry.ActivitySource.HasListeners() ||
            duration.Enabled)
        {
            state = new TufTelemetryOperationState(
                activityName,
                duration);
        }

        return new TufTelemetryOperation(active, state);
    }

    private static void RecordQueueDuration(
        Histogram<double> histogram,
        long startedAt,
        string? errorType)
    {
        if (!histogram.Enabled)
        {
            return;
        }

        TagList tags = default;
        if (errorType is not null)
        {
            tags.Add("error.type", errorType);
        }

        histogram.Record(
            Stopwatch.GetElapsedTime(startedAt).TotalSeconds,
            in tags);
    }
}

internal readonly struct TufTelemetryOperation : IDisposable
{
    private readonly TufActiveOperationTracker _active;
    private readonly TufTelemetryOperationState? _state;

    internal TufTelemetryOperation(
        TufActiveOperationTracker active,
        TufTelemetryOperationState? state)
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
        SetError(TufInstrumentation.GetErrorType(exception, cancellationToken));

    public void Dispose()
    {
        _state?.Dispose();
        _active.Decrement();
    }
}

internal sealed class TufTelemetryOperationState : IDisposable
{
    private readonly Histogram<double> _duration;
    private readonly Activity? _activity;
    private readonly long _startedAt;
    private TagList _tags;
    private bool _disposed;
    private bool _failed;

    internal TufTelemetryOperationState(
        string activityName,
        Histogram<double> duration)
    {
        _duration = duration;
        _startedAt = Stopwatch.GetTimestamp();
        _activity = TufTelemetry.ActivitySource.StartActivity(
            activityName,
            ActivityKind.Internal);
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

internal sealed class TufActiveOperationTracker
{
    private readonly ObservableGauge<long> _instrument;
    private long _count;

    internal TufActiveOperationTracker(
        string name,
        string description)
    {
        _instrument = TufTelemetry.Meter.CreateObservableGauge(
            name,
            Observe,
            "{operation}",
            description);
    }

    internal void Increment() => Interlocked.Increment(ref _count);

    internal void Decrement() => Interlocked.Decrement(ref _count);

    private long Observe() => Interlocked.Read(ref _count);
}
