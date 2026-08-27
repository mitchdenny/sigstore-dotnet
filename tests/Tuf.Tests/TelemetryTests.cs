using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Tuf.Tests;

[TestClass]
public sealed class TelemetryTests
{
    [TestMethod]
    public async Task TargetGetEmitsActivitiesAndMetricsForCacheMissAndHit()
    {
        using var activityListener = CreateActivityListener(out var activities);
        using var meterListener = CreateMeterListener(
            out var measurements,
            out var instruments);
        using var parent = new Activity("telemetry-test")
            .SetIdFormat(ActivityIdFormat.W3C)
            .Start();

        var repository = new RepositorySimulator();
        var content = "target-content"u8.ToArray();
        repository.AddTarget("target.txt", content);
        repository.BumpNonRootVersions();
        using var client = new TufClient(new TufClientOptions
        {
            MetadataBaseUrl = new Uri("https://example.com/metadata/"),
            TrustedRoot = repository.GetInitialRoot(),
            Repository = repository,
            Cache = new InMemoryTufCache()
        });

        await client.GetTargetAsync("target.txt");
        await client.GetTargetAsync("target.txt");
        meterListener.RecordObservableInstruments();

        var traceActivities = activities
            .Where(activity => activity.TraceId == parent.TraceId)
            .ToList();
        var targetGets = traceActivities
            .Where(activity => activity.OperationName == "tuf.target.get")
            .ToList();
        Assert.AreEqual(2, targetGets.Count);
        Assert.Contains(
            activity => Equals(
                activity.GetTagItem("tuf.target.cache_hit"),
                false),
            targetGets);
        Assert.Contains(
            activity => Equals(
                activity.GetTagItem("tuf.target.cache_hit"),
                true),
            targetGets);

        var refreshes = traceActivities
            .Where(activity =>
                activity.OperationName == "tuf.metadata.refresh")
            .ToList();
        Assert.AreEqual(2, refreshes.Count);
        TestSeq.All(
            refreshes,
            refresh => Assert.Contains(
                target => target.SpanId == refresh.ParentSpanId,
                targetGets));
        Assert.Contains(
            activity => activity.OperationName == "tuf.metadata.root.update",
            traceActivities);
        Assert.Contains(
            activity => activity.OperationName == "tuf.target.resolve",
            traceActivities);

        var targetDurations = measurements
            .Where(measurement =>
                measurement.Name == "tuf.target.get.duration")
            .ToList();
        Assert.Contains(
            measurement => Equals(
                measurement.Tags["tuf.target.cache_hit"],
                false),
            targetDurations);
        Assert.Contains(
            measurement => Equals(
                measurement.Tags["tuf.target.cache_hit"],
                true),
            targetDurations);
        Assert.IsTrue(
            measurements.Count(measurement =>
                measurement.Name == "tuf.metadata.refresh.duration") >= 2);
        Assert.IsTrue(
            measurements.Count(measurement =>
                measurement.Name == "tuf.target.get.queue.duration") >= 2);
        Assert.Contains(
            measurement =>
                measurement.Name == "tuf.target.size" &&
                measurement.Value == content.Length &&
                Equals(
                    measurement.Tags["tuf.target.cache_hit"],
                    false),
            measurements);
        Assert.Contains(
            measurement =>
                measurement.Name == "tuf.target.size" &&
                measurement.Value == content.Length &&
                Equals(
                    measurement.Tags["tuf.target.cache_hit"],
                    true),
            measurements);

        Assert.Contains("tuf.metadata.refresh.duration", instruments);
        Assert.Contains("tuf.metadata.refresh.active", instruments);
        Assert.Contains("tuf.target.get.duration", instruments);
        Assert.Contains("tuf.target.get.active", instruments);
        Assert.Contains("tuf.target.size", instruments);
        Assert.Contains(
            measurement =>
                measurement.Name == "tuf.target.get.active" &&
                measurement.Value == 0,
            measurements);
    }

    [TestMethod]
    public async Task ExpiredMetadataSetsErrorType()
    {
        using var activityListener = CreateActivityListener(out var activities);
        using var meterListener = CreateMeterListener(
            out var measurements,
            out _);
        using var parent = new Activity("telemetry-test")
            .SetIdFormat(ActivityIdFormat.W3C)
            .Start();

        var repository = new RepositorySimulator();
        repository.ExpiredRoles.Add("timestamp");
        repository.PublishAll();
        using var client = new TufClient(new TufClientOptions
        {
            MetadataBaseUrl = new Uri("https://example.com/metadata/"),
            TrustedRoot = repository.GetInitialRoot(),
            Repository = repository
        });

        await Assert.ThrowsExactlyAsync<TufExpiredException>(
            () => client.GetTrustedMetadataAsync());

        var refresh = TestSeq.Single(
            activities,
            activity =>
                activity.TraceId == parent.TraceId &&
                activity.OperationName == "tuf.metadata.refresh");
        Assert.AreEqual(ActivityStatusCode.Error, refresh.Status);
        Assert.AreEqual("expired", refresh.GetTagItem("error.type"));
        Assert.Contains(
            measurement =>
                measurement.Name == "tuf.metadata.refresh.duration" &&
                Equals(measurement.Tags["error.type"], "expired"),
            measurements);
    }

    private static ActivityListener CreateActivityListener(
        out ConcurrentQueue<Activity> activities)
    {
        activities = new ConcurrentQueue<Activity>();
        var capturedActivities = activities;
        var listener = new ActivityListener
        {
            ShouldListenTo = source =>
                source.Name == TufTelemetry.ActivitySourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) =>
                ActivitySamplingResult.AllDataAndRecorded,
            SampleUsingParentId =
                (ref ActivityCreationOptions<string> _) =>
                    ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = capturedActivities.Enqueue
        };
        ActivitySource.AddActivityListener(listener);
        return listener;
    }

    private static MeterListener CreateMeterListener(
        out ConcurrentQueue<MetricMeasurement> measurements,
        out ConcurrentQueue<string> instruments)
    {
        measurements = new ConcurrentQueue<MetricMeasurement>();
        instruments = new ConcurrentQueue<string>();
        var capturedMeasurements = measurements;
        var capturedInstruments = instruments;
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, meterListener) =>
            {
                if (instrument.Meter.Name != TufTelemetry.MeterName)
                {
                    return;
                }

                capturedInstruments.Enqueue(instrument.Name);
                meterListener.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<double>(
            (instrument, value, tags, _) =>
                capturedMeasurements.Enqueue(
                    new MetricMeasurement(
                        instrument.Name,
                        value,
                        CopyTags(tags))));
        listener.SetMeasurementEventCallback<long>(
            (instrument, value, tags, _) =>
                capturedMeasurements.Enqueue(
                    new MetricMeasurement(
                        instrument.Name,
                        value,
                        CopyTags(tags))));
        listener.Start();
        return listener;
    }

    private static IReadOnlyDictionary<string, object?> CopyTags(
        ReadOnlySpan<KeyValuePair<string, object?>> tags)
    {
        var copy = new Dictionary<string, object?>(tags.Length);
        foreach (var tag in tags)
        {
            copy[tag.Key] = tag.Value;
        }

        return copy;
    }

    private sealed record MetricMeasurement(
        string Name,
        double Value,
        IReadOnlyDictionary<string, object?> Tags);
}
