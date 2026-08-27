using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Sigstore.Tests;

[TestClass]
// The *.active gauges report a process-global in-flight count, so these
// assertions only hold when nothing else is exercising the library at the
// same time. Measurement attribution is handled by the TraceId filter in
// CreateMeterListener, but a global count cannot be filtered, so this class
// has to run on its own.
[DoNotParallelize]
public sealed class TelemetryTests
{
    [TestMethod]
    public async Task VerifyFailureEmitsActivityAndMetrics()
    {
        using var parent = new Activity("telemetry-test")
            .SetIdFormat(ActivityIdFormat.W3C)
            .Start();
        parent.AddBaggage("telemetry-test", "inherited");
        using var activityListener = CreateActivityListener(out var activities);
        using var meterListener = CreateMeterListener(
            parent.TraceId,
            out var measurements,
            out var instruments);

        var verifier = new SigstoreVerifier(
            new InMemoryTrustRootProvider(new TrustedRoot()));
        using var artifact = new MemoryStream("artifact"u8.ToArray());

        var (success, _) = await verifier.TryVerifyStreamAsync(
            artifact,
            new SigstoreBundle(),
            new VerificationPolicy());
        meterListener.RecordObservableInstruments();

        Assert.IsFalse(success);

        var verify = TestSeq.Single(
            activities,
            activity =>
                activity.TraceId == parent.TraceId &&
                activity.OperationName == "sigstore.verify");
        Assert.AreEqual(ActivityStatusCode.Error, verify.Status);
        Assert.AreSame(parent, verify.Parent);
        Assert.AreEqual("inherited", verify.GetBaggageItem("telemetry-test"));
        Assert.AreEqual("bundle_invalid", verify.GetTagItem("error.type"));
        Assert.AreEqual("stream", verify.GetTagItem("sigstore.verify.input_type"));
        Assert.AreEqual("unknown", verify.GetTagItem("sigstore.bundle.type"));
        Assert.AreEqual(
            "certificate",
            verify.GetTagItem("sigstore.verification.material"));

        var duration = TestSeq.Single(
            measurements,
            measurement =>
                measurement.Name == "sigstore.verify.duration");
        Assert.AreEqual("bundle_invalid", duration.Tags["error.type"]);
        Assert.AreEqual("stream", duration.Tags["sigstore.verify.input_type"]);
        Assert.Contains(
            measurement =>
                measurement.Name == "sigstore.verify.active" &&
                measurement.Value == 0,
            measurements);

        Assert.Contains("sigstore.sign.duration", instruments);
        Assert.Contains("sigstore.sign.active", instruments);
        Assert.Contains("sigstore.attest.duration", instruments);
        Assert.Contains("sigstore.attest.active", instruments);
        Assert.Contains("sigstore.verify.duration", instruments);
        Assert.Contains("sigstore.verify.active", instruments);
    }

    [TestMethod]
    public async Task SignFailureEmitsNestedOidcActivity()
    {
        using var parent = new Activity("telemetry-test")
            .SetIdFormat(ActivityIdFormat.W3C)
            .Start();
        using var activityListener = CreateActivityListener(out var activities);
        using var meterListener = CreateMeterListener(
            parent.TraceId,
            out var measurements,
            out _);

        var tokenProvider = new BlockingTokenProvider();
        var signer = new SigstoreSigner(
            new UnusedFulcioClient(),
            new UnusedRekorClient(),
            new UnusedTimestampAuthority(),
            tokenProvider);
        using var artifact = new MemoryStream("artifact"u8.ToArray());

        var signTask = signer.SignAsync(artifact);
        await tokenProvider.Started.WaitAsync(TimeSpan.FromSeconds(5));
        meterListener.RecordObservableInstruments();
        tokenProvider.Fail(new InvalidOperationException("Token acquisition failed."));
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => signTask);
        meterListener.RecordObservableInstruments();

        var traceActivities = activities
            .Where(activity => activity.TraceId == parent.TraceId)
            .ToList();
        var sign = TestSeq.Single(
            traceActivities,
            activity => activity.OperationName == "sigstore.sign");
        var oidc = TestSeq.Single(
            traceActivities,
            activity =>
                activity.OperationName == "sigstore.oidc.token.get");

        Assert.AreEqual(sign.SpanId, oidc.ParentSpanId);
        Assert.AreEqual(ActivityStatusCode.Error, sign.Status);
        Assert.AreEqual(ActivityStatusCode.Error, oidc.Status);
        Assert.AreEqual(
            typeof(InvalidOperationException).FullName,
            sign.GetTagItem("error.type"));
        Assert.Contains(
            measurement =>
                measurement.Name == "sigstore.sign.duration" &&
                Equals(
                    measurement.Tags["error.type"],
                    typeof(InvalidOperationException).FullName),
            measurements);
        Assert.Contains(
            measurement =>
                measurement.Name == "sigstore.sign.active" &&
                measurement.Value == 1,
            measurements);
        Assert.Contains(
            measurement =>
                measurement.Name == "sigstore.sign.active" &&
                measurement.Value == 0,
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
                source.Name == SigstoreTelemetry.ActivitySourceName,
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
        ActivityTraceId traceId,
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
                if (instrument.Meter.Name != SigstoreTelemetry.MeterName)
                {
                    return;
                }

                capturedInstruments.Enqueue(instrument.Name);
                meterListener.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<double>(
            (instrument, value, tags, _) =>
                Capture(instrument.Name, value, tags));
        listener.SetMeasurementEventCallback<long>(
            (instrument, value, tags, _) =>
                Capture(instrument.Name, value, tags));
        listener.Start();
        return listener;

        // The Meter is process-wide, so without this filter a concurrently
        // running test's measurements would land in our queue. Durations are
        // recorded before the owning activity is disposed, and observable
        // instruments are sampled by the test itself, so in both cases
        // Activity.Current still belongs to the test that caused the
        // measurement.
        void Capture(
            string name,
            double value,
            ReadOnlySpan<KeyValuePair<string, object?>> tags)
        {
            if (Activity.Current?.TraceId != traceId)
            {
                return;
            }

            capturedMeasurements.Enqueue(
                new MetricMeasurement(name, value, CopyTags(tags)));
        }
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

    private sealed class BlockingTokenProvider : IOidcTokenProvider
    {
        private readonly TaskCompletionSource _started =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<OidcToken> _completion =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        internal Task Started => _started.Task;

        internal void Fail(Exception exception) =>
            _completion.SetException(exception);

        public async Task<OidcToken> GetTokenAsync(
            CancellationToken cancellationToken = default)
        {
            _started.SetResult();
            return await _completion.Task.WaitAsync(cancellationToken);
        }
    }

    private sealed class UnusedFulcioClient : IFulcioClient
    {
        public Task<FulcioCertificateResponse> GetSigningCertificateAsync(
            FulcioCertificateRequest request,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class UnusedRekorClient : IRekorClient
    {
        public Task<TransparencyLogEntry> SubmitEntryAsync(
            RekorEntry entry,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<TransparencyLogEntry> SubmitDsseEntryAsync(
            RekorDsseEntry entry,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class UnusedTimestampAuthority : ITimestampAuthority
    {
        public Task<TimestampResponse> GetTimestampAsync(
            ReadOnlyMemory<byte> signature,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }
}
