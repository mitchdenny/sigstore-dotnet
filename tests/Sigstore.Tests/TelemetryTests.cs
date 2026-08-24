using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Sigstore.Tests;

[CollectionDefinition("Telemetry", DisableParallelization = true)]
public sealed class TelemetryTestCollection;

[Collection("Telemetry")]
public sealed class TelemetryTests
{
    [Fact]
    public async Task VerifyFailureEmitsActivityAndMetrics()
    {
        using var activityListener = CreateActivityListener(out var activities);
        using var meterListener = CreateMeterListener(
            out var measurements,
            out var instruments);
        using var parent = new Activity("telemetry-test")
            .SetIdFormat(ActivityIdFormat.W3C)
            .Start();
        parent.AddBaggage("telemetry-test", "inherited");

        var verifier = new SigstoreVerifier(
            new InMemoryTrustRootProvider(new TrustedRoot()));
        using var artifact = new MemoryStream("artifact"u8.ToArray());

        var (success, _) = await verifier.TryVerifyStreamAsync(
            artifact,
            new SigstoreBundle(),
            new VerificationPolicy());
        meterListener.RecordObservableInstruments();

        Assert.False(success);

        var verify = Assert.Single(
            activities,
            activity =>
                activity.TraceId == parent.TraceId &&
                activity.OperationName == "sigstore.verify");
        Assert.Equal(ActivityStatusCode.Error, verify.Status);
        Assert.Same(parent, verify.Parent);
        Assert.Equal("inherited", verify.GetBaggageItem("telemetry-test"));
        Assert.Equal("bundle_invalid", verify.GetTagItem("error.type"));
        Assert.Equal("stream", verify.GetTagItem("sigstore.verify.input_type"));
        Assert.Equal("unknown", verify.GetTagItem("sigstore.bundle.type"));
        Assert.Equal(
            "certificate",
            verify.GetTagItem("sigstore.verification.material"));

        var duration = Assert.Single(
            measurements,
            measurement =>
                measurement.Name == "sigstore.verify.duration");
        Assert.Equal("bundle_invalid", duration.Tags["error.type"]);
        Assert.Equal("stream", duration.Tags["sigstore.verify.input_type"]);
        Assert.Contains(
            measurements,
            measurement =>
                measurement.Name == "sigstore.verify.active" &&
                measurement.Value == 0);

        Assert.Contains("sigstore.sign.duration", instruments);
        Assert.Contains("sigstore.sign.active", instruments);
        Assert.Contains("sigstore.attest.duration", instruments);
        Assert.Contains("sigstore.attest.active", instruments);
        Assert.Contains("sigstore.verify.duration", instruments);
        Assert.Contains("sigstore.verify.active", instruments);
    }

    [Fact]
    public async Task SignFailureEmitsNestedOidcActivity()
    {
        using var activityListener = CreateActivityListener(out var activities);
        using var meterListener = CreateMeterListener(
            out var measurements,
            out _);
        using var parent = new Activity("telemetry-test")
            .SetIdFormat(ActivityIdFormat.W3C)
            .Start();

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
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => signTask);
        meterListener.RecordObservableInstruments();

        var traceActivities = activities
            .Where(activity => activity.TraceId == parent.TraceId)
            .ToList();
        var sign = Assert.Single(
            traceActivities,
            activity => activity.OperationName == "sigstore.sign");
        var oidc = Assert.Single(
            traceActivities,
            activity =>
                activity.OperationName == "sigstore.oidc.token.get");

        Assert.Equal(sign.SpanId, oidc.ParentSpanId);
        Assert.Equal(ActivityStatusCode.Error, sign.Status);
        Assert.Equal(ActivityStatusCode.Error, oidc.Status);
        Assert.Equal(
            typeof(InvalidOperationException).FullName,
            sign.GetTagItem("error.type"));
        Assert.Contains(
            measurements,
            measurement =>
                measurement.Name == "sigstore.sign.duration" &&
                Equals(
                    measurement.Tags["error.type"],
                    typeof(InvalidOperationException).FullName));
        Assert.Contains(
            measurements,
            measurement =>
                measurement.Name == "sigstore.sign.active" &&
                measurement.Value == 1);
        Assert.Contains(
            measurements,
            measurement =>
                measurement.Name == "sigstore.sign.active" &&
                measurement.Value == 0);
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
