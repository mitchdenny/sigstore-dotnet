using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Reflection;

namespace Sigstore;

/// <summary>
/// Identifies the diagnostics emitted by the Sigstore package.
/// </summary>
public static class SigstoreTelemetry
{
    /// <summary>
    /// The name of the <see cref="ActivitySource"/> used by the Sigstore package.
    /// </summary>
    public const string ActivitySourceName = "Sigstore";

    /// <summary>
    /// The name of the <see cref="Meter"/> used by the Sigstore package.
    /// </summary>
    public const string MeterName = "Sigstore";

    private static readonly string? InstrumentationVersion = typeof(SigstoreTelemetry)
        .Assembly
        .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
        .InformationalVersion;

    internal static readonly ActivitySource ActivitySource =
        new(ActivitySourceName, InstrumentationVersion);

    internal static readonly Meter Meter =
        new(MeterName, InstrumentationVersion);
}
