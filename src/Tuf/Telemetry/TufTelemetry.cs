using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Reflection;

namespace Tuf;

/// <summary>
/// Identifies the diagnostics emitted by the Tuf package.
/// </summary>
public static class TufTelemetry
{
    /// <summary>
    /// The name of the <see cref="ActivitySource"/> used by the Tuf package.
    /// </summary>
    public const string ActivitySourceName = "Tuf";

    /// <summary>
    /// The name of the <see cref="Meter"/> used by the Tuf package.
    /// </summary>
    public const string MeterName = "Tuf";

    private static readonly string? InstrumentationVersion = typeof(TufTelemetry)
        .Assembly
        .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
        .InformationalVersion;

    internal static readonly ActivitySource ActivitySource =
        new(ActivitySourceName, InstrumentationVersion);

    internal static readonly Meter Meter =
        new(MeterName, InstrumentationVersion);
}
