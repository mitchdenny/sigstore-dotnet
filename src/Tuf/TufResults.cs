namespace Tuf;

/// <summary>
/// Describes the trusted metadata established by a TUF operation.
/// </summary>
public sealed record TufMetadataResult
{
    /// <summary>
    /// The earliest expiry across the trusted metadata set.
    /// </summary>
    public required DateTimeOffset Expires { get; init; }
}

/// <summary>
/// A verified TUF target and the metadata that authorized it.
/// </summary>
public sealed record TufTargetResult
{
    /// <summary>
    /// The verified target contents.
    /// </summary>
    public required ReadOnlyMemory<byte> Content { get; init; }

    /// <summary>
    /// The trusted metadata that authorized the target.
    /// </summary>
    public required TufMetadataResult Metadata { get; init; }
}
