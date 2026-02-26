namespace Tuf;

/// <summary>
/// Options for configuring a <see cref="TufClient"/>.
/// </summary>
public sealed class TufClientOptions
{
    /// <summary>
    /// The base URL for the TUF repository metadata.
    /// </summary>
    public required Uri MetadataBaseUrl { get; init; }

    /// <summary>
    /// The base URL for the TUF repository targets. If null, targets are fetched
    /// relative to <see cref="MetadataBaseUrl"/>.
    /// </summary>
    public Uri? TargetsBaseUrl { get; init; }

    /// <summary>
    /// The initial trusted root metadata (root.json content).
    /// This is used to bootstrap trust with the TUF repository.
    /// </summary>
    public required byte[] TrustedRoot { get; init; }

    /// <summary>
    /// The cache implementation for storing verified metadata and targets.
    /// If null, an <see cref="InMemoryTufCache"/> is used.
    /// </summary>
    public ITufCache? Cache { get; init; }

    /// <summary>
    /// The repository implementation for fetching metadata and targets.
    /// If null, an <see cref="HttpTufRepository"/> is created using the provided URLs.
    /// </summary>
    public ITufRepository? Repository { get; init; }

    /// <summary>
    /// Maximum allowed root metadata rotations in a single refresh.
    /// Protects against endless root rotation loops. Default is 1024.
    /// </summary>
    public int MaxRootRotations { get; init; } = 1024;
}
