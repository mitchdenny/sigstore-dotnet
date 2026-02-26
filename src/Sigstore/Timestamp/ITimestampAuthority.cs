namespace Sigstore.Timestamp;

/// <summary>
/// Client for interacting with an RFC 3161 Timestamp Authority.
/// </summary>
public interface ITimestampAuthority
{
    /// <summary>
    /// Requests a signed timestamp for the given signature.
    /// </summary>
    /// <param name="signature">The signature bytes to timestamp.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The DER-encoded RFC 3161 TimeStampResponse.</returns>
    Task<TimestampResponse> GetTimestampAsync(
        ReadOnlyMemory<byte> signature,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Response from an RFC 3161 Timestamp Authority.
/// </summary>
public class TimestampResponse
{
    /// <summary>
    /// The DER-encoded TimeStampResponse.
    /// </summary>
    public required byte[] RawBytes { get; init; }
}
