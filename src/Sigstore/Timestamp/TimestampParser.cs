namespace Sigstore.Timestamp;

/// <summary>
/// Pure computation for parsing and verifying RFC 3161 timestamps.
/// No I/O — operates entirely on in-memory data.
/// </summary>
public static class TimestampParser
{
    /// <summary>
    /// Parses an RFC 3161 TimeStampResponse.
    /// </summary>
    /// <param name="timestampResponse">The DER-encoded TimeStampResponse bytes.</param>
    /// <returns>The parsed timestamp information.</returns>
    public static TimestampInfo Parse(ReadOnlyMemory<byte> timestampResponse)
    {
        // TODO: Implement ASN.1 DER parsing of RFC 3161 TimeStampResponse
        throw new NotImplementedException();
    }

    /// <summary>
    /// Verifies an RFC 3161 timestamp against a signature and trusted TSA certificates.
    /// </summary>
    /// <param name="info">The parsed timestamp info.</param>
    /// <param name="signature">The signature that was timestamped.</param>
    /// <param name="tsaCertificates">The trusted TSA certificate chain.</param>
    /// <returns>True if the timestamp is valid.</returns>
    public static bool Verify(
        TimestampInfo info,
        ReadOnlyMemory<byte> signature,
        IReadOnlyList<byte[]> tsaCertificates)
    {
        // TODO: Implement RFC 3161 timestamp verification
        throw new NotImplementedException();
    }
}

/// <summary>
/// Parsed information from an RFC 3161 timestamp.
/// </summary>
public class TimestampInfo
{
    /// <summary>
    /// The timestamp value.
    /// </summary>
    public required DateTimeOffset Timestamp { get; init; }

    /// <summary>
    /// The hash algorithm used in the message imprint.
    /// </summary>
    public required Common.HashAlgorithmType HashAlgorithm { get; init; }

    /// <summary>
    /// The message imprint (hash of the timestamped data).
    /// </summary>
    public required byte[] MessageImprint { get; init; }

    /// <summary>
    /// The raw DER-encoded TimeStampToken.
    /// </summary>
    public required byte[] RawToken { get; init; }
}
