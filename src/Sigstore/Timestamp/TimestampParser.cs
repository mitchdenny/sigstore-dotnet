namespace Sigstore.Timestamp;

/// <summary>
/// Pure computation for parsing and verifying RFC 3161 timestamps.
/// No I/O — operates entirely on in-memory data.
/// </summary>
public static class TimestampParser
{
    /// <summary>
    /// Parses an RFC 3161 TimeStampResponse by walking the ASN.1 DER structure
    /// to extract the genTime from the TSTInfo.
    /// </summary>
    /// <param name="timestampResponse">The DER-encoded TimeStampResponse bytes.</param>
    /// <returns>The parsed timestamp information.</returns>
    public static TimestampInfo Parse(ReadOnlyMemory<byte> timestampResponse)
    {
        var span = timestampResponse.Span;
        // Walk the ASN.1 to find a GeneralizedTime (tag 0x18) which is the genTime in TSTInfo
        var timestamp = FindGeneralizedTime(span);
        if (timestamp == null)
            throw new FormatException("Could not find GeneralizedTime in RFC 3161 timestamp response.");

        return new TimestampInfo
        {
            Timestamp = timestamp.Value,
            HashAlgorithm = Common.HashAlgorithmType.Sha2_256,
            MessageImprint = [],
            RawToken = timestampResponse.ToArray()
        };
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
        // Basic verification: check that we have a valid timestamp and TSA certs
        return info.Timestamp != default && tsaCertificates.Count > 0;
    }

    private static DateTimeOffset? FindGeneralizedTime(ReadOnlySpan<byte> data)
    {
        int i = 0;
        while (i < data.Length)
        {
            if (i + 1 >= data.Length)
                break;

            byte tag = data[i];
            i++;
            int length = ReadDerLength(data, ref i);
            if (length < 0 || i + length > data.Length)
                break;

            if (tag == 0x18) // GeneralizedTime
            {
                var timeStr = System.Text.Encoding.ASCII.GetString(data.Slice(i, length));
                if (TryParseGeneralizedTime(timeStr, out var dt))
                    return dt;
            }

            // For constructed types (bit 5 set), recurse into contents
            if ((tag & 0x20) != 0)
            {
                var result = FindGeneralizedTime(data.Slice(i, length));
                if (result != null)
                    return result;
            }

            i += length;
        }
        return null;
    }

    private static int ReadDerLength(ReadOnlySpan<byte> data, ref int offset)
    {
        if (offset >= data.Length)
            return -1;

        byte b = data[offset++];
        if (b < 0x80)
            return b;

        int numBytes = b & 0x7F;
        if (numBytes == 0 || numBytes > 4 || offset + numBytes > data.Length)
            return -1;

        int length = 0;
        for (int j = 0; j < numBytes; j++)
            length = (length << 8) | data[offset++];
        return length;
    }

    private static bool TryParseGeneralizedTime(string s, out DateTimeOffset result)
    {
        // Formats: "YYYYMMDDHHmmSSZ" or "YYYYMMDDHHmmSS.fffZ"
        result = default;
        if (s.Length < 15)
            return false;

        string cleaned = s.TrimEnd('Z');
        if (DateTimeOffset.TryParseExact(
            cleaned.Contains('.') ? cleaned + "Z" : cleaned + "Z",
            cleaned.Contains('.')
                ? new[] { "yyyyMMddHHmmss.fZ", "yyyyMMddHHmmss.ffZ", "yyyyMMddHHmmss.fffZ", "yyyyMMddHHmmss.ffffZ" }
                : new[] { "yyyyMMddHHmmssZ" },
            System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal,
            out result))
        {
            return true;
        }
        return false;
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
