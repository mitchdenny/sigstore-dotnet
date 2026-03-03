using System.Text;
using System.Text.Json;

namespace Sigstore;

/// <summary>
/// Represents an in-toto v1 statement, the standard attestation format used in Sigstore DSSE bundles.
/// See https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
/// </summary>
public sealed class InTotoStatement
{
    /// <summary>
    /// The in-toto statement type URI (e.g., "https://in-toto.io/Statement/v1").
    /// Corresponds to the <c>_type</c> field.
    /// </summary>
    public string? Type { get; init; }

    /// <summary>
    /// The URI identifying the type of the predicate (e.g., "https://slsa.dev/provenance/v1").
    /// </summary>
    public string? PredicateType { get; init; }

    /// <summary>
    /// The subjects of the attestation, identifying the artifacts being attested.
    /// </summary>
    public IReadOnlyList<InTotoSubject> Subject { get; init; } = [];

    /// <summary>
    /// The predicate containing attestation-specific data (e.g., SLSA provenance).
    /// Kept as a <see cref="JsonElement"/> for flexibility — consumers can deserialize
    /// to their own strongly-typed models as needed.
    /// </summary>
    public JsonElement? Predicate { get; init; }

    /// <summary>
    /// Parses an in-toto statement from raw JSON bytes (typically from a DSSE envelope payload).
    /// </summary>
    /// <param name="payloadBytes">The UTF-8 JSON bytes of the in-toto statement.</param>
    /// <returns>The parsed statement, or <c>null</c> if the bytes cannot be parsed.</returns>
    public static InTotoStatement? Parse(ReadOnlyMemory<byte> payloadBytes)
    {
        return Parse(payloadBytes.Span);
    }

    /// <summary>
    /// Parses an in-toto statement from a read-only span of JSON bytes.
    /// </summary>
    /// <param name="payloadBytes">The UTF-8 JSON bytes of the in-toto statement.</param>
    /// <returns>The parsed statement, or <c>null</c> if the bytes cannot be parsed.</returns>
    public static InTotoStatement? Parse(ReadOnlySpan<byte> payloadBytes)
    {
        if (payloadBytes.IsEmpty)
            return null;

        try
        {
            using var doc = JsonDocument.Parse(payloadBytes.ToArray());
            return ParseFromDocument(doc);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Parses an in-toto statement from a JSON string.
    /// </summary>
    /// <param name="json">The JSON string of the in-toto statement.</param>
    /// <returns>The parsed statement, or <c>null</c> if the string cannot be parsed.</returns>
    public static InTotoStatement? Parse(string json)
    {
        if (string.IsNullOrEmpty(json))
            return null;

        try
        {
            using var doc = JsonDocument.Parse(json);
            return ParseFromDocument(doc);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static InTotoStatement? ParseFromDocument(JsonDocument doc)
    {
        var root = doc.RootElement;

        string? type = null;
        if (root.TryGetProperty("_type", out var typeEl))
            type = typeEl.GetString();

        string? predicateType = null;
        if (root.TryGetProperty("predicateType", out var predTypeEl))
            predicateType = predTypeEl.GetString();

        var subjects = new List<InTotoSubject>();
        if (root.TryGetProperty("subject", out var subjectEl) && subjectEl.ValueKind == JsonValueKind.Array)
        {
            foreach (var subjectItem in subjectEl.EnumerateArray())
            {
                string? name = null;
                if (subjectItem.TryGetProperty("name", out var nameEl))
                    name = nameEl.GetString();

                var digest = new Dictionary<string, string>();
                if (subjectItem.TryGetProperty("digest", out var digestEl) && digestEl.ValueKind == JsonValueKind.Object)
                {
                    foreach (var prop in digestEl.EnumerateObject())
                    {
                        var val = prop.Value.GetString();
                        if (val != null)
                            digest[prop.Name] = val;
                    }
                }

                subjects.Add(new InTotoSubject
                {
                    Name = name ?? "",
                    Digest = digest
                });
            }
        }

        // Clone the predicate so it survives the JsonDocument disposal
        JsonElement? predicate = null;
        if (root.TryGetProperty("predicate", out var predicateEl))
            predicate = predicateEl.Clone();

        return new InTotoStatement
        {
            Type = type,
            PredicateType = predicateType,
            Subject = subjects,
            Predicate = predicate
        };
    }
}

/// <summary>
/// Represents a subject (artifact) in an in-toto statement.
/// </summary>
public sealed class InTotoSubject
{
    /// <summary>
    /// The name/URI of the artifact.
    /// </summary>
    public string Name { get; init; } = "";

    /// <summary>
    /// A map of digest algorithm to digest value (e.g., {"sha256": "abc123..."}).
    /// </summary>
    public IReadOnlyDictionary<string, string> Digest { get; init; } = new Dictionary<string, string>();
}
