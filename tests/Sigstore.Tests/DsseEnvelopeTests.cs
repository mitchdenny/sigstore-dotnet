using System.Text;
using Sigstore;

namespace Sigstore.Tests;

public class DsseEnvelopeTests
{
    private static readonly string ValidInTotoStatement = """
    {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [
            {
                "name": "test-artifact",
                "digest": { "sha256": "abc123" }
            }
        ],
        "predicate": {
            "buildDefinition": {
                "buildType": "test-type"
            }
        }
    }
    """;

    [Fact]
    public void GetStatement_ValidInTotoPayload_ReturnsStatement()
    {
        var envelope = new DsseEnvelope
        {
            PayloadType = "application/vnd.in-toto+json",
            Payload = Encoding.UTF8.GetBytes(ValidInTotoStatement)
        };

        var statement = envelope.GetStatement();

        Assert.NotNull(statement);
        Assert.Equal("https://in-toto.io/Statement/v1", statement.Type);
        Assert.Equal("https://slsa.dev/provenance/v1", statement.PredicateType);
        Assert.Single(statement.Subject);
    }

    [Fact]
    public void GetStatement_NonInTotoPayloadType_ReturnsNull()
    {
        var envelope = new DsseEnvelope
        {
            PayloadType = "application/json",
            Payload = Encoding.UTF8.GetBytes(ValidInTotoStatement)
        };

        var statement = envelope.GetStatement();

        Assert.Null(statement);
    }

    [Fact]
    public void GetStatement_EmptyPayloadType_ReturnsNull()
    {
        var envelope = new DsseEnvelope
        {
            PayloadType = "",
            Payload = Encoding.UTF8.GetBytes(ValidInTotoStatement)
        };

        var statement = envelope.GetStatement();

        Assert.Null(statement);
    }

    [Fact]
    public void GetStatement_EmptyPayload_ReturnsNull()
    {
        var envelope = new DsseEnvelope
        {
            PayloadType = "application/vnd.in-toto+json",
            Payload = ReadOnlyMemory<byte>.Empty
        };

        var statement = envelope.GetStatement();

        Assert.Null(statement);
    }

    [Fact]
    public void GetStatement_CorruptPayload_ReturnsNull()
    {
        var envelope = new DsseEnvelope
        {
            PayloadType = "application/vnd.in-toto+json",
            Payload = Encoding.UTF8.GetBytes("this is not valid json!!!")
        };

        var statement = envelope.GetStatement();

        Assert.Null(statement);
    }

    [Fact]
    public void GetStatement_CaseInsensitivePayloadType()
    {
        var envelope = new DsseEnvelope
        {
            PayloadType = "Application/VND.In-Toto+JSON",
            Payload = Encoding.UTF8.GetBytes(ValidInTotoStatement)
        };

        var statement = envelope.GetStatement();

        Assert.NotNull(statement);
    }

    [Fact]
    public void GetStatement_CanAccessPredicateDetails()
    {
        var envelope = new DsseEnvelope
        {
            PayloadType = "application/vnd.in-toto+json",
            Payload = Encoding.UTF8.GetBytes(ValidInTotoStatement)
        };

        var statement = envelope.GetStatement()!;

        var buildType = statement.Predicate!.Value
            .GetProperty("buildDefinition")
            .GetProperty("buildType")
            .GetString();

        Assert.Equal("test-type", buildType);
    }
}
