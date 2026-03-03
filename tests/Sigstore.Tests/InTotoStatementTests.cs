using System.Text;
using System.Text.Json;
using Sigstore;

namespace Sigstore.Tests;

public class InTotoStatementTests
{
    private const string ValidStatement = """
    {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [
            {
                "name": "mypackage-1.0.0.tgz",
                "digest": {
                    "sha256": "abc123def456789"
                }
            }
        ],
        "predicate": {
            "buildDefinition": {
                "buildType": "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1"
            },
            "runDetails": {
                "builder": {
                    "id": "https://github.com/actions/runner"
                }
            }
        }
    }
    """;

    [Fact]
    public void Parse_ValidStatement_ReturnsStatement()
    {
        var statement = InTotoStatement.Parse(ValidStatement);

        Assert.NotNull(statement);
        Assert.Equal("https://in-toto.io/Statement/v1", statement.Type);
        Assert.Equal("https://slsa.dev/provenance/v1", statement.PredicateType);
    }

    [Fact]
    public void Parse_ValidStatement_HasSubject()
    {
        var statement = InTotoStatement.Parse(ValidStatement)!;

        Assert.Single(statement.Subject);
        Assert.Equal("mypackage-1.0.0.tgz", statement.Subject[0].Name);
        Assert.Equal("abc123def456789", statement.Subject[0].Digest["sha256"]);
    }

    [Fact]
    public void Parse_ValidStatement_HasPredicate()
    {
        var statement = InTotoStatement.Parse(ValidStatement)!;

        Assert.NotNull(statement.Predicate);
        Assert.Equal(JsonValueKind.Object, statement.Predicate.Value.ValueKind);

        var buildType = statement.Predicate.Value
            .GetProperty("buildDefinition")
            .GetProperty("buildType")
            .GetString();
        Assert.Equal("https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1", buildType);
    }

    [Fact]
    public void Parse_MultipleSubjects_AllParsed()
    {
        var json = """
        {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [
                {
                    "name": "artifact-a",
                    "digest": { "sha256": "aaa" }
                },
                {
                    "name": "artifact-b",
                    "digest": { "sha256": "bbb", "sha512": "ccc" }
                }
            ],
            "predicate": {}
        }
        """;

        var statement = InTotoStatement.Parse(json)!;

        Assert.Equal(2, statement.Subject.Count);
        Assert.Equal("artifact-a", statement.Subject[0].Name);
        Assert.Equal("artifact-b", statement.Subject[1].Name);
        Assert.Equal("aaa", statement.Subject[0].Digest["sha256"]);
        Assert.Equal("bbb", statement.Subject[1].Digest["sha256"]);
        Assert.Equal("ccc", statement.Subject[1].Digest["sha512"]);
    }

    [Fact]
    public void Parse_NoSubjects_ReturnsEmptyList()
    {
        var json = """
        {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {}
        }
        """;

        var statement = InTotoStatement.Parse(json)!;

        Assert.NotNull(statement);
        Assert.Empty(statement.Subject);
    }

    [Fact]
    public void Parse_NoPredicate_PredicateIsNull()
    {
        var json = """
        {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": []
        }
        """;

        var statement = InTotoStatement.Parse(json)!;

        Assert.NotNull(statement);
        Assert.Null(statement.Predicate);
    }

    [Fact]
    public void Parse_MalformedJson_ReturnsNull()
    {
        var statement = InTotoStatement.Parse("{invalid json!!!");
        Assert.Null(statement);
    }

    [Fact]
    public void Parse_EmptyString_ReturnsNull()
    {
        var statement = InTotoStatement.Parse("");
        Assert.Null(statement);
    }

    [Fact]
    public void Parse_NullString_ReturnsNull()
    {
        var statement = InTotoStatement.Parse((string)null!);
        Assert.Null(statement);
    }

    [Fact]
    public void Parse_FromBytes_ValidStatement()
    {
        var bytes = Encoding.UTF8.GetBytes(ValidStatement);
        var statement = InTotoStatement.Parse(new ReadOnlyMemory<byte>(bytes));

        Assert.NotNull(statement);
        Assert.Equal("https://in-toto.io/Statement/v1", statement.Type);
        Assert.Equal("https://slsa.dev/provenance/v1", statement.PredicateType);
    }

    [Fact]
    public void Parse_FromBytes_EmptyBytes_ReturnsNull()
    {
        var statement = InTotoStatement.Parse(ReadOnlyMemory<byte>.Empty);
        Assert.Null(statement);
    }

    [Fact]
    public void Parse_FromBytes_MalformedBytes_ReturnsNull()
    {
        var bytes = Encoding.UTF8.GetBytes("not json at all {{{");
        var statement = InTotoStatement.Parse(new ReadOnlyMemory<byte>(bytes));
        Assert.Null(statement);
    }

    [Fact]
    public void Parse_MinimalStatement_OnlyTypeAndPredicateType()
    {
        var json = """
        {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "custom/type/v1"
        }
        """;

        var statement = InTotoStatement.Parse(json)!;

        Assert.NotNull(statement);
        Assert.Equal("https://in-toto.io/Statement/v1", statement.Type);
        Assert.Equal("custom/type/v1", statement.PredicateType);
        Assert.Empty(statement.Subject);
        Assert.Null(statement.Predicate);
    }

    [Fact]
    public void Parse_SlsaProvenanceV1_CanNavigatePredicate()
    {
        var json = """
        {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [
                {
                    "name": "pkg:npm/@playwright/cli@0.1.1",
                    "digest": { "sha512": "abc123" }
                }
            ],
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1",
                    "externalParameters": {
                        "workflow": {
                            "ref": "refs/tags/v0.1.1",
                            "repository": "https://github.com/microsoft/playwright-cli",
                            "path": ".github/workflows/publish.yml"
                        }
                    }
                },
                "runDetails": {
                    "builder": {
                        "id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.0.0"
                    }
                }
            }
        }
        """;

        var statement = InTotoStatement.Parse(json)!;

        // Verify we can navigate the SLSA predicate like Aspire would need to
        var predicate = statement.Predicate!.Value;
        var buildDef = predicate.GetProperty("buildDefinition");
        var buildType = buildDef.GetProperty("buildType").GetString();
        var workflow = buildDef.GetProperty("externalParameters").GetProperty("workflow");
        var repo = workflow.GetProperty("repository").GetString();
        var path = workflow.GetProperty("path").GetString();
        var workflowRef = workflow.GetProperty("ref").GetString();
        var builderId = predicate.GetProperty("runDetails").GetProperty("builder").GetProperty("id").GetString();

        Assert.Equal("https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1", buildType);
        Assert.Equal("https://github.com/microsoft/playwright-cli", repo);
        Assert.Equal(".github/workflows/publish.yml", path);
        Assert.Equal("refs/tags/v0.1.1", workflowRef);
        Assert.StartsWith("https://github.com/slsa-framework/", builderId);
    }

    [Fact]
    public void Parse_SubjectDigest_MultipleAlgorithms()
    {
        var json = """
        {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "custom",
            "subject": [
                {
                    "name": "artifact",
                    "digest": {
                        "sha256": "sha256value",
                        "sha384": "sha384value",
                        "sha512": "sha512value"
                    }
                }
            ]
        }
        """;

        var statement = InTotoStatement.Parse(json)!;
        var digest = statement.Subject[0].Digest;

        Assert.Equal(3, digest.Count);
        Assert.Equal("sha256value", digest["sha256"]);
        Assert.Equal("sha384value", digest["sha384"]);
        Assert.Equal("sha512value", digest["sha512"]);
    }

    [Fact]
    public void Parse_PredicateSurvivesDocumentDisposal()
    {
        // The predicate should be cloned so it survives JsonDocument disposal
        var statement = InTotoStatement.Parse(ValidStatement)!;

        // Force GC to make sure the predicate isn't holding onto a disposed document
        GC.Collect();
        GC.WaitForPendingFinalizers();

        // Should still be accessible
        Assert.NotNull(statement.Predicate);
        var buildType = statement.Predicate.Value
            .GetProperty("buildDefinition")
            .GetProperty("buildType")
            .GetString();
        Assert.NotNull(buildType);
    }

    [Fact]
    public void Parse_EmptySubjectArray_ReturnsEmptyList()
    {
        var json = """
        {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "test",
            "subject": [],
            "predicate": {}
        }
        """;

        var statement = InTotoStatement.Parse(json)!;
        Assert.Empty(statement.Subject);
    }

    [Fact]
    public void Parse_SubjectWithNoDigest_HasEmptyDigestDictionary()
    {
        var json = """
        {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "test",
            "subject": [
                {
                    "name": "artifact-no-digest"
                }
            ]
        }
        """;

        var statement = InTotoStatement.Parse(json)!;
        Assert.Single(statement.Subject);
        Assert.Equal("artifact-no-digest", statement.Subject[0].Name);
        Assert.Empty(statement.Subject[0].Digest);
    }
}
