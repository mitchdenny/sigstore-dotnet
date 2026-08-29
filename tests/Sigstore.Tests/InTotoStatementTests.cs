using System.Text;
using System.Text.Json;
using Sigstore;

namespace Sigstore.Tests;

[TestClass]
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

    [TestMethod]
    public void Parse_ValidStatement_ReturnsStatement()
    {
        var statement = InTotoStatement.Parse(ValidStatement);

        Assert.IsNotNull(statement);
        Assert.AreEqual("https://in-toto.io/Statement/v1", statement.Type);
        Assert.AreEqual("https://slsa.dev/provenance/v1", statement.PredicateType);
    }

    [TestMethod]
    public void Parse_ValidStatement_HasSubject()
    {
        var statement = InTotoStatement.Parse(ValidStatement)!;

        TestSeq.Single(statement.Subject);
        Assert.AreEqual("mypackage-1.0.0.tgz", statement.Subject[0].Name);
        Assert.AreEqual("abc123def456789", statement.Subject[0].Digest["sha256"]);
    }

    [TestMethod]
    public void Parse_ValidStatement_HasPredicate()
    {
        var statement = InTotoStatement.Parse(ValidStatement)!;

        Assert.IsNotNull(statement.Predicate);
        Assert.AreEqual(JsonValueKind.Object, statement.Predicate.Value.ValueKind);

        var buildType = statement.Predicate.Value
            .GetProperty("buildDefinition")
            .GetProperty("buildType")
            .GetString();
        Assert.AreEqual("https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1", buildType);
    }

    [TestMethod]
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

        Assert.AreEqual(2, statement.Subject.Count);
        Assert.AreEqual("artifact-a", statement.Subject[0].Name);
        Assert.AreEqual("artifact-b", statement.Subject[1].Name);
        Assert.AreEqual("aaa", statement.Subject[0].Digest["sha256"]);
        Assert.AreEqual("bbb", statement.Subject[1].Digest["sha256"]);
        Assert.AreEqual("ccc", statement.Subject[1].Digest["sha512"]);
    }

    [TestMethod]
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

        Assert.IsNotNull(statement);
        Assert.IsEmpty(statement.Subject);
    }

    [TestMethod]
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

        Assert.IsNotNull(statement);
        Assert.IsNull(statement.Predicate);
    }

    [TestMethod]
    public void Parse_MalformedJson_ReturnsNull()
    {
        var statement = InTotoStatement.Parse("{invalid json!!!");
        Assert.IsNull(statement);
    }

    [TestMethod]
    public void Parse_EmptyString_ReturnsNull()
    {
        var statement = InTotoStatement.Parse("");
        Assert.IsNull(statement);
    }

    [TestMethod]
    public void Parse_NullString_ReturnsNull()
    {
        var statement = InTotoStatement.Parse((string)null!);
        Assert.IsNull(statement);
    }

    [TestMethod]
    public void Parse_FromBytes_ValidStatement()
    {
        var bytes = Encoding.UTF8.GetBytes(ValidStatement);
        var statement = InTotoStatement.Parse(new ReadOnlyMemory<byte>(bytes));

        Assert.IsNotNull(statement);
        Assert.AreEqual("https://in-toto.io/Statement/v1", statement.Type);
        Assert.AreEqual("https://slsa.dev/provenance/v1", statement.PredicateType);
    }

    [TestMethod]
    public void Parse_FromBytes_EmptyBytes_ReturnsNull()
    {
        var statement = InTotoStatement.Parse(ReadOnlyMemory<byte>.Empty);
        Assert.IsNull(statement);
    }

    [TestMethod]
    public void Parse_FromBytes_MalformedBytes_ReturnsNull()
    {
        var bytes = Encoding.UTF8.GetBytes("not json at all {{{");
        var statement = InTotoStatement.Parse(new ReadOnlyMemory<byte>(bytes));
        Assert.IsNull(statement);
    }

    [TestMethod]
    public void Parse_MinimalStatement_OnlyTypeAndPredicateType()
    {
        var json = """
        {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "custom/type/v1"
        }
        """;

        var statement = InTotoStatement.Parse(json)!;

        Assert.IsNotNull(statement);
        Assert.AreEqual("https://in-toto.io/Statement/v1", statement.Type);
        Assert.AreEqual("custom/type/v1", statement.PredicateType);
        Assert.IsEmpty(statement.Subject);
        Assert.IsNull(statement.Predicate);
    }

    [TestMethod]
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

        Assert.AreEqual("https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1", buildType);
        Assert.AreEqual("https://github.com/microsoft/playwright-cli", repo);
        Assert.AreEqual(".github/workflows/publish.yml", path);
        Assert.AreEqual("refs/tags/v0.1.1", workflowRef);
        Assert.StartsWith("https://github.com/slsa-framework/", builderId);
    }

    [TestMethod]
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

        Assert.AreEqual(3, digest.Count);
        Assert.AreEqual("sha256value", digest["sha256"]);
        Assert.AreEqual("sha384value", digest["sha384"]);
        Assert.AreEqual("sha512value", digest["sha512"]);
    }

    [TestMethod]
    public void Parse_PredicateSurvivesDocumentDisposal()
    {
        // The predicate should be cloned so it survives JsonDocument disposal
        var statement = InTotoStatement.Parse(ValidStatement)!;

        // Force GC to make sure the predicate isn't holding onto a disposed document
        GC.Collect();
        GC.WaitForPendingFinalizers();

        // Should still be accessible
        Assert.IsNotNull(statement.Predicate);
        var buildType = statement.Predicate.Value
            .GetProperty("buildDefinition")
            .GetProperty("buildType")
            .GetString();
        Assert.IsNotNull(buildType);
    }

    [TestMethod]
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
        Assert.IsEmpty(statement.Subject);
    }

    [TestMethod]
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
        TestSeq.Single(statement.Subject);
        Assert.AreEqual("artifact-no-digest", statement.Subject[0].Name);
        Assert.IsEmpty(statement.Subject[0].Digest);
    }
}
