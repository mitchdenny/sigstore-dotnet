using Sigstore;

namespace Sigstore.Tests.Verification;

public class CertificateExtensionPolicyTests
{
    private static FulcioCertificateExtensions CreateExtensions(
        string? sourceRepositoryUri = null,
        string? sourceRepositoryDigest = null,
        string? sourceRepositoryRef = null,
        string? sourceRepositoryIdentifier = null,
        string? sourceRepositoryOwnerUri = null,
        string? sourceRepositoryOwnerIdentifier = null,
        string? buildSignerUri = null,
        string? buildSignerDigest = null,
        string? buildConfigUri = null,
        string? buildConfigDigest = null,
        string? buildTrigger = null,
        string? runnerEnvironment = null,
        string? sourceRepositoryVisibilityAtSigning = null)
    {
        return new FulcioCertificateExtensions
        {
            SourceRepositoryUri = sourceRepositoryUri,
            SourceRepositoryDigest = sourceRepositoryDigest,
            SourceRepositoryRef = sourceRepositoryRef,
            SourceRepositoryIdentifier = sourceRepositoryIdentifier,
            SourceRepositoryOwnerUri = sourceRepositoryOwnerUri,
            SourceRepositoryOwnerIdentifier = sourceRepositoryOwnerIdentifier,
            BuildSignerUri = buildSignerUri,
            BuildSignerDigest = buildSignerDigest,
            BuildConfigUri = buildConfigUri,
            BuildConfigDigest = buildConfigDigest,
            BuildTrigger = buildTrigger,
            RunnerEnvironment = runnerEnvironment,
            SourceRepositoryVisibilityAtSigning = sourceRepositoryVisibilityAtSigning
        };
    }

    [Fact]
    public void Matches_EmptyPolicy_AlwaysMatches()
    {
        var policy = new CertificateExtensionPolicy();
        var extensions = CreateExtensions(
            sourceRepositoryUri: "https://github.com/myorg/myrepo",
            buildTrigger: "push");

        var (isMatch, reason) = policy.Matches(extensions);

        Assert.True(isMatch);
        Assert.Null(reason);
    }

    [Fact]
    public void Matches_SourceRepositoryUri_Matches()
    {
        var policy = new CertificateExtensionPolicy
        {
            SourceRepositoryUri = "https://github.com/myorg/myrepo"
        };
        var extensions = CreateExtensions(sourceRepositoryUri: "https://github.com/myorg/myrepo");

        var (isMatch, _) = policy.Matches(extensions);

        Assert.True(isMatch);
    }

    [Fact]
    public void Matches_SourceRepositoryUri_Fails()
    {
        var policy = new CertificateExtensionPolicy
        {
            SourceRepositoryUri = "https://github.com/myorg/myrepo"
        };
        var extensions = CreateExtensions(sourceRepositoryUri: "https://github.com/attacker/evil");

        var (isMatch, reason) = policy.Matches(extensions);

        Assert.False(isMatch);
        Assert.Contains("SourceRepositoryUri", reason);
        Assert.Contains("attacker/evil", reason!);
    }

    [Fact]
    public void Matches_SourceRepositoryUri_FailsWhenNull()
    {
        var policy = new CertificateExtensionPolicy
        {
            SourceRepositoryUri = "https://github.com/myorg/myrepo"
        };
        var extensions = CreateExtensions(); // no SourceRepositoryUri

        var (isMatch, reason) = policy.Matches(extensions);

        Assert.False(isMatch);
        Assert.Contains("SourceRepositoryUri", reason);
    }

    [Fact]
    public void Matches_BuildSignerUri_Matches()
    {
        var policy = new CertificateExtensionPolicy
        {
            BuildSignerUri = "https://github.com/myorg/myrepo/.github/workflows/release.yml@refs/tags/v1.0"
        };
        var extensions = CreateExtensions(
            buildSignerUri: "https://github.com/myorg/myrepo/.github/workflows/release.yml@refs/tags/v1.0");

        var (isMatch, _) = policy.Matches(extensions);

        Assert.True(isMatch);
    }

    [Fact]
    public void Matches_BuildSignerUri_Fails()
    {
        var policy = new CertificateExtensionPolicy
        {
            BuildSignerUri = "https://github.com/myorg/myrepo/.github/workflows/release.yml@refs/tags/v1.0"
        };
        var extensions = CreateExtensions(
            buildSignerUri: "https://github.com/attacker/evil/.github/workflows/attack.yml@refs/heads/main");

        var (isMatch, reason) = policy.Matches(extensions);

        Assert.False(isMatch);
        Assert.Contains("BuildSignerUri", reason);
    }

    [Fact]
    public void Matches_RunnerEnvironment_Matches()
    {
        var policy = new CertificateExtensionPolicy
        {
            RunnerEnvironment = "github-hosted"
        };
        var extensions = CreateExtensions(runnerEnvironment: "github-hosted");

        var (isMatch, _) = policy.Matches(extensions);

        Assert.True(isMatch);
    }

    [Fact]
    public void Matches_RunnerEnvironment_Fails()
    {
        var policy = new CertificateExtensionPolicy
        {
            RunnerEnvironment = "github-hosted"
        };
        var extensions = CreateExtensions(runnerEnvironment: "self-hosted");

        var (isMatch, reason) = policy.Matches(extensions);

        Assert.False(isMatch);
        Assert.Contains("RunnerEnvironment", reason);
    }

    [Fact]
    public void Matches_MultipleFields_AllMustMatch()
    {
        var policy = new CertificateExtensionPolicy
        {
            SourceRepositoryUri = "https://github.com/myorg/myrepo",
            RunnerEnvironment = "github-hosted",
            BuildTrigger = "push"
        };
        var extensions = CreateExtensions(
            sourceRepositoryUri: "https://github.com/myorg/myrepo",
            runnerEnvironment: "github-hosted",
            buildTrigger: "push");

        var (isMatch, _) = policy.Matches(extensions);

        Assert.True(isMatch);
    }

    [Fact]
    public void Matches_MultipleFields_FailsOnFirst()
    {
        var policy = new CertificateExtensionPolicy
        {
            SourceRepositoryUri = "https://github.com/myorg/myrepo",
            RunnerEnvironment = "github-hosted",
            BuildTrigger = "push"
        };
        var extensions = CreateExtensions(
            sourceRepositoryUri: "https://github.com/wrong/repo",
            runnerEnvironment: "github-hosted",
            buildTrigger: "push");

        var (isMatch, reason) = policy.Matches(extensions);

        Assert.False(isMatch);
        Assert.Contains("SourceRepositoryUri", reason);
    }

    [Fact]
    public void Matches_SourceRepositoryDigest_Matches()
    {
        var policy = new CertificateExtensionPolicy
        {
            SourceRepositoryDigest = "abc123"
        };
        var extensions = CreateExtensions(sourceRepositoryDigest: "abc123");

        var (isMatch, _) = policy.Matches(extensions);
        Assert.True(isMatch);
    }

    [Fact]
    public void Matches_SourceRepositoryRef_Matches()
    {
        var policy = new CertificateExtensionPolicy
        {
            SourceRepositoryRef = "refs/tags/v1.0.0"
        };
        var extensions = CreateExtensions(sourceRepositoryRef: "refs/tags/v1.0.0");

        var (isMatch, _) = policy.Matches(extensions);
        Assert.True(isMatch);
    }

    [Fact]
    public void Matches_SourceRepositoryRef_Fails()
    {
        var policy = new CertificateExtensionPolicy
        {
            SourceRepositoryRef = "refs/tags/v1.0.0"
        };
        var extensions = CreateExtensions(sourceRepositoryRef: "refs/heads/main");

        var (isMatch, reason) = policy.Matches(extensions);
        Assert.False(isMatch);
        Assert.Contains("SourceRepositoryRef", reason);
    }

    [Fact]
    public void Matches_BuildConfigUri_Matches()
    {
        var policy = new CertificateExtensionPolicy
        {
            BuildConfigUri = "https://github.com/myorg/myrepo/.github/workflows/build.yml@refs/tags/v1.0"
        };
        var extensions = CreateExtensions(
            buildConfigUri: "https://github.com/myorg/myrepo/.github/workflows/build.yml@refs/tags/v1.0");

        var (isMatch, _) = policy.Matches(extensions);
        Assert.True(isMatch);
    }

    [Fact]
    public void Matches_SourceRepositoryOwnerUri_Matches()
    {
        var policy = new CertificateExtensionPolicy
        {
            SourceRepositoryOwnerUri = "https://github.com/myorg"
        };
        var extensions = CreateExtensions(sourceRepositoryOwnerUri: "https://github.com/myorg");

        var (isMatch, _) = policy.Matches(extensions);
        Assert.True(isMatch);
    }

    [Fact]
    public void Matches_SourceRepositoryVisibilityAtSigning_Matches()
    {
        var policy = new CertificateExtensionPolicy
        {
            SourceRepositoryVisibilityAtSigning = "public"
        };
        var extensions = CreateExtensions(sourceRepositoryVisibilityAtSigning: "public");

        var (isMatch, _) = policy.Matches(extensions);
        Assert.True(isMatch);
    }

    [Fact]
    public void Matches_SourceRepositoryVisibilityAtSigning_Fails()
    {
        var policy = new CertificateExtensionPolicy
        {
            SourceRepositoryVisibilityAtSigning = "public"
        };
        var extensions = CreateExtensions(sourceRepositoryVisibilityAtSigning: "private");

        var (isMatch, reason) = policy.Matches(extensions);
        Assert.False(isMatch);
        Assert.Contains("SourceRepositoryVisibilityAtSigning", reason);
    }

    [Fact]
    public void BackwardCompatibility_ExistingSanAndIssuerOnlyPolicy()
    {
        // Ensure that existing policies without Extensions still work
        var policy = new CertificateIdentity
        {
            SubjectAlternativeName = "user@example.com",
            Issuer = "https://accounts.google.com"
        };

        Assert.Null(policy.Extensions);
    }

    [Fact]
    public void ForGitHubActions_SetsSourceRepositoryUri()
    {
        var identity = CertificateIdentity.ForGitHubActions("myorg", "myrepo");

        Assert.NotNull(identity.Extensions);
        Assert.Equal("https://github.com/myorg/myrepo", identity.Extensions.SourceRepositoryUri);
    }

    [Fact]
    public void ForGitHubActions_WithWorkflowRef_StillSetsExtensions()
    {
        var identity = CertificateIdentity.ForGitHubActions("myorg", "myrepo", workflowRef: "refs/heads/main");

        Assert.NotNull(identity.Extensions);
        Assert.Equal("https://github.com/myorg/myrepo", identity.Extensions.SourceRepositoryUri);
    }
}
