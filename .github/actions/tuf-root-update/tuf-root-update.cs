#:project ../../../src/Tuf/Tuf.csproj
#:property TargetFramework=net10.0
#:property TreatWarningsAsErrors=true

using System.Diagnostics;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Tuf;

return await TufRootUpdateApp.RunAsync(args);

internal static partial class TufRootUpdateApp
{
    private const string EmbeddedRootPath = "src/Sigstore/TrustRoot/TufData/root.json";
    private const string RootFixturePath = "tests/Tuf.Tests/Fixtures/root.json";

    public static async Task<int> RunAsync(string[] arguments)
    {
        try
        {
            if (arguments.Length == 0)
            {
                throw new ArgumentException(
                    "Expected a command: refresh, verify-pr, open-pr, or self-test.");
            }

            switch (arguments[0])
            {
                case "refresh":
                    await RefreshAsync(arguments[1..]);
                    break;
                case "verify-pr":
                    await VerifyPullRequestAsync(arguments[1..]);
                    break;
                case "open-pr":
                    await OpenPullRequestAsync(arguments[1..]);
                    break;
                case "self-test":
                    await SelfTestAsync(arguments[1..]);
                    break;
                default:
                    throw new ArgumentException($"Unknown command '{arguments[0]}'.");
            }

            return 0;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            Console.Error.WriteLine($"::error::{EscapeWorkflowCommand(exception.Message)}");
            return 1;
        }
    }

    private static async Task RefreshAsync(string[] arguments)
    {
        if (arguments.Length < 2)
        {
            throw new ArgumentException(
                "Usage: refresh <metadata-url> <trusted-root-path> [additional-root-paths...]");
        }

        var metadataUrl = ParseHttpsUri(arguments[0], "metadata URL");
        var rootPaths = arguments[1..].Select(Path.GetFullPath).ToArray();
        var result = await UpdateRootFilesAsync(
            metadataUrl,
            rootPaths,
            RefreshFromRepositoryAsync,
            CancellationToken.None);

        await WriteGitHubOutputAsync(result);
        Console.WriteLine(result.Changed
            ? $"Verified and updated the production TUF root from v{result.PreviousVersion} to v{result.CurrentVersion}."
            : $"The production TUF root is already current at v{result.CurrentVersion}.");
    }

    private static async Task<RootUpdateResult> UpdateRootFilesAsync(
        Uri metadataUrl,
        IReadOnlyList<string> rootPaths,
        Func<byte[], Uri, CancellationToken, Task<byte[]>> refreshRoot,
        CancellationToken cancellationToken)
    {
        if (rootPaths.Count == 0)
        {
            throw new ArgumentException("At least one trusted-root path is required.");
        }

        var trustedRoot = await File.ReadAllBytesAsync(rootPaths[0], cancellationToken);
        for (var index = 1; index < rootPaths.Count; index++)
        {
            var additionalRoot = await File.ReadAllBytesAsync(rootPaths[index], cancellationToken);
            if (!trustedRoot.AsSpan().SequenceEqual(additionalRoot))
            {
                throw new InvalidOperationException(
                    $"{rootPaths[index]} differs from the trusted root {rootPaths[0]}.");
            }
        }

        var previousVersion = ReadRootVersion(trustedRoot);
        var verifiedRoot = await refreshRoot(trustedRoot, metadataUrl, cancellationToken);
        var currentVersion = ReadRootVersion(verifiedRoot);

        if (currentVersion < previousVersion)
        {
            throw new InvalidOperationException(
                $"TUF refresh rolled root v{previousVersion} back to v{currentVersion}.");
        }

        var changed = !trustedRoot.AsSpan().SequenceEqual(verifiedRoot);
        if (changed && currentVersion == previousVersion)
        {
            throw new InvalidOperationException(
                $"TUF refresh changed root v{currentVersion} without advancing its version.");
        }

        if (changed)
        {
            await ReplaceFilesAsync(rootPaths, verifiedRoot, cancellationToken);
        }

        return new RootUpdateResult(
            changed,
            previousVersion,
            currentVersion,
            ComputeSha256(verifiedRoot));
    }

    private static async Task<byte[]> RefreshFromRepositoryAsync(
        byte[] trustedRoot,
        Uri metadataUrl,
        CancellationToken cancellationToken)
    {
        var cacheDirectory = CreateTemporaryDirectory();
        try
        {
            var cache = new FileSystemTufCache(cacheDirectory);
            using var client = new TufClient(new TufClientOptions
            {
                MetadataBaseUrl = metadataUrl,
                TargetsBaseUrl = new Uri(metadataUrl, "targets/"),
                TrustedRoot = trustedRoot,
                Cache = cache
            });

            await client.GetTrustedMetadataAsync(cancellationToken);
            var verifiedRoot = cache.LoadMetadata("root")
                ?? throw new InvalidOperationException("The TUF refresh did not produce trusted root metadata.");

            var currentVersion = ReadRootVersion(verifiedRoot);
            using var repository = new HttpTufRepository(
                metadataUrl,
                new Uri(metadataUrl, "targets/"));
            var remainingRoot = await repository.FetchMetadataAsync(
                "root",
                checked(currentVersion + 1),
                cancellationToken);
            if (remainingRoot is not null)
            {
                throw new InvalidOperationException(
                    $"The TUF root walk stopped at v{currentVersion} before reaching the latest root.");
            }

            return verifiedRoot;
        }
        finally
        {
            DeleteDirectory(cacheDirectory);
        }
    }

    private static async Task VerifyPullRequestAsync(string[] arguments)
    {
        if (arguments.Length != 2 ||
            !ShaPattern().IsMatch(arguments[0]) ||
            !ShaPattern().IsMatch(arguments[1]))
        {
            throw new ArgumentException(
                "Usage: verify-pr <40-character-base-commit-sha> <40-character-head-commit-sha>");
        }

        var baseSha = arguments[0];
        var headSha = arguments[1];
        var repositoryRoot = await GetRepositoryRootAsync();
        var checkedOutSha = (await RunProcessAsync(
            "git",
            ["rev-parse", "HEAD"],
            repositoryRoot,
            echoOutput: false)).StandardOutput.Trim();
        if (!string.Equals(checkedOutSha, baseSha, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Expected the trusted base commit {baseSha}, but checked out {checkedOutSha}.");
        }

        var baseEmbeddedRootPath = Path.Combine(repositoryRoot, EmbeddedRootPath);
        var baseRootFixturePath = Path.Combine(repositoryRoot, RootFixturePath);
        EnsureFilesEqual(
            baseEmbeddedRootPath,
            baseRootFixturePath,
            "The base commit's embedded root and test fixture differ.");

        var repository = GetRequiredEnvironmentVariable("GITHUB_REPOSITORY");
        var apiUrl = ParseHttpsUri(
            GetRequiredEnvironmentVariable("GITHUB_API_URL"),
            "GITHUB_API_URL");
        var token = GetRequiredEnvironmentVariable("GH_TOKEN");
        var proposedEmbeddedRoot = await DownloadRepositoryFileAsync(
            apiUrl,
            repository,
            EmbeddedRootPath,
            headSha,
            token,
            CancellationToken.None);
        var proposedRootFixture = await DownloadRepositoryFileAsync(
            apiUrl,
            repository,
            RootFixturePath,
            headSha,
            token,
            CancellationToken.None);

        var baseRoot = await File.ReadAllBytesAsync(baseEmbeddedRootPath);
        var changed = await VerifyProposedRootAsync(
            baseRoot,
            proposedEmbeddedRoot,
            proposedRootFixture,
            (root, cancellationToken) => RefreshFromRepositoryAsync(
                root,
                new Uri("https://tuf-repo-cdn.sigstore.dev/"),
                cancellationToken),
            CancellationToken.None);

        Console.WriteLine(changed
            ? "Verified production TUF root continuity from the base commit."
            : "The production TUF root is unchanged.");
    }

    private static async Task<bool> VerifyProposedRootAsync(
        byte[] baseRoot,
        byte[] proposedEmbeddedRoot,
        byte[] proposedRootFixture,
        Func<byte[], CancellationToken, Task<byte[]>> refreshRoot,
        CancellationToken cancellationToken)
    {
        if (!proposedEmbeddedRoot.AsSpan().SequenceEqual(proposedRootFixture))
        {
            throw new InvalidOperationException(
                "The proposed embedded production root and test fixture differ.");
        }

        if (baseRoot.AsSpan().SequenceEqual(proposedEmbeddedRoot))
        {
            return false;
        }

        var verifiedRoot = await refreshRoot(baseRoot, cancellationToken);
        if (!verifiedRoot.AsSpan().SequenceEqual(proposedEmbeddedRoot))
        {
            throw new InvalidOperationException(
                "The proposed production root is not the latest root verified from the base commit.");
        }

        return true;
    }

    private static async Task<byte[]> DownloadRepositoryFileAsync(
        Uri apiUrl,
        string repository,
        string path,
        string commitSha,
        string token,
        CancellationToken cancellationToken)
    {
        var repositoryParts = repository.Split('/');
        if (repositoryParts.Length != 2 ||
            !OwnerPattern().IsMatch(repositoryParts[0]) ||
            !RepositoryNamePattern().IsMatch(repositoryParts[1]) ||
            repositoryParts[1] is "." or "..")
        {
            throw new InvalidOperationException($"Invalid GITHUB_REPOSITORY value '{repository}'.");
        }

        var escapedPath = string.Join(
            '/',
            path.Split('/').Select(Uri.EscapeDataString));
        var baseUrl = new Uri($"{apiUrl.AbsoluteUri.TrimEnd('/')}/");
        var url = new Uri(
            baseUrl,
            $"repos/{Uri.EscapeDataString(repositoryParts[0])}/{Uri.EscapeDataString(repositoryParts[1])}/contents/{escapedPath}?ref={commitSha}");

        using var client = new HttpClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        client.DefaultRequestHeaders.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/vnd.github.raw+json"));
        client.DefaultRequestHeaders.UserAgent.ParseAdd("sigstore-dotnet-tuf-root-update");

        using var response = await client.GetAsync(url, cancellationToken);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsByteArrayAsync(cancellationToken);
    }

    private static async Task OpenPullRequestAsync(string[] arguments)
    {
        if (arguments.Length != 1)
        {
            throw new ArgumentException("Usage: open-pr <downloaded-artifact-directory>");
        }

        var artifactDirectory = Path.GetFullPath(arguments[0]);
        var defaultBranch = GetRequiredEnvironmentVariable("DEFAULT_BRANCH");
        var repository = GetRequiredEnvironmentVariable("GITHUB_REPOSITORY");
        var repositoryOwner = GetRequiredEnvironmentVariable("GITHUB_REPOSITORY_OWNER");
        var runId = ParsePositiveLong(
            GetRequiredEnvironmentVariable("GITHUB_RUN_ID"),
            "GITHUB_RUN_ID");
        var runAttempt = ParsePositiveInteger(
            GetRequiredEnvironmentVariable("GITHUB_RUN_ATTEMPT"),
            "GITHUB_RUN_ATTEMPT");
        var newVersion = ParsePositiveInteger(
            GetRequiredEnvironmentVariable("NEW_VERSION"),
            "NEW_VERSION");
        var previousVersion = ParsePositiveInteger(
            GetRequiredEnvironmentVariable("PREVIOUS_VERSION"),
            "PREVIOUS_VERSION");
        var reviewer = GetRequiredEnvironmentVariable("REVIEWER");
        var expectedSha256 = GetRequiredEnvironmentVariable("ROOT_SHA256");
        var runUrl = ParseHttpsUri(
            GetRequiredEnvironmentVariable("RUN_URL"),
            "RUN_URL");
        var serverUrl = ParseHttpsUri(
            GetRequiredEnvironmentVariable("GITHUB_SERVER_URL"),
            "GITHUB_SERVER_URL");
        var token = GetRequiredEnvironmentVariable("GH_TOKEN");

        var repositoryParts = repository.Split('/');
        if (repositoryParts.Length != 2 ||
            !string.Equals(repositoryParts[0], repositoryOwner, StringComparison.OrdinalIgnoreCase) ||
            !OwnerPattern().IsMatch(repositoryParts[0]) ||
            !RepositoryNamePattern().IsMatch(repositoryParts[1]) ||
            repositoryParts[1] is "." or "..")
        {
            throw new InvalidOperationException($"Invalid GITHUB_REPOSITORY value '{repository}'.");
        }

        if (!OwnerPattern().IsMatch(repositoryOwner) || !OwnerPattern().IsMatch(reviewer))
        {
            throw new InvalidOperationException("The repository owner or reviewer is invalid.");
        }

        if (!Sha256Pattern().IsMatch(expectedSha256))
        {
            throw new InvalidOperationException("ROOT_SHA256 must be a lowercase SHA-256 digest.");
        }

        var repositoryRoot = await GetRepositoryRootAsync();
        await RunProcessAsync(
            "git",
            ["check-ref-format", "--branch", defaultBranch],
            repositoryRoot,
            echoOutput: false);

        var artifactEmbeddedRoot = Path.Combine(artifactDirectory, EmbeddedRootPath);
        var artifactRootFixture = Path.Combine(artifactDirectory, RootFixturePath);
        EnsureFilesEqual(
            artifactEmbeddedRoot,
            artifactRootFixture,
            "The verified embedded root and test fixture differ.");

        var verifiedRoot = await File.ReadAllBytesAsync(artifactEmbeddedRoot);
        if (!string.Equals(ComputeSha256(verifiedRoot), expectedSha256, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("The verified root does not match ROOT_SHA256.");
        }

        if (ReadRootVersion(verifiedRoot) != newVersion)
        {
            throw new InvalidOperationException(
                $"The verified root version does not match NEW_VERSION v{newVersion}.");
        }

        var currentEmbeddedRoot = Path.Combine(repositoryRoot, EmbeddedRootPath);
        var currentRootFixture = Path.Combine(repositoryRoot, RootFixturePath);
        EnsureFilesEqual(
            currentEmbeddedRoot,
            currentRootFixture,
            "The checked-out embedded root and test fixture differ.");

        var checkedOutVersion = ReadRootVersion(await File.ReadAllBytesAsync(currentEmbeddedRoot));
        if (checkedOutVersion != previousVersion)
        {
            throw new InvalidOperationException(
                $"The default branch root changed from expected v{previousVersion} to v{checkedOutVersion}.");
        }

        await ReplaceFilesAsync(
            [currentEmbeddedRoot, currentRootFixture],
            verifiedRoot,
            CancellationToken.None);

        await RunProcessAsync(
            "git",
            ["config", "user.name", "github-actions[bot]"],
            repositoryRoot,
            echoOutput: false);
        await RunProcessAsync(
            "git",
            ["config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com"],
            repositoryRoot,
            echoOutput: false);

        var headBranch = $"bot/tuf-root-update-v{newVersion}";
        var existingPullRequest = (await RunProcessAsync(
            "gh",
            [
                "api",
                "--method", "GET",
                $"repos/{repository}/pulls",
                "-f", "state=open",
                "-f", $"base={defaultBranch}",
                "-f", $"head={repositoryOwner}:{headBranch}",
                "--jq", ".[0].number // empty"
            ],
            repositoryRoot,
            echoOutput: false)).StandardOutput.Trim();

        if (existingPullRequest.Length > 0)
        {
            if (!existingPullRequest.All(char.IsAsciiDigit))
            {
                throw new InvalidOperationException("GitHub returned an invalid pull request number.");
            }

            Console.WriteLine(
                $"::notice::Pull request #{existingPullRequest} already updates root v{newVersion}.");
            return;
        }

        var remoteUrl = BuildRepositoryUrl(serverUrl, repository);
        var gitAuthentication = CreateGitAuthentication(serverUrl, token);
        var remoteBranch = await RunProcessAsync(
            "git",
            ["ls-remote", "--exit-code", "--heads", remoteUrl.AbsoluteUri, $"refs/heads/{headBranch}"],
            repositoryRoot,
            new HashSet<int> { 0, 2 },
            gitAuthentication,
            echoOutput: false);
        if (remoteBranch.ExitCode == 0)
        {
            headBranch = $"{headBranch}-{runId}-{runAttempt}";
        }

        await RunProcessAsync(
            "git",
            ["checkout", "-b", headBranch],
            repositoryRoot,
            echoOutput: false);
        await RunProcessAsync(
            "git",
            ["add", EmbeddedRootPath, RootFixturePath],
            repositoryRoot,
            echoOutput: false);

        var stagedPaths = (await RunProcessAsync(
            "git",
            ["diff", "--cached", "--name-only"],
            repositoryRoot,
            echoOutput: false)).StandardOutput
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var expectedPaths = new[] { EmbeddedRootPath, RootFixturePath }
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (!stagedPaths.SequenceEqual(expectedPaths, StringComparer.Ordinal))
        {
            throw new InvalidOperationException(
                $"Unexpected staged paths: {string.Join(", ", stagedPaths)}.");
        }

        await RunProcessAsync(
            "git",
            ["commit", "--quiet", "-m", $"chore: update production TUF root to v{newVersion}"],
            repositoryRoot,
            echoOutput: false);
        await RunProcessAsync(
            "git",
            ["push", remoteUrl.AbsoluteUri, $"HEAD:refs/heads/{headBranch}"],
            repositoryRoot,
            environment: gitAuthentication);

        var title = $"Update production TUF root to v{newVersion}";
        var body = $"""
            Updates the embedded Sigstore production TUF root from **v{previousVersion}** to
            **v{newVersion}**.

            The repository's TUF client walked every numbered intermediate root and verified each
            root against both the previous and new key thresholds before writing these files.

            @{reviewer}, mark this draft ready for review to run the full test and conformance
            suites.

            - Root SHA-256: `{expectedSha256}`
            - Verification run: {runUrl}
            """;

        await RunProcessAsync(
            "gh",
            [
                "pr", "create",
                "--repo", repository,
                "--base", defaultBranch,
                "--head", headBranch,
                "--draft",
                "--reviewer", reviewer,
                "--title", title,
                "--body", body
            ],
            repositoryRoot);
    }

    private static async Task SelfTestAsync(string[] arguments)
    {
        if (arguments.Length != 0)
        {
            throw new ArgumentException("Usage: self-test");
        }

        var temporaryDirectory = CreateTemporaryDirectory();
        try
        {
            var embeddedRoot = Path.Combine(temporaryDirectory, "root.json");
            var rootFixture = Path.Combine(temporaryDirectory, "root-fixture.json");
            var rootV14 = CreateTestRoot(14);
            var rootV15 = CreateTestRoot(15);
            await File.WriteAllBytesAsync(embeddedRoot, rootV14);
            await File.WriteAllBytesAsync(rootFixture, rootV14);

            var metadataUrl = new Uri("https://tuf.example.invalid/");
            var updated = await UpdateRootFilesAsync(
                metadataUrl,
                [embeddedRoot, rootFixture],
                (_, _, _) => Task.FromResult(rootV15),
                CancellationToken.None);

            Require(updated.Changed, "an update was not reported");
            Require(updated.PreviousVersion == 14, "the previous version was not reported");
            Require(updated.CurrentVersion == 15, "the current version was not reported");
            Require(
                (await File.ReadAllBytesAsync(embeddedRoot)).AsSpan().SequenceEqual(rootV15),
                "the embedded root was not updated");
            Require(
                (await File.ReadAllBytesAsync(rootFixture)).AsSpan().SequenceEqual(rootV15),
                "the root fixture was not updated");

            var unchanged = await UpdateRootFilesAsync(
                metadataUrl,
                [embeddedRoot, rootFixture],
                (_, _, _) => Task.FromResult(rootV15),
                CancellationToken.None);
            Require(!unchanged.Changed, "an idempotent refresh reported a change");

            var changedRootV15 = Encoding.UTF8.GetBytes(
                "{\"signed\":{\"_type\":\"root\",\"version\":15,\"unexpected\":true}}");
            await ExpectFailureAsync(
                () => UpdateRootFilesAsync(
                    metadataUrl,
                    [embeddedRoot, rootFixture],
                    (_, _, _) => Task.FromResult(changedRootV15),
                    CancellationToken.None),
                "root bytes changed without a version increase");

            await ExpectFailureAsync(
                () => UpdateRootFilesAsync(
                    metadataUrl,
                    [embeddedRoot, rootFixture],
                    (_, _, _) => Task.FromResult(rootV14),
                    CancellationToken.None),
                "a root rollback was accepted");

            await File.WriteAllBytesAsync(rootFixture, rootV14);
            await ExpectFailureAsync(
                () => UpdateRootFilesAsync(
                    metadataUrl,
                    [embeddedRoot, rootFixture],
                    (_, _, _) => Task.FromResult(rootV15),
                    CancellationToken.None),
                "divergent trusted-root inputs were accepted");

            var proposedRootChanged = await VerifyProposedRootAsync(
                rootV14,
                rootV15,
                rootV15,
                (_, _) => Task.FromResult(rootV15),
                CancellationToken.None);
            Require(proposedRootChanged, "a verified proposed root update was reported as unchanged");
            var proposedRootUnchanged = await VerifyProposedRootAsync(
                rootV14,
                rootV14,
                rootV14,
                (_, _) => throw new InvalidOperationException("unchanged roots must not refresh"),
                CancellationToken.None);
            Require(!proposedRootUnchanged, "an unchanged proposed root was reported as changed");
            await ExpectFailureAsync(
                () => VerifyProposedRootAsync(
                    rootV14,
                    rootV15,
                    rootV14,
                    (_, _) => Task.FromResult(rootV15),
                    CancellationToken.None),
                "divergent proposed roots were accepted");

            Console.WriteLine("All TUF root update self-tests passed.");
        }
        finally
        {
            DeleteDirectory(temporaryDirectory);
        }
    }

    private static int ReadRootVersion(byte[] root)
    {
        using var document = JsonDocument.Parse(root);
        if (!document.RootElement.TryGetProperty("signed", out var signed) ||
            !signed.TryGetProperty("_type", out var type) ||
            type.GetString() != "root" ||
            !signed.TryGetProperty("version", out var version) ||
            !version.TryGetInt32(out var value) ||
            value <= 0)
        {
            throw new InvalidOperationException("The TUF root has an invalid signed version.");
        }

        return value;
    }

    private static async Task ReplaceFilesAsync(
        IReadOnlyList<string> paths,
        byte[] content,
        CancellationToken cancellationToken)
    {
        var stagedPaths = new List<string>(paths.Count);
        try
        {
            foreach (var path in paths)
            {
                var fullPath = Path.GetFullPath(path);
                var directory = Path.GetDirectoryName(fullPath)
                    ?? throw new InvalidOperationException($"Cannot resolve the directory for {fullPath}.");
                Directory.CreateDirectory(directory);
                var stagedPath = Path.Combine(
                    directory,
                    $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.tmp");
                await File.WriteAllBytesAsync(stagedPath, content, cancellationToken);
                stagedPaths.Add(stagedPath);
            }

            for (var index = 0; index < paths.Count; index++)
            {
                File.Move(stagedPaths[index], Path.GetFullPath(paths[index]), overwrite: true);
            }
        }
        finally
        {
            foreach (var stagedPath in stagedPaths)
            {
                if (File.Exists(stagedPath))
                {
                    File.Delete(stagedPath);
                }
            }
        }
    }

    private static async Task WriteGitHubOutputAsync(RootUpdateResult result)
    {
        var outputPath = Environment.GetEnvironmentVariable("GITHUB_OUTPUT");
        if (string.IsNullOrEmpty(outputPath))
        {
            return;
        }

        await File.AppendAllLinesAsync(
            outputPath,
            [
                $"changed={result.Changed.ToString().ToLowerInvariant()}",
                $"previous_version={result.PreviousVersion}",
                $"current_version={result.CurrentVersion}",
                $"sha256={result.Sha256}"
            ]);
    }

    private static async Task<string> GetRepositoryRootAsync()
    {
        var result = await RunProcessAsync(
            "git",
            ["rev-parse", "--show-toplevel"],
            Directory.GetCurrentDirectory(),
            echoOutput: false);
        return Path.GetFullPath(result.StandardOutput.Trim());
    }

    private static ProcessEnvironment CreateGitAuthentication(Uri serverUrl, string token)
    {
        var authority = serverUrl.GetLeftPart(UriPartial.Authority).TrimEnd('/');
        var credential = Convert.ToBase64String(Encoding.UTF8.GetBytes($"x-access-token:{token}"));
        return new ProcessEnvironment
        {
            ["GIT_CONFIG_COUNT"] = "1",
            ["GIT_CONFIG_KEY_0"] = $"http.{authority}/.extraheader",
            ["GIT_CONFIG_VALUE_0"] = $"AUTHORIZATION: basic {credential}"
        };
    }

    private static Uri BuildRepositoryUrl(Uri serverUrl, string repository)
    {
        var baseUrl = new Uri($"{serverUrl.GetLeftPart(UriPartial.Authority).TrimEnd('/')}/");
        return new Uri(baseUrl, $"{repository}.git");
    }

    private static async Task<ProcessResult> RunProcessAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        string workingDirectory,
        IReadOnlySet<int>? allowedExitCodes = null,
        ProcessEnvironment? environment = null,
        bool echoOutput = true)
    {
        allowedExitCodes ??= new HashSet<int> { 0 };
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            WorkingDirectory = workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        if (environment is not null)
        {
            foreach (var (name, value) in environment)
            {
                startInfo.Environment[name] = value;
            }
        }

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException($"Failed to start {fileName}.");
        var standardOutputTask = process.StandardOutput.ReadToEndAsync();
        var standardErrorTask = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        var standardOutput = await standardOutputTask;
        var standardError = await standardErrorTask;

        if (echoOutput)
        {
            if (standardOutput.Length > 0)
            {
                Console.Write(standardOutput);
            }

            if (standardError.Length > 0)
            {
                Console.Error.Write(standardError);
            }
        }

        if (!allowedExitCodes.Contains(process.ExitCode))
        {
            throw new InvalidOperationException(
                $"{fileName} exited with code {process.ExitCode}: {standardError.Trim()}");
        }

        return new ProcessResult(process.ExitCode, standardOutput, standardError);
    }

    private static void EnsureFilesEqual(string firstPath, string secondPath, string errorMessage)
    {
        var first = File.ReadAllBytes(firstPath);
        var second = File.ReadAllBytes(secondPath);
        if (!first.AsSpan().SequenceEqual(second))
        {
            throw new InvalidOperationException(errorMessage);
        }
    }

    private static Uri ParseHttpsUri(string value, string name)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(uri.UserInfo))
        {
            throw new InvalidOperationException($"{name} must be an absolute HTTPS URL.");
        }

        return uri;
    }

    private static int ParsePositiveInteger(string value, string name)
    {
        if (!int.TryParse(value, out var result) || result <= 0)
        {
            throw new InvalidOperationException($"{name} must be a positive integer.");
        }

        return result;
    }

    private static long ParsePositiveLong(string value, string name)
    {
        if (!long.TryParse(value, out var result) || result <= 0)
        {
            throw new InvalidOperationException($"{name} must be a positive integer.");
        }

        return result;
    }

    private static string GetRequiredEnvironmentVariable(string name)
    {
        var value = Environment.GetEnvironmentVariable(name);
        return string.IsNullOrEmpty(value)
            ? throw new InvalidOperationException($"{name} is required.")
            : value;
    }

    private static string ComputeSha256(byte[] content) =>
        Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();

    private static string CreateTemporaryDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), $"tuf-root-update-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }

    private static void DeleteDirectory(string path)
    {
        if (Directory.Exists(path))
        {
            Directory.Delete(path, recursive: true);
        }
    }

    private static byte[] CreateTestRoot(int version) =>
        Encoding.UTF8.GetBytes($"{{\"signed\":{{\"_type\":\"root\",\"version\":{version}}}}}");

    private static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException($"Self-test failed: {message}.");
        }
    }

    private static async Task ExpectFailureAsync(Func<Task> action, string message)
    {
        try
        {
            await action();
        }
        catch (InvalidOperationException)
        {
            return;
        }

        throw new InvalidOperationException($"Self-test failed: {message}.");
    }

    private static string EscapeWorkflowCommand(string value) =>
        value.Replace("%", "%25", StringComparison.Ordinal)
            .Replace("\r", "%0D", StringComparison.Ordinal)
            .Replace("\n", "%0A", StringComparison.Ordinal);

    [GeneratedRegex("^[0-9a-f]{40}$", RegexOptions.CultureInvariant)]
    private static partial Regex ShaPattern();

    [GeneratedRegex("^[0-9a-f]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256Pattern();

    [GeneratedRegex("^[A-Za-z0-9_.-]+$", RegexOptions.CultureInvariant)]
    private static partial Regex RepositoryNamePattern();

    [GeneratedRegex("^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$", RegexOptions.CultureInvariant)]
    private static partial Regex OwnerPattern();

    private sealed record RootUpdateResult(
        bool Changed,
        int PreviousVersion,
        int CurrentVersion,
        string Sha256);

    private sealed record ProcessResult(
        int ExitCode,
        string StandardOutput,
        string StandardError);

    private sealed class ProcessEnvironment : Dictionary<string, string>;
}
