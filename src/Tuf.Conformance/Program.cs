using System.Security.Cryptography;
using System.Text;
using System.CommandLine;
using Tuf;

namespace Tuf.Conformance;

/// <summary>
/// TUF conformance CLI — implements the tuf-conformance CLI protocol.
/// </summary>
public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var metadataDirOption = new Option<string>("--metadata-dir") { Required = true };
        var metadataUrlOption = new Option<string?>("--metadata-url");
        var targetNameOption = new Option<string?>("--target-name");
        var targetBasUrlOption = new Option<string?>("--target-base-url");
        var targetDirOption = new Option<string?>("--target-dir");

        var rootCommand = new RootCommand("TUF conformance CLI");
        rootCommand.Add(metadataDirOption);
        rootCommand.Add(metadataUrlOption);
        rootCommand.Add(targetNameOption);
        rootCommand.Add(targetBasUrlOption);
        rootCommand.Add(targetDirOption);

        var initArg = new Argument<string>("trusted-root-path");
        var initCommand = new Command("init", "Initialize TUF client with trusted root");
        initCommand.Add(initArg);
        initCommand.SetAction(async (parseResult, cancellationToken) =>
        {
            var metadataDir = parseResult.GetRequiredValue(metadataDirOption);
            var trustedRootPath = parseResult.GetRequiredValue(initArg);

            await InitAsync(metadataDir, trustedRootPath);
        });

        var refreshCommand = new Command("refresh", "Refresh TUF metadata");
        refreshCommand.SetAction(async (parseResult, cancellationToken) =>
        {
            var metadataDir = parseResult.GetRequiredValue(metadataDirOption);
            var metadataUrl = parseResult.GetValue(metadataUrlOption)
                ?? throw new InvalidOperationException("--metadata-url is required for refresh");

            await RefreshAsync(metadataDir, metadataUrl, cancellationToken);
        });

        var downloadCommand = new Command("download", "Download a TUF target");
        downloadCommand.SetAction(async (parseResult, cancellationToken) =>
        {
            var metadataDir = parseResult.GetRequiredValue(metadataDirOption);
            var metadataUrl = parseResult.GetValue(metadataUrlOption)
                ?? throw new InvalidOperationException("--metadata-url is required for download");
            var targetName = parseResult.GetValue(targetNameOption)
                ?? throw new InvalidOperationException("--target-name is required for download");
            var targetBaseUrl = parseResult.GetValue(targetBasUrlOption)
                ?? throw new InvalidOperationException("--target-base-url is required for download");
            var targetDir = parseResult.GetValue(targetDirOption)
                ?? throw new InvalidOperationException("--target-dir is required for download");

            await DownloadAsync(metadataDir, metadataUrl, targetName, targetBaseUrl, targetDir, cancellationToken);
        });

        rootCommand.Add(initCommand);
        rootCommand.Add(refreshCommand);
        rootCommand.Add(downloadCommand);

        var parseResult = rootCommand.Parse(args);
        return await parseResult.InvokeAsync();
    }

    private static Task InitAsync(string metadataDir, string trustedRootPath)
    {
        Directory.CreateDirectory(metadataDir);
        var destPath = Path.Combine(metadataDir, "root.json");
        File.Copy(trustedRootPath, destPath, overwrite: true);
        return Task.CompletedTask;
    }

    private static async Task RefreshAsync(string metadataDir, string metadataUrl, CancellationToken cancellationToken)
    {
        using var client = CreateTufClient(metadataDir, metadataUrl, targetBaseUrl: null);
        await client.GetTrustedMetadataAsync(cancellationToken);
    }

    private static async Task DownloadAsync(string metadataDir, string metadataUrl,
        string targetName, string targetBaseUrl, string targetDir, CancellationToken cancellationToken)
    {
        using var client = CreateTufClient(metadataDir, metadataUrl, targetBaseUrl);
        var target = await client.GetTargetAsync(targetName, cancellationToken);

        Directory.CreateDirectory(targetDir);
        var targetPath = Path.Combine(targetDir, targetName);
        var dir = Path.GetDirectoryName(targetPath);
        if (dir != null)
            Directory.CreateDirectory(dir);

        if (File.Exists(targetPath))
        {
            var existingBytes = await File.ReadAllBytesAsync(targetPath, cancellationToken);
            if (existingBytes.AsSpan().SequenceEqual(target.Content.Span))
            {
                return;
            }
        }

        await File.WriteAllBytesAsync(targetPath, target.Content, cancellationToken);
    }

    private static TufClient CreateTufClient(string metadataDir, string metadataUrl, string? targetBaseUrl)
    {
        var rootPath = Path.Combine(metadataDir, "root.json");
        var trustedRoot = File.ReadAllBytes(rootPath);

        var metadataUri = new Uri(metadataUrl.TrimEnd('/') + "/");
        Uri? targetsUri = targetBaseUrl != null
            ? new Uri(targetBaseUrl.TrimEnd('/') + "/")
            : null;

        var options = new TufClientOptions
        {
            MetadataBaseUrl = metadataUri,
            TrustedRoot = trustedRoot,
            Cache = new ConformanceCache(metadataDir),
            TargetsBaseUrl = targetsUri,
        };

        return new TufClient(options);
    }

    private sealed class ConformanceCache : ITufCache
    {
        private readonly string _metadataDir;
        private readonly string _targetsDir;

        public ConformanceCache(string metadataDir)
        {
            _metadataDir = metadataDir;
            _targetsDir = Path.Combine(metadataDir, "targets");
            Directory.CreateDirectory(_metadataDir);
            Directory.CreateDirectory(_targetsDir);
        }

        public byte[]? LoadMetadata(string role)
        {
            var path = GetMetadataPath(role);
            return File.Exists(path) ? File.ReadAllBytes(path) : null;
        }

        public void StoreMetadata(string role, byte[] data) =>
            File.WriteAllBytes(GetMetadataPath(role), data);

        public byte[]? LoadTarget(string targetPath)
        {
            var path = GetTargetPath(targetPath);
            return File.Exists(path) ? File.ReadAllBytes(path) : null;
        }

        public void StoreTarget(string targetPath, byte[] data) =>
            File.WriteAllBytes(GetTargetPath(targetPath), data);

        private string GetMetadataPath(string role) =>
            Path.Combine(_metadataDir, $"{Uri.EscapeDataString(role)}.json");

        private string GetTargetPath(string targetPath)
        {
            var hash = Convert.ToHexString(
                SHA256.HashData(Encoding.UTF8.GetBytes(targetPath)));
            return Path.Combine(_targetsDir, hash);
        }
    }
}
