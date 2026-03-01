using System.CommandLine;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Sigstore.Common;
using Sigstore.Fulcio;
using Sigstore.Oidc;
using Sigstore.Rekor;
using Sigstore.Signing;
using Sigstore.Timestamp;
using Sigstore.TrustRoot;
using Sigstore.Verification;

namespace Sigstore.Conformance;

/// <summary>
/// Sigstore conformance CLI — implements the sigstore-conformance CLI protocol.
/// </summary>
public static class Program
{
    private static readonly Uri StagingTufUrl = TufTrustRootProvider.StagingUrl;
    private static readonly Uri ProductionTufUrl = TufTrustRootProvider.ProductionUrl;

    public static async Task<int> Main(string[] args)
    {
        var rootCommand = new RootCommand("Sigstore conformance CLI");

        rootCommand.Add(BuildSignBundleCommand());
        rootCommand.Add(BuildVerifyBundleCommand());

        var parseResult = rootCommand.Parse(args);
        return await parseResult.InvokeAsync();
    }

    private static Command BuildSignBundleCommand()
    {
        var stagingOption = new Option<bool>("--staging");
        var inTotoOption = new Option<bool>("--in-toto");
        var identityTokenOption = new Option<string>("--identity-token") { Required = true };
        var bundleOption = new Option<string>("--bundle") { Required = true };
        var trustedRootOption = new Option<string?>("--trusted-root");
        var signingConfigOption = new Option<string?>("--signing-config");
        var fileArgument = new Argument<string>("file");

        var command = new Command("sign-bundle", "Sign an artifact and produce a Sigstore bundle");
        command.Add(stagingOption);
        command.Add(inTotoOption);
        command.Add(identityTokenOption);
        command.Add(bundleOption);
        command.Add(trustedRootOption);
        command.Add(signingConfigOption);
        command.Add(fileArgument);

        command.SetAction(async (parseResult, cancellationToken) =>
        {
            var staging = parseResult.GetValue(stagingOption);
            var inToto = parseResult.GetValue(inTotoOption);
            var identityToken = parseResult.GetRequiredValue(identityTokenOption);
            var bundlePath = parseResult.GetRequiredValue(bundleOption);
            var trustedRootPath = parseResult.GetValue(trustedRootOption);
            var signingConfigPath = parseResult.GetValue(signingConfigOption);
            var file = parseResult.GetRequiredValue(fileArgument);

            await SignBundleAsync(staging, inToto, identityToken, bundlePath,
                trustedRootPath, signingConfigPath, file, cancellationToken);
        });

        return command;
    }

    private static Command BuildVerifyBundleCommand()
    {
        var stagingOption = new Option<bool>("--staging");
        var bundleOption = new Option<string>("--bundle") { Required = true };
        var certIdentityOption = new Option<string?>("--certificate-identity");
        var certIssuerOption = new Option<string?>("--certificate-oidc-issuer");
        var keyOption = new Option<string?>("--key");
        var trustedRootOption = new Option<string?>("--trusted-root");
        var fileArgument = new Argument<string>("file_or_digest");

        var command = new Command("verify-bundle", "Verify a Sigstore bundle");
        command.Add(stagingOption);
        command.Add(bundleOption);
        command.Add(certIdentityOption);
        command.Add(certIssuerOption);
        command.Add(keyOption);
        command.Add(trustedRootOption);
        command.Add(fileArgument);

        command.SetAction(async (parseResult, cancellationToken) =>
        {
            var staging = parseResult.GetValue(stagingOption);
            var bundlePath = parseResult.GetRequiredValue(bundleOption);
            var certIdentity = parseResult.GetValue(certIdentityOption);
            var certIssuer = parseResult.GetValue(certIssuerOption);
            var keyPath = parseResult.GetValue(keyOption);
            var trustedRootPath = parseResult.GetValue(trustedRootOption);
            var fileOrDigest = parseResult.GetRequiredValue(fileArgument);

            await VerifyBundleAsync(staging, bundlePath, certIdentity, certIssuer,
                keyPath, trustedRootPath, fileOrDigest, cancellationToken);
        });

        return command;
    }

    private static async Task SignBundleAsync(bool staging, bool inToto, string identityToken,
        string bundlePath, string? trustedRootPath, string? signingConfigPath, string file,
        CancellationToken cancellationToken)
    {
        // Parse signing config if provided
        SigningConfig? signingConfig = null;
        if (signingConfigPath != null)
        {
            var configJson = await File.ReadAllTextAsync(signingConfigPath, cancellationToken);
            signingConfig = SigningConfig.Deserialize(configJson);
        }

        // Create trust root provider
        using var trustRootProvider = CreateTrustRootProvider(staging, trustedRootPath);

        // Get the trust root to extract service URLs
        var trustRoot = await trustRootProvider.GetTrustRootAsync(cancellationToken);

        // Find Fulcio URL — use signing config if available, otherwise trust root
        Uri fulcioUrl;
        if (signingConfig != null)
        {
            var caEndpoint = SigningConfig.SelectBest(signingConfig.CaUrls)
                ?? throw new InvalidOperationException("No valid CA URL in signing config");
            fulcioUrl = new Uri(caEndpoint.Url);
        }
        else
        {
            var caUri = trustRoot.CertificateAuthorities
                .Where(ca => ca.ValidTo == null || ca.ValidTo > DateTimeOffset.UtcNow)
                .Select(ca => ca.Uri)
                .FirstOrDefault() ?? throw new InvalidOperationException("No Fulcio CA found in trust root");
            fulcioUrl = new Uri(caUri);
        }

        // Find Rekor URL and API version — use signing config if available
        Uri rekorUrl;
        int rekorApiVersion = 1;
        if (signingConfig != null)
        {
            var rekorEndpoint = SigningConfig.SelectBest(signingConfig.RekorTlogUrls)
                ?? throw new InvalidOperationException("No valid Rekor URL in signing config");
            rekorUrl = new Uri(rekorEndpoint.Url);
            rekorApiVersion = rekorEndpoint.MajorApiVersion;
        }
        else
        {
            var rekorUri = trustRoot.TransparencyLogs
                .Where(l => l.ValidTo == null || l.ValidTo > DateTimeOffset.UtcNow)
                .Select(l => l.BaseUrl)
                .FirstOrDefault() ?? throw new InvalidOperationException("No Rekor log found in trust root");
            rekorUrl = new Uri(rekorUri);
        }

        // Find TSA URL — use signing config if available
        Uri? tsaUrl = null;
        if (signingConfig != null)
        {
            var tsaEndpoint = SigningConfig.SelectBest(signingConfig.TsaUrls);
            if (tsaEndpoint != null)
                tsaUrl = new Uri(tsaEndpoint.Url);
        }
        else
        {
            var tsaUri = trustRoot.TimestampAuthorities
                .Where(t => t.ValidTo == null || t.ValidTo > DateTimeOffset.UtcNow)
                .Select(t => t.Uri)
                .FirstOrDefault();
            if (tsaUri != null)
                tsaUrl = new Uri(tsaUri);
        }

        // Create HTTP clients
        using var fulcio = new FulcioHttpClient(fulcioUrl);
        using var rekor = new RekorHttpClient(rekorUrl, rekorApiVersion);
        ITimestampAuthority tsa = tsaUrl != null
            ? new HttpTimestampAuthority(tsaUrl)
            : new NoOpTimestampAuthority();

        // Create OIDC token provider from raw JWT
        var tokenProvider = new RawTokenProvider(identityToken);

        var signer = new SigstoreSigner(fulcio, rekor, tsa, tokenProvider, trustRootProvider);

        SigstoreBundle bundle;
        if (inToto)
        {
            var statement = await File.ReadAllTextAsync(file, cancellationToken);
            bundle = await signer.AttestAsync(statement, cancellationToken);
        }
        else
        {
            bundle = await signer.SignAsync(file, cancellationToken);
        }

        await File.WriteAllTextAsync(bundlePath, bundle.Serialize(), cancellationToken);
    }

    private static async Task VerifyBundleAsync(bool staging, string bundlePath,
        string? certIdentity, string? certIssuer, string? keyPath,
        string? trustedRootPath, string fileOrDigest, CancellationToken cancellationToken)
    {
        // Create trust root provider
        using var trustRootProvider = CreateTrustRootProvider(staging, trustedRootPath);

        // Load bundle
        var bundleJson = await File.ReadAllTextAsync(bundlePath, cancellationToken);
        var bundle = SigstoreBundle.Deserialize(bundleJson);

        // Build verification policy
        var policy = new VerificationPolicy();

        if (certIdentity != null && certIssuer != null)
        {
            policy.CertificateIdentity = new CertificateIdentity
            {
                SubjectAlternativeName = certIdentity,
                Issuer = certIssuer
            };
        }

        if (keyPath != null)
        {
            var keyPem = await File.ReadAllTextAsync(keyPath, cancellationToken);
            var keyDer = ConvertPemPublicKeyToDer(keyPem);
            policy.PublicKey = keyDer;
        }

        var verifier = new SigstoreVerifier(trustRootProvider);

        // Determine if input is a digest or file path
        if (IsDigestInput(fileOrDigest))
        {
            // Parse the digest
            var hexDigest = fileOrDigest["sha256:".Length..];
            var digestBytes = Convert.FromHexString(hexDigest);

            if (bundle.DsseEnvelope != null)
            {
                // For DSSE/in-toto bundles, verify subject digest match first
                VerifyInTotoSubjectDigest(bundle.DsseEnvelope, fileOrDigest);
            }

            // Use digest-based verification
            await verifier.VerifyAsync(
                new ReadOnlyMemory<byte>(digestBytes),
                Common.HashAlgorithmType.Sha2_256,
                bundle, policy, cancellationToken);
        }
        else
        {
            await using var stream = File.OpenRead(fileOrDigest);
            await verifier.VerifyAsync(stream, bundle, policy, cancellationToken);
        }

        Console.WriteLine("OK");
    }

    private static DisposableTrustRootProvider CreateTrustRootProvider(bool staging, string? trustedRootPath)
    {
        if (trustedRootPath != null)
        {
            return new DisposableTrustRootProvider(new FileTrustRootProvider(trustedRootPath));
        }

        var url = staging ? StagingTufUrl : ProductionTufUrl;
        return new DisposableTrustRootProvider(new TufTrustRootProvider(url));
    }

    private static bool IsDigestInput(string input)
    {
        if (!input.StartsWith("sha256:", StringComparison.Ordinal))
            return false;

        var hexPart = input["sha256:".Length..];
        if (hexPart.Length != 64) // SHA-256 hex = 64 chars
            return false;

        // Must not be a path on disk
        if (File.Exists(input))
            return false;

        return hexPart.All(c => char.IsAsciiHexDigit(c));
    }

    private static void VerifyInTotoSubjectDigest(DsseEnvelope envelope, string fileOrDigest)
    {
        var payloadJson = Encoding.UTF8.GetString(envelope.Payload);
        using var doc = JsonDocument.Parse(payloadJson);
        var root = doc.RootElement;

        if (!root.TryGetProperty("subject", out var subjects))
            return;

        foreach (var subject in subjects.EnumerateArray())
        {
            if (!subject.TryGetProperty("digest", out var digests))
                continue;

            if (digests.TryGetProperty("sha256", out var sha256))
            {
                var expectedDigest = $"sha256:{sha256.GetString()}";
                if (string.Equals(expectedDigest, fileOrDigest, StringComparison.OrdinalIgnoreCase))
                    return; // Match found
            }
        }

        throw new VerificationException("Digest does not match any subject in the in-toto statement.");
    }

    private static byte[] ConvertPemPublicKeyToDer(string pem)
    {
        var base64 = pem
            .Replace("-----BEGIN PUBLIC KEY-----", "")
            .Replace("-----END PUBLIC KEY-----", "")
            .Replace("\n", "")
            .Replace("\r", "")
            .Trim();

        return Convert.FromBase64String(base64);
    }
}

/// <summary>
/// Wrapper to make any ITrustRootProvider disposable.
/// </summary>
internal sealed class DisposableTrustRootProvider : ITrustRootProvider, IDisposable
{
    private readonly ITrustRootProvider _inner;

    public DisposableTrustRootProvider(ITrustRootProvider inner) => _inner = inner;

    public Task<TrustRoot.TrustedRoot> GetTrustRootAsync(CancellationToken cancellationToken = default)
        => _inner.GetTrustRootAsync(cancellationToken);

    public void Dispose()
    {
        if (_inner is IDisposable disposable)
            disposable.Dispose();
    }
}

/// <summary>
/// OIDC token provider that wraps a raw JWT token string.
/// Decodes the subject and issuer claims from the JWT payload.
/// </summary>
internal sealed class RawTokenProvider : IOidcTokenProvider
{
    private readonly OidcToken _token;

    public RawTokenProvider(string rawToken)
    {
        var parts = rawToken.Split('.');
        if (parts.Length != 3)
            throw new ArgumentException("Invalid JWT format", nameof(rawToken));

        var payload = parts[1];
        payload = payload.Replace('-', '+').Replace('_', '/');
        switch (payload.Length % 4)
        {
            case 2: payload += "=="; break;
            case 3: payload += "="; break;
        }

        var payloadBytes = Convert.FromBase64String(payload);
        using var doc = JsonDocument.Parse(payloadBytes);
        var root = doc.RootElement;

        var subject = root.TryGetProperty("sub", out var sub) ? sub.GetString() ?? "" : "";
        var issuer = root.TryGetProperty("iss", out var iss) ? iss.GetString() ?? "" : "";

        _token = new OidcToken
        {
            RawToken = rawToken,
            Subject = subject,
            Issuer = issuer
        };
    }

    public Task<OidcToken> GetTokenAsync(CancellationToken cancellationToken = default)
        => Task.FromResult(_token);
}

/// <summary>
/// No-op timestamp authority for when no TSA is configured.
/// </summary>
internal sealed class NoOpTimestampAuthority : ITimestampAuthority
{
    /// <inheritdoc />
    public Task<TimestampResponse> GetTimestampAsync(
        ReadOnlyMemory<byte> signature,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(new TimestampResponse { RawBytes = [] });
    }
}
