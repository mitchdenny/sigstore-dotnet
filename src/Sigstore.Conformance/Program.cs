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
    private static readonly Uri StagingTufMetadataUrl = new("https://tuf-repo-cdn.sigstage.dev/");
    private static readonly Uri StagingTufTargetsUrl = new("https://tuf-repo-cdn.sigstage.dev/targets/");

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
        var stagingOption = new Option<bool>("--staging", "Use Sigstore staging infrastructure");
        var inTotoOption = new Option<bool>("--in-toto", "Treat input as an in-toto statement");
        var identityTokenOption = new Option<string>("--identity-token", "OIDC identity token") { Required = true };
        var bundleOption = new Option<string>("--bundle", "Path to write the bundle to") { Required = true };
        var trustedRootOption = new Option<string?>("--trusted-root", "Path to a custom trusted root");
        var signingConfigOption = new Option<string?>("--signing-config", "Path to a custom signing config");
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

            try
            {
                await SignBundleAsync(staging, inToto, identityToken, bundlePath,
                    trustedRootPath, signingConfigPath, file, cancellationToken);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex}");
                Environment.ExitCode = 1;
            }
        });

        return command;
    }

    private static Command BuildVerifyBundleCommand()
    {
        var stagingOption = new Option<bool>("--staging", "Use Sigstore staging infrastructure");
        var bundleOption = new Option<string>("--bundle", "Path to the Sigstore bundle") { Required = true };
        var certIdentityOption = new Option<string?>("--certificate-identity", "Expected certificate identity");
        var certIssuerOption = new Option<string?>("--certificate-oidc-issuer", "Expected OIDC issuer");
        var keyOption = new Option<string?>("--key", "Path to PEM-encoded public key");
        var trustedRootOption = new Option<string?>("--trusted-root", "Path to a custom trusted root");
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

            try
            {
                await VerifyBundleAsync(staging, bundlePath, certIdentity, certIssuer,
                    keyPath, trustedRootPath, fileOrDigest, cancellationToken);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex}");
                Environment.ExitCode = 1;
            }
        });

        return command;
    }

    private static async Task SignBundleAsync(bool staging, bool inToto, string identityToken,
        string bundlePath, string? trustedRootPath, string? signingConfigPath, string file,
        CancellationToken cancellationToken)
    {
        // Create trust root provider
        using var trustRootProvider = CreateTrustRootProvider(staging, trustedRootPath);

        // Get the trust root to extract service URLs
        var trustRoot = await trustRootProvider.GetTrustRootAsync(cancellationToken);

        // Find Fulcio URL
        var fulcioUrl = trustRoot.CertificateAuthorities
            .Where(ca => ca.ValidTo == null || ca.ValidTo > DateTimeOffset.UtcNow)
            .Select(ca => ca.Uri)
            .FirstOrDefault() ?? throw new InvalidOperationException("No Fulcio CA found in trust root");

        // Find Rekor URL
        var rekorUrl = trustRoot.TransparencyLogs
            .Where(l => l.ValidTo == null || l.ValidTo > DateTimeOffset.UtcNow)
            .Select(l => l.BaseUrl)
            .FirstOrDefault() ?? throw new InvalidOperationException("No Rekor log found in trust root");

        // Find TSA URL (optional)
        var tsaUrl = trustRoot.TimestampAuthorities
            .Where(t => t.ValidTo == null || t.ValidTo > DateTimeOffset.UtcNow)
            .Select(t => t.Uri)
            .FirstOrDefault();

        // Create HTTP clients
        using var fulcio = new FulcioHttpClient(new Uri(fulcioUrl));
        using var rekor = new RekorHttpClient(new Uri(rekorUrl));
        ITimestampAuthority tsa = tsaUrl != null
            ? new HttpTimestampAuthority(new Uri(tsaUrl))
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
            // Key-based verification — not yet supported
            throw new NotSupportedException("Public key verification is not yet supported.");
        }

        var verifier = new SigstoreVerifier(trustRootProvider);

        // Determine if input is a digest or file path
        if (IsDigestInput(fileOrDigest))
        {
            // For digest-based verification with DSSE/in-toto bundles
            if (bundle.DsseEnvelope != null)
            {
                VerifyInTotoSubjectDigest(bundle.DsseEnvelope, fileOrDigest);
                // For DSSE verification, we don't need the artifact stream
                // The verifier checks the PAE signature, not the artifact hash
                using var emptyStream = new MemoryStream();
                await verifier.VerifyAsync(emptyStream, bundle, policy, cancellationToken);
            }
            else
            {
                // For message signature bundles, verify the digest matches
                var hexDigest = fileOrDigest["sha256:".Length..];
                var digestBytes = Convert.FromHexString(hexDigest);

                if (bundle.MessageSignature?.MessageDigest != null &&
                    !bundle.MessageSignature.MessageDigest.Digest.AsSpan().SequenceEqual(digestBytes))
                {
                    throw new VerificationException("Provided digest does not match bundle's message digest.");
                }

                // Create a stream whose hash matches the expected digest
                // Since the verifier compares computed hash vs bundle digest,
                // and we've already verified they match, we need the artifact bytes
                // We can't reconstruct the artifact from just a digest,
                // but the verifier only needs the hash to match the bundle's hash.
                // Pass the raw digest bytes — the verifier will hash them and compare
                // against the bundle's digest. This won't match unless the bundle's digest
                // IS the hash of the digest bytes, which it isn't.
                // Instead, we need to bypass artifact hashing for digest-only verification.
                throw new NotSupportedException("Digest-only verification for message signatures requires library support.");
            }
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
        if (staging)
        {
            return new DisposableTrustRootProvider(new TufTrustRootProvider(new TufTrustRootProviderOptions
            {
                MetadataBaseUrl = StagingTufMetadataUrl,
                TargetsBaseUrl = StagingTufTargetsUrl
            }));
        }
        return new DisposableTrustRootProvider(new TufTrustRootProvider());
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
