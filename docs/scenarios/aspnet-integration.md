# ASP.NET Core Integration

This guide shows how to use sigstore-dotnet with ASP.NET Core's dependency injection system.

## Register Services

```csharp
// Program.cs
using Sigstore;

var builder = WebApplication.CreateBuilder(args);

// Register the verifier as a singleton (it's thread-safe)
builder.Services.AddSingleton<SigstoreVerifier>();

// Or with a custom trust root
builder.Services.AddSingleton<ITrustRootProvider>(
    new TufTrustRootProvider(TufTrustRootProvider.ProductionUrl));
builder.Services.AddSingleton<SigstoreVerifier>(sp =>
    new SigstoreVerifier(sp.GetRequiredService<ITrustRootProvider>()));

var app = builder.Build();
```

## Verify Uploads in an Endpoint

```csharp
app.MapPost("/api/artifacts/verify", async (
    IFormFile artifact,
    IFormFile bundle,
    SigstoreVerifier verifier) =>
{
    var bundleJson = await new StreamReader(bundle.OpenReadStream()).ReadToEndAsync();
    var sigstoreBundle = SigstoreBundle.Deserialize(bundleJson);

    var policy = new VerificationPolicy
    {
        CertificateIdentity = CertificateIdentity.ForGitHubActions(
            repository: "myorg/myapp")
    };

    var (success, result) = await verifier.TryVerifyAsync(
        artifact.OpenReadStream(), sigstoreBundle, policy);

    return success
        ? Results.Ok(new { signer = result!.SignerIdentity!.SubjectAlternativeName })
        : Results.BadRequest(new { error = result?.FailureReason });
});
```

## Verify in a Background Service

```csharp
public class ArtifactVerificationService : BackgroundService
{
    private readonly SigstoreVerifier _verifier;
    private readonly ILogger<ArtifactVerificationService> _logger;

    public ArtifactVerificationService(
        SigstoreVerifier verifier,
        ILogger<ArtifactVerificationService> logger)
    {
        _verifier = verifier;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Poll for new artifacts to verify...
        var policy = new VerificationPolicy
        {
            CertificateIdentity = CertificateIdentity.ForGitHubActions("myorg/myapp")
        };

        var result = await _verifier.VerifyAsync(
            new FileInfo("artifact.tar.gz"),
            new FileInfo("artifact.sigstore.json"),
            policy,
            stoppingToken);

        _logger.LogInformation("Verified artifact signed by {Identity}",
            result.SignerIdentity?.SubjectAlternativeName);
    }
}
```

## Custom Trust Root via Configuration

```csharp
builder.Services.AddSingleton<ITrustRootProvider>(sp =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    var trustRootPath = config["Sigstore:TrustRootPath"];

    return trustRootPath is not null
        ? new FileTrustRootProvider(new FileInfo(trustRootPath))
        : new TufTrustRootProvider(TufTrustRootProvider.ProductionUrl);
});
```

```json
// appsettings.json
{
    "Sigstore": {
        "TrustRootPath": "/etc/sigstore/trusted_root.json"
    }
}
```

## See Also

- [Verify a Bundle](verify-bundle.md) — verification options
- [Custom Trust Root](custom-trust-root.md) — private deployments
