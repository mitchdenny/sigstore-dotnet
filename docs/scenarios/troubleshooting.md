# Troubleshooting

Common issues and how to resolve them.

## Verification Failures

### "Certificate identity mismatch"

**Cause:** The certificate's Subject Alternative Name or OIDC issuer doesn't match your `VerificationPolicy`.

**Fix:** Check exactly what identity was used to sign:

```csharp
// Use TryVerifyStreamAsync with a permissive policy first to inspect the bundle
var (success, result) = await verifier.TryVerifyStreamAsync(artifact, bundle,
    new VerificationPolicy());

if (result?.SignerIdentity != null)
{
    Console.WriteLine($"SAN: {result.SignerIdentity.SubjectAlternativeName}");
    Console.WriteLine($"Issuer: {result.SignerIdentity.Issuer}");
}
```

Then update your policy to match. For GitHub Actions, the SAN is a URL like:
```
https://github.com/owner/repo/.github/workflows/ci.yml@refs/heads/main
```

### "No verified transparency log entries"

**Cause:** The bundle doesn't contain a valid Rekor transparency log entry, or the log entry couldn't be verified.

**Fix:**
- Ensure the artifact was signed with Rekor logging enabled
- Check that the bundle contains `tlogEntries` in the verification material
- If using a private deployment, ensure your trust root includes the correct transparency log keys

### "Certificate chain validation failed"

**Cause:** The signing certificate couldn't be validated against the trust root.

**Fix:**
- Check that you're using the correct trust root for the deployment that signed the artifact
- For staging-signed artifacts, use `TufTrustRootProvider.StagingUrl`
- For private deployments, use `InMemoryTrustRootProvider` with your custom root

### "SCT verification failed"

**Cause:** The Signed Certificate Timestamp embedded in the certificate couldn't be verified.

**Fix:**
- Ensure your trust root includes CT log keys
- For testing, you can disable SCT checks:
```csharp
var policy = new VerificationPolicy
{
    CertificateIdentity = identity,
    RequireSignedCertificateTimestamps = false
};
```

## Bundle Issues

### "Failed to deserialize Sigstore bundle"

**Cause:** The bundle JSON is malformed or uses an unsupported format.

**Fix:**
- Verify the file is valid JSON
- Check the `mediaType` field — supported types are:
  - `application/vnd.dev.sigstore.bundle+json;version=0.1`
  - `application/vnd.dev.sigstore.bundle+json;version=0.2`
  - `application/vnd.dev.sigstore.bundle.v0.3+json`

### Bundle Inspection

```csharp
var bundle = await SigstoreBundle.LoadAsync(new FileInfo("artifact.sigstore.json"));

Console.WriteLine($"Media Type: {bundle.MediaType}");
Console.WriteLine($"Has signature: {bundle.MessageSignature != null}");
Console.WriteLine($"Has attestation: {bundle.DsseEnvelope != null}");

if (bundle.VerificationMaterial != null)
{
    var vm = bundle.VerificationMaterial;
    Console.WriteLine($"Has certificate: {vm.Certificate.HasValue}");
    Console.WriteLine($"Tlog entries: {vm.TlogEntries.Count}");
    Console.WriteLine($"RFC 3161 timestamps: {vm.Rfc3161Timestamps.Count}");
}
```

## Network Issues

### Trust root download fails

**Cause:** The TUF trust root download from `tuf-repo-cdn.sigstore.dev` failed.

**Fix:**
- Check network connectivity
- For air-gapped environments, pre-download the trust root and use `FileTrustRootProvider`:
```csharp
var verifier = new SigstoreVerifier(
    new FileTrustRootProvider(new FileInfo("trusted_root.json")));
```

## See Also

- [Verify a Bundle](verify-bundle.md) — verification options
- [Custom Trust Root](custom-trust-root.md) — private deployments
