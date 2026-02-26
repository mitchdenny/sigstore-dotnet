namespace Sigstore.Oidc;

/// <summary>
/// Provider for obtaining OIDC identity tokens for Sigstore signing.
/// </summary>
public interface IOidcTokenProvider
{
    /// <summary>
    /// Obtains an OIDC identity token for use with Fulcio.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The OIDC token.</returns>
    Task<OidcToken> GetTokenAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// An OIDC identity token with extracted metadata.
/// </summary>
public class OidcToken
{
    /// <summary>
    /// The raw JWT token string.
    /// </summary>
    public required string RawToken { get; init; }

    /// <summary>
    /// The subject (identity) from the token (e.g., email or workflow URI).
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// The OIDC issuer URL.
    /// </summary>
    public required string Issuer { get; init; }
}
