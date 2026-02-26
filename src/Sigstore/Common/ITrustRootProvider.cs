using Sigstore.TrustRoot;

namespace Sigstore.Common;

/// <summary>
/// Provider for obtaining the Sigstore trusted root material.
/// </summary>
public interface ITrustRootProvider
{
    /// <summary>
    /// Gets the trusted root containing CAs, transparency logs, CT logs, and TSAs.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The trusted root.</returns>
    Task<TrustedRoot> GetTrustRootAsync(CancellationToken cancellationToken = default);
}
