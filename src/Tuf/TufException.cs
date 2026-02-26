namespace Tuf;

/// <summary>
/// Exception thrown when a TUF operation fails due to a security violation or protocol error.
/// </summary>
public class TufException : Exception
{
    /// <summary>
    /// Creates a new TUF exception with the specified message.
    /// </summary>
    public TufException(string message) : base(message) { }

    /// <summary>
    /// Creates a new TUF exception with the specified message and inner exception.
    /// </summary>
    public TufException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// Exception thrown when TUF metadata has expired.
/// </summary>
public class TufExpiredException : TufException
{
    /// <summary>
    /// The role whose metadata has expired.
    /// </summary>
    public string Role { get; }

    /// <summary>
    /// When the metadata expired.
    /// </summary>
    public DateTimeOffset Expiry { get; }

    /// <summary>
    /// Creates a new expiry exception.
    /// </summary>
    public TufExpiredException(string role, DateTimeOffset expiry)
        : base($"TUF {role} metadata expired at {expiry:O}.")
    {
        Role = role;
        Expiry = expiry;
    }
}
