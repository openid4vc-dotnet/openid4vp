namespace OpenID4VC.Core.Results;

/// <summary>
/// Error type for validation failures.
/// Used when data validation rules are violated.
/// </summary>
public sealed class ValidationError : Error
{
    /// <summary>
    /// Gets the name of the property/field that failed validation.
    /// Can be null for general validation errors not tied to a specific field.
    /// </summary>
    public string? PropertyName { get; }

    /// <summary>
    /// Initializes a new instance of the ValidationError class.
    /// </summary>
    /// <param name="message">The human-readable error message.</param>
    /// <param name="propertyName">Optional name of the property that failed validation.</param>
    public ValidationError(string message, string? propertyName = null)
        : base("validation_error", message)
    {
        PropertyName = propertyName;
    }
}

/// <summary>
/// Error type for parsing/deserialization failures.
/// Used when converting data from one format to another fails (e.g., JSON parsing, JWT decoding).
/// </summary>
public sealed class ParseError : Error
{
    /// <summary>
    /// Gets the input value that failed to parse.
    /// Can be the raw JSON, JWT string, etc. Useful for debugging.
    /// </summary>
    public string? InputValue { get; }

    /// <summary>
    /// Initializes a new instance of the ParseError class.
    /// </summary>
    /// <param name="message">The human-readable error message describing what went wrong.</param>
    /// <param name="inputValue">Optional: the raw input that failed to parse.</param>
    public ParseError(string message, string? inputValue = null)
        : base("parse_error", message)
    {
        InputValue = inputValue;
    }
}

/// <summary>
/// Error type for domain/business logic failures.
/// Used when an operation violates domain rules or constraints.
/// </summary>
public sealed class DomainError : Error
{
    /// <summary>
    /// Gets an optional error code specific to the domain (e.g., "insufficient_balance", "invalid_state_transition").
    /// This allows clients to handle specific domain errors programmatically.
    /// </summary>
    public string? DomainCode { get; }

    /// <summary>
    /// Initializes a new instance of the DomainError class.
    /// </summary>
    /// <param name="message">The human-readable error message.</param>
    /// <param name="domainCode">Optional domain-specific error code for programmatic handling.</param>
    public DomainError(string message, string? domainCode = null)
        : base("domain_error", message)
    {
        DomainCode = domainCode;
    }
}

/// <summary>
/// Error type for external system failures.
/// Used when calling external services (APIs, databases, identity providers) fails.
/// </summary>
public sealed class ExternalError : Error
{
    /// <summary>
    /// Gets the name of the external system that failed (e.g., "IssuerService", "CredentialRepository").
    /// </summary>
    public string? ExternalSystem { get; }

    /// <summary>
    /// Gets the HTTP status code if applicable (e.g., 500, 503, 404).
    /// </summary>
    public int? HttpStatusCode { get; }

    /// <summary>
    /// Initializes a new instance of the ExternalError class.
    /// </summary>
    /// <param name="message">The human-readable error message.</param>
    /// <param name="externalSystem">Optional name of the external system that failed.</param>
    /// <param name="httpStatusCode">Optional HTTP status code if the failure was HTTP-related.</param>
    public ExternalError(string message, string? externalSystem = null, int? httpStatusCode = null)
        : base("external_error", message)
    {
        ExternalSystem = externalSystem;
        HttpStatusCode = httpStatusCode;
    }
}

/// <summary>
/// Error type for JSON parsing/deserialization failures.
/// Used when JSON document structure is malformed or invalid.
/// Distinct from ParseError (which is broader - could be JWT, XML, etc.).
/// </summary>
public sealed class JsonError : Error
{
    /// <summary>
    /// Gets the JSON content that failed to parse (truncated if very long).
    /// Useful for debugging malformed JSON structures.
    /// </summary>
    public string? JsonContent { get; }

    /// <summary>
    /// Gets the line number where the parse error occurred (if available from JsonException).
    /// Helps pinpoint the exact location of the problem in large JSON documents.
    /// </summary>
    public long? LineNumber { get; }

    /// <summary>
    /// Gets the byte position in the JSON where the parse error occurred (if available).
    /// Useful for precise error reporting and editor integration.
    /// </summary>
    public long? BytePosition { get; }

    /// <summary>
    /// Initializes a new instance of the JsonError class.
    /// </summary>
    /// <param name="message">The human-readable error message describing what went wrong.</param>
    /// <param name="jsonContent">Optional: the raw JSON content that failed to parse.</param>
    /// <param name="lineNumber">Optional: the line number where the error occurred.</param>
    /// <param name="bytePosition">Optional: the byte position where the error occurred.</param>
    public JsonError(string message, string? jsonContent = null, long? lineNumber = null, long? bytePosition = null)
        : base("json_error", message)
    {
        JsonContent = jsonContent;
        LineNumber = lineNumber;
        BytePosition = bytePosition;
    }
}
