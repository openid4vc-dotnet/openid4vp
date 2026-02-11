using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenID4VP.Models;

/// <summary>
/// Represents Verifier metadata in the Authorization Request.
/// Contains information about the Verifier that the Wallet should know about.
///
/// Specification: OpenID for Verifiable Presentations 1.0, Section 5.1
/// </summary>
public sealed record VerifierMetadata
{
    [JsonConstructor]
    internal VerifierMetadata() { }

    /// <summary>
    /// OPTIONAL. A JSON Web Key Set (JWKS) containing one or more public keys.
    /// May be used by the Wallet for encryption of the Authorization Response or 
    /// to generate Verifiable Presentations.
    /// Each JWK in the set MUST have a "kid" (Key ID) parameter.
    /// Specification: Section 5.1
    /// </summary>
    [JsonPropertyName("jwks")]
    public JsonElement? Jwks { get; init; }

    /// <summary>
    /// OPTIONAL. Non-empty array of JWE "enc" algorithms that can be used for 
    /// encrypting the response.
    /// MUST be present when response_mode requires encryption (e.g., direct_post.jwt),
    /// except for the default single value of "A128GCM".
    /// Specification: Section 5.1
    /// </summary>
    [JsonPropertyName("encrypted_response_enc_values_supported")]
    public IReadOnlyList<string>? EncryptedResponseEncValuesSupported { get; init; }

    /// <summary>
    /// REQUIRED (when not available via other mechanism). 
    /// A JSON object mapping Credential Format Identifiers to their supported parameters.
    /// Specification: Section 5.1
    /// </summary>
    [JsonPropertyName("vp_formats_supported")]
    public JsonElement? VpFormatsSupported { get; init; }

    /// <summary>
    /// Additional metadata fields not defined in this specification.
    /// These should be preserved during serialization/deserialization.
    /// </summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; init; }
}
