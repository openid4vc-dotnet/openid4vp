using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenID4VP.Models;

/// <summary>
/// Unified metadata for Verifier/Client in Authorization Requests per OpenID4VP spec Section 5.1.
/// 
/// Contains information about the Verifier that the Wallet should know about, including:
/// - Basic identification (client_name, logo_uri, jwks_uri)
/// - Public keys for signature verification (jwks)
/// - Response encryption preferences (encrypted_response_enc_values_supported)
/// - Supported VP formats (vp_formats_supported)
/// - Additional metadata fields for extensibility
/// 
/// All keys in the JWKS MUST be public keys only. Private keys should never be transmitted.
/// Specification: OpenID for Verifiable Presentations 1.0, Section 5.1
/// </summary>
public sealed record ClientMetadata
{
    [JsonConstructor]
    internal ClientMetadata() { }

    /// <summary>
    /// OPTIONAL. Human-readable name of the Verifier (e.g., "My Company Verifier").
    /// Used for UI display in the Wallet.
    /// </summary>
    [JsonPropertyName("client_name")]
    public string? ClientName { get; init; }

    /// <summary>
    /// OPTIONAL. URL of the Verifier's logo image.
    /// Used for UI display in the Wallet.
    /// </summary>
    [JsonPropertyName("logo_uri")]
    public string? LogoUri { get; init; }

    /// <summary>
    /// OPTIONAL. URL where the Wallet can fetch the Verifier's JWKS.
    /// Used if JWKS is not provided inline via the 'jwks' parameter.
    /// </summary>
    [JsonPropertyName("jwks_uri")]
    public string? JwksUri { get; init; }

    /// <summary>
    /// OPTIONAL. A JSON Web Key Set (JWKS) containing one or more public keys.
    /// May be used by the Wallet for encryption of the Authorization Response,
    /// to generate Verifiable Presentations, or to verify signatures on Authorization Requests (JAR).
    /// Each JWK in the set MUST have a "kid" (Key ID) parameter.
    /// 
    /// IMPORTANT: Must contain ONLY public keys. Private keys should never be included.
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
    /// OPTIONAL. A JSON object mapping Credential Format Identifiers to their supported parameters.
    /// Required when not available via other mechanism.
    /// Specification: Section 5.1
    /// </summary>
    [JsonPropertyName("vp_formats_supported")]
    public JsonElement? VpFormatsSupported { get; init; }

    /// <summary>
    /// Additional metadata fields not defined in this specification.
    /// These are preserved during serialization/deserialization for extensibility.
    /// </summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; init; }
}
