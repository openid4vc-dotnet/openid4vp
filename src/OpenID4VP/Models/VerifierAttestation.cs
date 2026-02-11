using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenID4VP.Models;

/// <summary>
/// Represents a Verifier attestation in the Authorization Request.
/// Attestations provide information about the Verifier relevant to the Credential Request,
/// such as Verifier metadata, policies, trust status, or authorizations.
///
/// Specification: OpenID for Verifiable Presentations 1.0, Section 5.1
/// </summary>
public sealed record VerifierAttestation
{
    [JsonConstructor]
    internal VerifierAttestation() { }

    /// <summary>
    /// REQUIRED. A string that identifies the format of the attestation and how it is encoded.
    /// Ecosystems SHOULD use collision-resistant identifiers.
    /// Specification: Section 5.1
    /// </summary>
    [JsonPropertyName("format")]
    public required string Format { get; init; }

    /// <summary>
    /// REQUIRED. An object or string containing an attestation (e.g., a JWT).
    /// The payload structure is defined on a per-format level.
    /// Specification: Section 5.1
    /// </summary>
    [JsonPropertyName("data")]
    public required JsonElement Data { get; init; }

    /// <summary>
    /// OPTIONAL. Non-empty array of strings each referencing a Credential requested by the Verifier
    /// for which the attestation is relevant.
    /// Each string matches the "id" field in a DCQL Credential Query.
    /// If omitted, the attestation is relevant to all requested Credentials.
    /// Specification: Section 5.1
    /// </summary>
    [JsonPropertyName("credential_ids")]
    public IReadOnlyList<string>? CredentialIds { get; init; }
}
