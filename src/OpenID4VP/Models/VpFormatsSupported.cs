using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenID4VP.Models;

/// <summary>
/// Represents the VP (Verifiable Presentation) formats supported by the Verifier/Client.
/// 
/// Maps Credential Format Identifiers to their supported parameters and algorithms.
/// Per OpenID4VP spec Section 5.1 and Appendix B, this defines what credential formats the Verifier
/// can accept and their specific requirements, algorithms, and options.
/// 
/// Example structure:
/// {
///   "jwt_vc_json": {
///     "alg_values": ["ES256K", "ES384"]
///   },
///   "mso_mdoc": {}
/// }
/// 
/// Specification: OpenID for Verifiable Presentations 1.0, Section 5.1 and Appendix B
/// </summary>
public sealed record VpFormatsSupported
{
    [JsonConstructor]
    public VpFormatsSupported() { }

    /// <summary>
    /// A dictionary mapping credential format identifiers (e.g., "jwt_vc_json", "mso_mdoc", "dc+sd-jwt")
    /// to their supported parameters and algorithms.
    /// 
    /// Each credential format identifier maps to a JSON object containing format-specific
    /// parameters, such as supported algorithms, proof types, or other constraints.
    /// 
    /// Format-specific parameter examples (see Appendix B of the spec):
    /// - "jwt_vc_json": may contain "alg_values" for supported signing algorithms
    /// - "dc+sd-jwt": may contain "sd-jwt_alg_values" and "kb-jwt_alg_values"
    /// - "mso_mdoc": may be empty or contain format-specific constraints
    /// </summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Formats { get; init; }
}
