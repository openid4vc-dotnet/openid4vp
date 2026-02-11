namespace OpenID4VP.Common;

/// <summary>
/// Common parameter names and constants from the OpenID4VP specification.
/// Specification: OpenID for Verifiable Presentations 1.0, throughout
/// </summary>
public static class ParameterNames
{
    // Authorization Request Parameters
    public const string ClientId = "client_id";
    public const string ResponseType = "response_type";
    public const string ResponseMode = "response_mode";
    public const string ResponseUri = "response_uri";
    public const string DcqlQuery = "dcql_query";
    public const string State = "state";
    public const string Nonce = "nonce";
    public const string RequestUri = "request_uri";
    public const string RequestUriMethod = "request_uri_method";
    public const string ClientMetadata = "client_metadata";
    public const string VerifierInfo = "verifier_info";
    public const string WalletNonce = "wallet_nonce";
    public const string TransactionData = "transaction_data";
    
    // Response Parameters
    public const string VpToken = "vp_token";
    public const string PresentationSubmission = "presentation_submission";
    public const string IdToken = "id_token";
    public const string Code = "code";
    public const string State_Response = "state";
    public const string Error = "error";
    public const string ErrorDescription = "error_description";
    public const string ErrorUri = "error_uri";
}
