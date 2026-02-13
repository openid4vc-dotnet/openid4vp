using OpenID4VP.Common;
using OpenID4VP.Models;

namespace OpenID4VP.Validators
{
    /// <summary>
    /// Validator for cross-device mode minimal authorization requests (Section 3.2 of OpenID4VP spec).
    /// 
    /// Cross-device minimal request requirements:
    /// - ONLY contains: client_id, request_uri, and optionally state
    /// - response_mode can be "direct_post" or "direct_post.jwt" (but not required in minimal request)
    /// - response_type MUST NOT be set
    /// - nonce MUST NOT be set
    /// - dcql_query MUST NOT be set
    /// - scope MUST NOT be set
    /// - redirect_uri MUST NOT be set
    /// - response_uri MUST NOT be set
    /// 
    /// Per spec: "In order to keep the size of the QR Code small and be able to sign and optionally 
    /// encrypt the Request Object, the actual Authorization Request contains only the Client Identifier 
    /// and Request URI"
    /// </summary>
    public sealed class CrossDeviceAuthorizationRequestValidator : IValidator<AuthorizationRequest>
    {
        public ValidationResult Validate(AuthorizationRequest request)
        {
            var errors = new List<string>();

            // Check required: client_id (always required)
            if (string.IsNullOrEmpty(request.ClientId))
            {
                errors.Add("client_id is REQUIRED");
            }

            // Check required: request_uri (for cross-device minimal request)
            if (string.IsNullOrEmpty(request.RequestUri))
            {
                errors.Add("request_uri is REQUIRED for cross-device mode. " +
                          "It points to the endpoint where the wallet fetches the full RequestObject");
            }

            // Check response_mode (if set, should be direct_post or direct_post.jwt)
            if (!string.IsNullOrEmpty(request.ResponseMode) &&
                request.ResponseMode != "direct_post" &&
                request.ResponseMode != "direct_post.jwt")
            {
                errors.Add($"response_mode '{request.ResponseMode}' is not valid for cross-device mode. " +
                          "Cross-device requires 'direct_post' or 'direct_post.jwt'");
            }

            // Check forbidden: response_type
            // response_type should NOT be set in minimal cross-device request (should be null)
            if (!string.IsNullOrEmpty(request.ResponseType))
            {
                errors.Add("response_type MUST NOT be set in cross-device mode minimal request. " +
                          "Include it in the RequestObject on the request_uri endpoint instead");
            }

            // Check forbidden: nonce
            // Nonce should NOT be set in minimal cross-device request (will be null if not explicitly set)
            if (!string.IsNullOrEmpty(request.Nonce))
            {
                errors.Add("nonce MUST NOT be set in cross-device mode minimal request. " +
                          "Include it in the RequestObject on the request_uri endpoint instead");
            }

            // Check forbidden: dcql_query
            if (request.DcqlQuery != null)
            {
                errors.Add("dcql_query MUST NOT be set in cross-device mode minimal request. " +
                          "Include it in the RequestObject on the request_uri endpoint instead");
            }

            // Check forbidden: scope
            if (!string.IsNullOrEmpty(request.Scope))
            {
                errors.Add("scope MUST NOT be set in cross-device mode minimal request. " +
                          "Include it in the RequestObject on the request_uri endpoint instead");
            }

            // Check forbidden: redirect_uri
            if (!string.IsNullOrEmpty(request.RedirectUri))
            {
                errors.Add("redirect_uri MUST NOT be set in cross-device mode. " +
                          "Cross-device uses response_uri from the RequestObject for response delivery");
            }

            // Check forbidden: response_uri
            if (!string.IsNullOrEmpty(request.ResponseUri))
            {
                errors.Add("response_uri MUST NOT be set in cross-device mode minimal request. " +
                          "It comes from the RequestObject retrieved from request_uri");
            }

            return errors.Count == 0
                ? ValidationResult.Success()
                : ValidationResult.Failure(errors);
        }
    }
}
