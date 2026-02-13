using OpenID4VP.Common;
using OpenID4VP.Models;

namespace OpenID4VP.Validators
{
    /// <summary>
    /// Validator for Request Object authorization requests (Section 3.2 & 6 of OpenID4VP spec).
    /// 
    /// Request Object is the full authorization parameters returned when wallet fetches from request_uri.
    /// Fetched via HTTP GET from the request_uri endpoint specified in the minimal cross-device request.
    /// 
    /// Per spec: "The HTTP GET response returns the Request Object containing Authorization Request parameters"
    /// 
    /// Request Object requirements:
    /// - response_type MUST be set
    /// - nonce MUST be set
    /// - dcql_query OR scope MUST be set (not both, not neither)
    /// - response_uri MUST be set (where wallet returns the authorization response)
    /// - client_id MUST be set
    /// - request_uri MUST NOT be set (request_uri is in the minimal request, not the RequestObject itself)
    /// - redirect_uri MUST NOT be set (cross-device uses response_uri, not redirect_uri)
    /// </summary>
    public sealed class RequestObjectAuthorizationRequestValidator : IValidator<AuthorizationRequest>
    {
        public ValidationResult Validate(AuthorizationRequest request)
        {
            var errors = new List<string>();

            // Check required: response_type
            if (string.IsNullOrEmpty(request.ResponseType) || request.ResponseType == "vp_token")
            {
                // "vp_token" is the default - should be explicitly set
                if (request.ResponseType != "vp_token")
                {
                    errors.Add("response_type is REQUIRED for Request Object");
                }
            }

            // Check required: nonce
            if (string.IsNullOrEmpty(request.Nonce) || request.Nonce == "nonce")
            {
                // "nonce" is the default placeholder - should be explicitly set
                if (request.Nonce != "nonce")
                {
                    errors.Add("nonce is REQUIRED for Request Object");
                }
            }

            // Check required: dcql_query OR scope (at least one, not both)
            var hasDcql = request.DcqlQuery != null;
            var hasScope = !string.IsNullOrEmpty(request.Scope);

            if (!hasDcql && !hasScope)
            {
                errors.Add("Either dcql_query or scope MUST be set for Request Object");
            }
            else if (hasDcql && hasScope)
            {
                errors.Add("Only one of dcql_query or scope can be set in Request Object, not both");
            }

            // Check required: response_uri (where wallet sends response back)
            if (string.IsNullOrEmpty(request.ResponseUri))
            {
                errors.Add("response_uri is REQUIRED for Request Object. " +
                          "It specifies where the wallet returns the authorization response via HTTP POST");
            }

            // Check required: client_id
            if (string.IsNullOrEmpty(request.ClientId))
            {
                errors.Add("client_id is REQUIRED");
            }

            // Check forbidden: request_uri (request_uri is in minimal request, not in RequestObject)
            if (!string.IsNullOrEmpty(request.RequestUri))
            {
                errors.Add("request_uri MUST NOT be set in Request Object. " +
                          "request_uri is specified in the minimal cross-device request, not in the Request Object itself");
            }

            // Check forbidden: redirect_uri (cross-device uses response_uri, not redirect_uri)
            if (!string.IsNullOrEmpty(request.RedirectUri))
            {
                errors.Add("redirect_uri MUST NOT be set in Request Object. " +
                          "Cross-device flow uses response_uri for response delivery");
            }

            return errors.Count == 0
                ? ValidationResult.Success()
                : ValidationResult.Failure(errors);
        }
    }
}
