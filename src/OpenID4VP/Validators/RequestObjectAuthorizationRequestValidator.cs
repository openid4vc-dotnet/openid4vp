using OpenID4VP.Common;
using OpenID4VP.Models;
using OpenID4VC.Core.Results;

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
        public Result Validate(AuthorizationRequest request)
        {
            var errors = new List<ValidationError>();

            // Check required: response_type
            if (string.IsNullOrEmpty(request.ResponseType) || request.ResponseType != "vp_token")
            {
                errors.Add(new ValidationError("response_type is REQUIRED and must be 'vp_token' for Request Object", "response_type"));
            }

            // Check required: nonce
            if (string.IsNullOrEmpty(request.Nonce))
            {
                errors.Add(new ValidationError("nonce is REQUIRED for Request Object", "nonce"));
            }

            // Check required: dcql_query OR scope (at least one, not both)
            var hasDcql = request.DcqlQuery != null;
            var hasScope = !string.IsNullOrEmpty(request.Scope);

            if (!hasDcql && !hasScope)
            {
                errors.Add(new ValidationError("Either dcql_query or scope MUST be set for Request Object", "dcql_query"));
            }
            else if (hasDcql && hasScope)
            {
                errors.Add(new ValidationError("Only one of dcql_query or scope can be set in Request Object, not both", "dcql_query"));
            }

            // Check required: response_uri (where wallet sends response back)
            if (string.IsNullOrEmpty(request.ResponseUri))
            {
                errors.Add(new ValidationError("response_uri is REQUIRED for Request Object. " +
                          "It specifies where the wallet returns the authorization response via HTTP POST", "response_uri"));
            }

            // Check required: client_id
            if (string.IsNullOrEmpty(request.ClientId))
            {
                errors.Add(new ValidationError("client_id is REQUIRED", "client_id"));
            }

            // Check forbidden: request_uri (request_uri is in minimal request, not in RequestObject)
            if (!string.IsNullOrEmpty(request.RequestUri))
            {
                errors.Add(new ValidationError("request_uri MUST NOT be set in Request Object. " +
                          "request_uri is specified in the minimal cross-device request, not in the Request Object itself", "request_uri"));
            }

            // Check forbidden: redirect_uri (cross-device uses response_uri, not redirect_uri)
            if (!string.IsNullOrEmpty(request.RedirectUri))
            {
                errors.Add(new ValidationError("redirect_uri MUST NOT be set in Request Object. " +
                          "Cross-device flow uses response_uri for response delivery", "redirect_uri"));
            }

            return errors.Count == 0
                ? Result.Success()
                : errors.Cast<Error>().ToArray();
        }
    }
}
