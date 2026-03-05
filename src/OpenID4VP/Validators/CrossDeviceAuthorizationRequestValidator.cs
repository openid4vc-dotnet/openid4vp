using OpenID4VP.Common;
using OpenID4VP.Models;
using OpenID4VC.Core.Results;

namespace OpenID4VP.Validators
{
    /// <summary>
    /// Validator for cross-device mode authorization requests (Section 3.2 of OpenID4VP spec).
    /// 
    /// Note: The cross-device flow involves TWO separate requests:
    /// 1. Minimal reference in QR code: client_id + request_uri only
    /// 2. Full AuthorizationRequest fetched from request_uri: includes nonce, response_type, etc.
    /// 
    /// This validator validates the AuthorizationRequest object representing the FULL request
    /// fetched from the request_uri endpoint (not the minimal QR code reference).
    /// 
    /// Cross-device AuthorizationRequest requirements:
    /// - MUST have: client_id, request_uri
    /// - nonce is REQUIRED (per spec: "nonce: REQUIRED... for every Authorization Request")
    /// - response_type MUST NOT be set in minimal request, but required in RequestObject
    /// - dcql_query MUST NOT be set in minimal request
    /// - scope MUST NOT be set in minimal request
    /// - redirect_uri MUST NOT be set (cross-device uses response_uri)
    /// - response_uri MUST NOT be set in minimal request
    /// </summary>
    public sealed class CrossDeviceAuthorizationRequestValidator : IValidator<AuthorizationRequest>
    {
        public Result Validate(AuthorizationRequest request)
        {
            var errors = new List<ValidationError>();

            // Check required: client_id (always required)
            if (string.IsNullOrEmpty(request.ClientId))
            {
                errors.Add(new ValidationError("client_id is REQUIRED", "client_id"));
            }

            // Check required: request_uri (for cross-device mode)
            if (string.IsNullOrEmpty(request.RequestUri))
            {
                errors.Add(new ValidationError("request_uri is REQUIRED for cross-device mode. " +
                          "It points to the endpoint where the wallet fetches the full RequestObject", "request_uri"));
            }

            // Check required: nonce (REQUIRED per OpenID4VP spec Section 5.2)
            if (string.IsNullOrEmpty(request.Nonce))
            {
                errors.Add(new ValidationError("nonce is REQUIRED for cross-device mode. " +
                          "Per spec: 'nonce: REQUIRED... for every Authorization Request'", "nonce"));
            }

            // Check forbidden: response_type
            // response_type should NOT be set in cross-device mode (it's in the RequestObject, not the minimal request)
            if (!string.IsNullOrEmpty(request.ResponseType))
            {
                errors.Add(new ValidationError("response_type MUST NOT be set in cross-device mode minimal request. " +
                          "Include it in the RequestObject on the request_uri endpoint instead", "response_type"));
            }

            // Check forbidden: dcql_query
            if (request.DcqlQuery != null)
            {
                errors.Add(new ValidationError("dcql_query MUST NOT be set in cross-device mode minimal request. " +
                          "Include it in the RequestObject on the request_uri endpoint instead", "dcql_query"));
            }

            // Check forbidden: scope
            if (!string.IsNullOrEmpty(request.Scope))
            {
                errors.Add(new ValidationError("scope MUST NOT be set in cross-device mode minimal request. " +
                          "Include it in the RequestObject on the request_uri endpoint instead", "scope"));
            }

            // Check forbidden: redirect_uri
            if (!string.IsNullOrEmpty(request.RedirectUri))
            {
                errors.Add(new ValidationError("redirect_uri MUST NOT be set in cross-device mode. " +
                          "Cross-device uses response_uri from the RequestObject for response delivery", "redirect_uri"));
            }

            // Check forbidden: response_uri
            if (!string.IsNullOrEmpty(request.ResponseUri))
            {
                errors.Add(new ValidationError("response_uri MUST NOT be set in cross-device mode minimal request. " +
                          "It comes from the RequestObject retrieved from request_uri", "response_uri"));
            }

            return errors.Count == 0
                ? Result.Success()
                : errors.Cast<Error>().ToArray();
        }
    }
}
