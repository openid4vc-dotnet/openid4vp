using OpenID4VP.Models;
using OpenID4VC.Core.Results;

namespace OpenID4VP.Builders
{
    /// <summary>
    /// Extensions for converting AuthorizationRequest to URI query parameters.
    /// 
    /// Used for cross-device flow to generate QR code URIs. Per OpenID4VP Spec Section 3.2,
    /// the minimal request in the QR code contains only:
    /// - client_id (REQUIRED)
    /// - request_uri (REQUIRED)
    /// - response_mode (optional but typically included)
    /// - state (optional)
    /// 
    /// Other parameters (nonce, response_type, dcql_query, redirect_uri) are in the 
    /// full AuthorizationRequest fetched from the request_uri endpoint.
    /// </summary>
    public static class AuthorizationRequestUriExtensions
    {
        /// <summary>
        /// Converts a successful AuthorizationRequest to a web-safe URI with query parameters
        /// suitable for QR code encoding.
        /// </summary>
        /// <param name="result">The Result containing a successful AuthorizationRequest</param>
        /// <param name="baseUri">The base URI to which query parameters will be appended (e.g., "https://verifier.example.com/auth")</param>
        /// <returns>A complete URI with encoded query parameters</returns>
        /// <exception cref="InvalidOperationException">Thrown if result is not successful</exception>
        public static string ToUri(this Result<AuthorizationRequest> result, string baseUri)
        {
            if (!result.IsSuccess)
                throw new InvalidOperationException("Cannot convert failed result to URI. Check result.IsSuccess before calling ToUri().");

            if (string.IsNullOrEmpty(baseUri))
                throw new ArgumentNullException(nameof(baseUri), "Base URI cannot be null or empty.");

            var request = result.Value!;
            var queryParams = new Dictionary<string, string>();

            // REQUIRED parameters
            if (!string.IsNullOrEmpty(request.ClientId))
                queryParams["client_id"] = request.ClientId;

            if (!string.IsNullOrEmpty(request.RequestUri))
                queryParams["request_uri"] = request.RequestUri;

            // OPTIONAL parameters for minimal request
            if (!string.IsNullOrEmpty(request.ResponseMode))
                queryParams["response_mode"] = request.ResponseMode;

            if (!string.IsNullOrEmpty(request.State))
                queryParams["state"] = request.State;

            // NOTE: The following are NOT included in the minimal request (QR code)
            // They are in the full AuthorizationRequest fetched from request_uri:
            // - nonce (NEVER in minimal request per spec Section 3.2)
            // - response_type (in RequestObject)
            // - dcql_query (in RequestObject)
            // - redirect_uri (in RequestObject)

            return BuildUriWithQueryParameters(baseUri, queryParams);
        }

        /// <summary>
        /// Builds a complete URI by appending encoded query parameters to a base URI.
        /// </summary>
        private static string BuildUriWithQueryParameters(string baseUri, Dictionary<string, string> parameters)
        {
            if (parameters.Count == 0)
                return baseUri;

            var encodedParams = parameters
                .Where(kvp => !string.IsNullOrEmpty(kvp.Value))
                .Select(kvp => $"{Uri.EscapeDataString(kvp.Key)}={Uri.EscapeDataString(kvp.Value)}")
                .ToList();

            if (encodedParams.Count == 0)
                return baseUri;

            var queryString = string.Join("&", encodedParams);
            var separator = baseUri.Contains("?") ? "&" : "?";

            return $"{baseUri}{separator}{queryString}";
        }
    }
}
