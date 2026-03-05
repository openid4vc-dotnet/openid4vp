using System.IdentityModel.Tokens.Jwt;
using System.Text;
using OpenID4VC.Core.Results;

namespace OpenID4VP.Parsers;

/// <summary>
/// Extracts the JSON payload from a JWT token.
/// </summary>
public sealed class JwtPayloadExtractor
{
    /// <summary>
    /// Extracts the payload from a JwtSecurityToken by decoding the JWT
    /// and retrieving the middle part (payload) as JSON.
    /// </summary>
    /// <param name="jwtToken">The JWT token to extract payload from</param>
    /// <returns>A Result containing the JSON payload if successful, or an error if extraction fails</returns>
    public Result<string> ExtractPayloadJson(JwtSecurityToken jwtToken)
    {
        if (jwtToken == null)
            return ParserErrors.InvalidJsonInput();

        // Recreate the full JWT to extract the payload
        var handler = new JwtSecurityTokenHandler();
        var tokenString = handler.WriteToken(jwtToken);

        // Split the JWT into its three parts: header.payload.signature
        var parts = tokenString.Split('.');
        if (parts.Length != 3)
            return ParserErrors.InvalidJsonInput();

        var payloadPart = parts[1];

        // Add padding if necessary (JWT uses base64url without padding)
        var padding = new string('=', (4 - payloadPart.Length % 4) % 4);
        var base64 = payloadPart.Replace('-', '+').Replace('_', '/') + padding;

        // Decode from base64
        var payloadBytes = Convert.FromBase64String(base64);
        var payloadJson = Encoding.UTF8.GetString(payloadBytes);

        return payloadJson;
    }
}
