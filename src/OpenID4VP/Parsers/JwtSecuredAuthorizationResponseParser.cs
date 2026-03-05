using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using OpenID4VC.Core.Results;
using OpenID4VP.Models;

namespace OpenID4VP.Parsers;

/// <summary>
/// Parser for JWT-Secured Authorization Responses (JAR) as specified in RFC 9101.
/// 
/// Handles decryption of JWE (JSON Web Encryption) containing a signed JWT
/// and parses the decrypted JWT into an AuthorizationResponse object.
///
/// Specification: RFC 9101 (OAuth 2.0 JWT-Secured Authorization Request Assertion Format)
/// </summary>
public sealed class JwtSecuredAuthorizationResponseParser
{
    private static readonly AuthorizationResponseParser ResponseParser = new();
    private static readonly JwtPayloadExtractor PayloadExtractor = new();

    /// <summary>
    /// Decrypts a JWE (JSON Web Encryption) using the provided private key,
    /// extracts the JWT payload, and parses it into an AuthorizationResponse.
    /// 
    /// The JWE typically contains an Authorization Response encrypted with the public key.
    /// This method handles:
    /// 1. Decryption using the private key
    /// 2. Extraction of the JWT payload
    /// 3. Parsing the payload into an AuthorizationResponse
    /// </summary>
    /// <param name="jweToken">The encrypted JWE token as a base64url-encoded string (format: header.encrypted_key.iv.ciphertext.auth_tag)</param>
    /// <param name="privateKey">The private key used to decrypt the JWE. Must be an asymmetric key (RSA or ECDSA)</param>
    /// <returns>
    /// A Result containing the parsed AuthorizationResponse if successful,
    /// or an error if decryption or parsing fails
    /// </returns>
    /// <remarks>
    /// The JWE is decrypted to reveal the signed JWT inside. The JWT payload
    /// (containing the authorization response data) is then parsed into an
    /// AuthorizationResponse object.
    /// 
    /// Example usage:
    /// <code>
    /// var parseResult = JwtSecuredAuthorizationResponseParser.FromJar(jweToken, privateKey);
    /// if (parseResult.IsSuccess)
    /// {
    ///     var authResponse = parseResult.Value;
    ///     var vpToken = authResponse.VpToken;
    ///     // Process the authorization response
    /// }
    /// </code>
    /// </remarks>
    public static Result<AuthorizationResponse> FromJar(string jweToken, SecurityKey privateKey)
    {
        if (string.IsNullOrWhiteSpace(jweToken))
            return ParserErrors.InvalidJsonInput();

        if (privateKey == null)
            return ParserErrors.InvalidJsonInput();

        try
        {
            var handler = new JwtSecurityTokenHandler();

            // Verify the token format is valid
            if (!handler.CanReadToken(jweToken))
                return ParserErrors.InvalidJsonInput();

            // Create token validation parameters for JWE decryption
            // We disable all validation except decryption since we only want to decrypt
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = false,
                // The TokenDecryptionKey is used to decrypt JWE tokens
                TokenDecryptionKey = privateKey
            };

            // ValidateToken handles both JWE decryption and JWT validation
            // Since we've disabled all validations except for decryption,
            // this will decrypt the JWE and return the inner JWT
            var principal = handler.ValidateToken(jweToken, validationParameters, out var validatedToken);

            if (validatedToken == null)
                return ParserErrors.InvalidJsonInput();

            // Extract the JWT payload from the decrypted token
            var jwtToken = validatedToken as JwtSecurityToken;
            if (jwtToken == null)
                return ParserErrors.InvalidJsonInput();

            var payloadResult = PayloadExtractor.ExtractPayloadJson(jwtToken);
            if (!payloadResult.IsSuccess)
                return payloadResult.Errors.ToArray();

            var payloadJson = payloadResult.Value;

            // Use AuthorizationResponseParser to parse the payload into an AuthorizationResponse
            return ResponseParser.Parse(payloadJson);
        }
        catch (SecurityTokenDecryptionFailedException)
        {
            return ParserErrors.InvalidJsonInput();
        }
        catch (SecurityTokenInvalidSignatureException)
        {
            return ParserErrors.InvalidJsonInput();
        }
        catch (SecurityTokenException)
        {
            return ParserErrors.InvalidJsonInput();
        }
        catch (Exception)
        {
            return ParserErrors.InvalidJsonInput();
        }
    }
}
