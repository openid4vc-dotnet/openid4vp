using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using OpenID4VP.Models;
using OpenID4VC.Core.Results;

namespace OpenID4VP.Builders;

/// <summary>
/// Context builder for fluently configuring ClientMetadata within AuthorizationRequestBuilder.
/// 
/// This builder is designed to work inline with WithClientMetadata(), providing a fluent API
/// for constructing metadata with all available options including:
/// - Basic identification (name, logo URI)
/// - JWKS with public keys for encryption of the authorization response
/// - Response encryption algorithm preferences
/// - Supported VP formats, and more
/// 
/// Pattern: .WithClientMetadata(metadata => metadata.WithName(...).WithJwks(...))
/// </summary>
public sealed class ClientMetadataBuilderContext
{
    private string? _clientName;
    private string? _logoUri;
    private string? _jwksUri;
    private JsonElement? _jwks;
    private List<string>? _encryptedResponseEncValues;
    private VpFormatsSupported? _vpFormatsSupported;
    private Dictionary<string, JsonElement>? _extensionData;
    private readonly List<Error> _errors = [];

    /// <summary>
    /// Creates a new ClientMetadataBuilderContext instance.
    /// </summary>
    public static ClientMetadataBuilderContext Create() => new();

    /// <summary>
    /// Sets the human-readable name of the Verifier/Client.
    /// </summary>
    public ClientMetadataBuilderContext WithName(string? clientName)
    {
        _clientName = clientName;
        return this;
    }

    /// <summary>
    /// Sets the logo URI for the Verifier/Client.
    /// </summary>
    public ClientMetadataBuilderContext WithLogoUri(string? logoUri)
    {
        _logoUri = logoUri;
        return this;
    }

    /// <summary>
    /// Sets the JWKS URI where public keys can be fetched.
    /// </summary>
    public ClientMetadataBuilderContext WithJwksUri(string? jwksUri)
    {
        _jwksUri = jwksUri;
        return this;
    }

    /// <summary>
    /// Sets the JWKS (JSON Web Key Set) containing public keys for encrypting the authorization response.
    /// The Wallet uses these public keys to encrypt the VP Token that is returned in the authorization response.
    /// 
    /// The JWKS must contain ONLY public keys, and each key MUST have:
    /// - "kid" (Key ID) - for the wallet to identify which key to use for encryption
    /// - "alg" (Algorithm) - for the wallet to know which algorithm this key supports
    /// - "use" (Key Usage) - must be "enc" (encryption) since these keys are for encrypting the response
    /// </summary>
    public ClientMetadataBuilderContext WithJwks(JsonWebKeySet? jwks)
    {
        if (jwks == null)
            return this;

        if (ValidateNoPrivateKeysInJwks(jwks))
        {
            _errors.Add(new ValidationError("JWKS contains private keys - only public keys allowed", "private_keys_in_jwks"));
            return this;
        }

        if (!ValidateAllKeysHaveKid(jwks))
        {
            _errors.Add(new ValidationError("All keys in JWKS must have a 'kid' (Key ID) parameter. The kid is used by the wallet to identify which key to use for encrypting the response.", "missing_kid_in_jwks"));
            return this;
        }

        if (!ValidateAllKeysHaveAlg(jwks))
        {
            _errors.Add(new ValidationError("All keys in JWKS must have an 'alg' (Algorithm) parameter. The alg specifies which algorithm this key can be used with (e.g., RS256, ES256, RSA-OAEP).", "missing_alg_in_jwks"));
            return this;
        }

        if (!ValidateAllKeysHaveUseEncryption(jwks))
        {
            _errors.Add(new ValidationError("All keys in JWKS must have 'use' (Key Usage) set to 'enc' (encryption). These keys are used to encrypt the authorization response.", "invalid_key_use_in_jwks"));
            return this;
        }

        try
        {
            _jwks = JwksBuilder.ConvertToJsonElement(jwks);
        }
        catch (Exception ex)
        {
            _errors.Add(new ValidationError($"Failed to convert JWKS: {ex.Message}", "jwks_conversion_error"));
        }

        return this;
    }

    /// <summary>
    /// Sets the JWKS by extracting the public key from an RSA private key.
    /// The extracted public key will be used by the Wallet to encrypt the authorization response.
    /// 
    /// This method automatically determines and sets a recommended JWE "enc" (content encryption) 
    /// algorithm based on the RSA key size:
    /// - RSA 2048: A128GCM
    /// - RSA 3072: A192GCM
    /// - RSA 4096+: A256GCM
    /// 
    /// IMPORTANT: Always provide an explicit, consistent keyId that matches what the wallet
    /// will use to encrypt the response. The wallet uses the kid to identify which public key
    /// to use for encrypting the authorization response sent back to the verifier.
    /// If no keyId is provided, a random one will be auto-generated.
    /// </summary>
    /// <param name="rsaPrivateKey">RSA private key from which to extract the public key</param>
    /// <param name="keyId">The key ID (kid). IMPORTANT: Use a consistent, explicit ID that the wallet can reference. 
    ///                      If null, a random ID will be generated.</param>
    public ClientMetadataBuilderContext WithPublicKeysFromRsaPrivateKey(RsaSecurityKey? rsaPrivateKey, string? keyId = null)
    {
        if (rsaPrivateKey == null)
        {
            _errors.Add(new ValidationError("RSA private key cannot be null", "validation_error"));
            return this;
        }

        var jwksResult = JwksBuilder.CreatePublicKeySet(rsaPrivateKey, keyId, keyUsage: "enc");
        if (!jwksResult.IsSuccess)
        {
            _errors.AddRange(jwksResult.Errors);
            return this;
        }

        try
        {
            _jwks = JwksBuilder.ConvertToJsonElement(jwksResult.Value);
        }
        catch (Exception ex)
        {
            _errors.Add(new ValidationError($"Failed to convert JWKS: {ex.Message}", "jwks_conversion_error"));
        }

        // Automatically add the recommended enc algorithm based on key size
        var encAlgorithm = JwksBuilder.DeriveRecommendedEncAlgorithm(rsaPrivateKey);
        AddEncryptedResponseEncValue(encAlgorithm);

        return this;
    }

    /// <summary>
    /// Sets the JWKS by extracting the public key from an ECDSA private key.
    /// The extracted public key will be used by the Wallet to encrypt the authorization response.
    /// 
    /// This method automatically determines and sets a recommended JWE "enc" (content encryption) 
    /// algorithm based on the ECDSA curve:
    /// - P-256: A128GCM
    /// - P-384: A192GCM
    /// - P-521: A256GCM
    /// 
    /// IMPORTANT: Always provide an explicit, consistent keyId that matches what the wallet
    /// will use to encrypt the response. The wallet uses the kid to identify which public key
    /// to use for encrypting the authorization response sent back to the verifier.
    /// If no keyId is provided, a random one will be auto-generated.
    /// </summary>
    /// <param name="ecdsaPrivateKey">ECDSA private key from which to extract the public key</param>
    /// <param name="keyId">The key ID (kid). IMPORTANT: Use a consistent, explicit ID that the wallet can reference. 
    ///                      If null, a random ID will be generated.</param>
    public ClientMetadataBuilderContext WithPublicKeysFromEcdsaPrivateKey(ECDsaSecurityKey? ecdsaPrivateKey, string? keyId = null)
    {
        if (ecdsaPrivateKey == null)
        {
            _errors.Add(new ValidationError("ECDSA private key cannot be null", "validation_error"));
            return this;
        }

        var jwksResult = JwksBuilder.CreatePublicKeySet(ecdsaPrivateKey, keyId, keyUsage: "enc");
        if (!jwksResult.IsSuccess)
        {
            _errors.AddRange(jwksResult.Errors);
            return this;
        }

        try
        {
            _jwks = JwksBuilder.ConvertToJsonElement(jwksResult.Value);
        }
        catch (Exception ex)
        {
            _errors.Add(new ValidationError($"Failed to convert JWKS: {ex.Message}", "jwks_conversion_error"));
        }

        // Automatically add the recommended enc algorithm based on curve
        var encAlgorithm = JwksBuilder.DeriveRecommendedEncAlgorithm(ecdsaPrivateKey);
        AddEncryptedResponseEncValue(encAlgorithm);

        return this;
    }

    /// <summary>
    /// Sets the JWKS by extracting public keys from multiple private keys.
    /// The extracted public keys will be used by the Wallet to encrypt the authorization response.
    /// 
    /// This method automatically determines and sets a recommended JWE "enc" (content encryption) 
    /// algorithm based on the strongest key in the collection.
    /// </summary>
    /// <param name="privateKeys">Collection of private keys from which to extract public keys</param>
    public ClientMetadataBuilderContext WithPublicKeysFromPrivateKeys(IEnumerable<SecurityKey>? privateKeys)
    {
        if (privateKeys == null || !privateKeys.Any())
        {
            _errors.Add(new ValidationError("Private keys collection cannot be null or empty", "validation_error"));
            return this;
        }

        var jwksResult = JwksBuilder.CreatePublicKeySet(privateKeys, keyUsage: "enc");
        if (!jwksResult.IsSuccess)
        {
            _errors.AddRange(jwksResult.Errors);
            return this;
        }

        try
        {
            _jwks = JwksBuilder.ConvertToJsonElement(jwksResult.Value);
        }
        catch (Exception ex)
        {
            _errors.Add(new ValidationError($"Failed to convert JWKS: {ex.Message}", "jwks_conversion_error"));
        }

        // Automatically add the recommended enc algorithm based on the first key
        var firstKey = privateKeys.FirstOrDefault();
        if (firstKey != null)
        {
            var encAlgorithm = JwksBuilder.DeriveRecommendedEncAlgorithm(firstKey);
            AddEncryptedResponseEncValue(encAlgorithm);
        }

        return this;
    }

    /// <summary>
    /// Adds an encryption algorithm to the supported encrypted response enc values.
    /// INTERNAL USE ONLY - automatically called by WithPublicKeysFromRsaPrivateKey and WithPublicKeysFromEcdsaPrivateKey.
    /// </summary>
    private ClientMetadataBuilderContext AddEncryptedResponseEncValue(string encAlgorithm)
    {
        if (string.IsNullOrWhiteSpace(encAlgorithm))
        {
            _errors.Add(new ValidationError("Encryption algorithm cannot be null or empty", "validation_error"));
            return this;
        }

        _encryptedResponseEncValues ??= [];
        _encryptedResponseEncValues.Add(encAlgorithm);
        return this;
    }

    /// <summary>
    /// Sets the supported VP formats for this Verifier.
    /// </summary>
    public ClientMetadataBuilderContext WithVpFormatsSupported(VpFormatsSupported? vpFormatsSupported)
    {
        _vpFormatsSupported = vpFormatsSupported;
        return this;
    }

    /// <summary>
    /// Adds extension data as arbitrary JSON.
    /// </summary>
    public ClientMetadataBuilderContext WithExtensionData(string key, JsonElement value)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            _errors.Add(new ValidationError("Extension data key cannot be null or empty", "validation_error"));
            return this;
        }

        _extensionData ??= [];
        _extensionData[key] = value;
        return this;
    }

    /// <summary>
    /// Builds the ClientMetadata object, returning a Result that includes any accumulated errors.
    /// </summary>
    public Result<ClientMetadata> Build()
    {
        if (_errors.Count > 0)
            return Result<ClientMetadata>.Failure(_errors);

        // Per spec: A128GCM is the default and SHOULD be absent from encrypted_response_enc_values_supported
        // If only A128GCM is in the list, set to null (absence) instead
        var encValues = _encryptedResponseEncValues;
        if (encValues != null && encValues.Count == 1 && encValues[0] == "A128GCM")
        {
            encValues = null;
        }

        var clientMetadata = new ClientMetadata
        {
            ClientName = _clientName,
            LogoUri = _logoUri,
            JwksUri = _jwksUri,
            Jwks = _jwks,
            EncryptedResponseEncValuesSupported = encValues?.AsReadOnly(),
            VpFormatsSupported = _vpFormatsSupported,
            ExtensionData = _extensionData
        };

        return clientMetadata;
    }

    /// <summary>
    /// Checks if a JWKS contains any private keys (which is not allowed).
    /// </summary>
    private static bool ValidateNoPrivateKeysInJwks(JsonWebKeySet jwks)
    {
        return jwks.Keys.Any(key => key.HasPrivateKey);
    }

    /// <summary>
    /// Validates that all keys in the JWKS have a "kid" (Key ID) parameter.
    /// The kid is essential for the wallet/holder to identify which key to use for decryption.
    /// Returns true if validation passes (all keys have kid), false if any key is missing kid.
    /// </summary>
    private static bool ValidateAllKeysHaveKid(JsonWebKeySet jwks)
    {
        // Check if any key is missing a kid
        return !jwks.Keys.Any(key => string.IsNullOrWhiteSpace(key.KeyId));
    }

    /// <summary>
    /// Validates that all keys in the JWKS have an "alg" (Algorithm) parameter.
    /// The alg is essential for the wallet to know which algorithm this key supports.
    /// Returns true if validation passes (all keys have alg), false if any key is missing alg.
    /// </summary>
    private static bool ValidateAllKeysHaveAlg(JsonWebKeySet jwks)
    {
        // Check if any key is missing an alg
        return !jwks.Keys.Any(key => string.IsNullOrWhiteSpace(key.Alg));
    }

    /// <summary>
    /// Validates that all keys in the JWKS have "use" (Key Usage) set to "enc" (encryption).
    /// These keys are specifically for encrypting the authorization response, so they must be marked for encryption use.
    /// Returns true if validation passes (all keys have use="enc"), false if any key is missing or has different use.
    /// </summary>
    private static bool ValidateAllKeysHaveUseEncryption(JsonWebKeySet jwks)
    {
        // Check if any key is missing use or doesn't have use="enc"
        return !jwks.Keys.Any(key => string.IsNullOrWhiteSpace(key.Use) || key.Use != "enc");
    }
}
