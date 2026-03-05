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
    private JsonWebKeySet? _jwks;  // Single collection for all keys (from WithJwks or WithPublicKey* methods)
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
    /// 
    /// Validation of the JWKS (private keys, required fields) is deferred to Build() to allow
    /// accumulation of multiple keys and batch validation.
    /// </summary>
    public ClientMetadataBuilderContext WithJwks(JsonWebKeySet? jwks)
    {
        if (jwks == null || jwks.Keys.Count == 0)
            return this;

        try
        {
            // Add all keys from the provided JWKS to the collection
            _jwks ??= new JsonWebKeySet();
            foreach (var key in jwks.Keys)
            {
                _jwks.Keys.Add(key);
            }
        }
        catch (Exception ex)
        {
            _errors.Add(new ValidationError($"Failed to add keys from JWKS: {ex.Message}", "key_addition_error"));
        }

        return this;
    }

    /// <summary>
    /// Adds a public key extracted from an RSA private key to the JWKS.
    /// This method can be called multiple times to compose a set of keys.
    /// The extracted public key will be used by the Wallet to encrypt the authorization response.
    /// 
    /// The RSA key MUST have a KeyId set - this will be used as the 'kid' in the JWKS.
    /// </summary>
    /// <param name="rsaPrivateKey">RSA private key from which to extract the public key. Must have KeyId set.</param>
    /// <param name="alg">The key encryption algorithm (e.g., RSA-OAEP-256). Default: RSA-OAEP-256</param>
    /// <param name="enc">The content encryption algorithm (e.g., A256GCM). Default: A256GCM</param>
    public ClientMetadataBuilderContext WithPublicKeyFromRsaPrivateKey(
        RsaSecurityKey? rsaPrivateKey,
        string alg = "RSA-OAEP-256",
        string enc = "A256GCM")
    {
        if (rsaPrivateKey == null)
        {
            _errors.Add(new ValidationError("RSA private key cannot be null", "validation_error"));
            return this;
        }

        if (string.IsNullOrWhiteSpace(rsaPrivateKey.KeyId))
        {
            _errors.Add(new ValidationError("RSA private key must have a KeyId set", "missing_key_id"));
            return this;
        }

        var jwkResult = JwksBuilder.CreatePublicKey(rsaPrivateKey, rsaPrivateKey.KeyId, keyUsage: "enc");
        if (!jwkResult.IsSuccess)
        {
            _errors.AddRange(jwkResult.Errors);
            return this;
        }

        try
        {
            // Add the key to the collection
            _jwks ??= new JsonWebKeySet();
            var jwk = jwkResult.Value;
            jwk.Alg = alg;
            _jwks.Keys.Add(jwk);
        }
        catch (Exception ex)
        {
            _errors.Add(new ValidationError($"Failed to add RSA key to JWKS: {ex.Message}", "key_addition_error"));
        }

        // Add the explicit enc algorithm
        AddEncryptedResponseEncValue(enc);

        return this;
    }

    /// <summary>
    /// Adds a public key extracted from an ECDSA private key to the JWKS.
    /// This method can be called multiple times to compose a set of keys.
    /// The extracted public key will be used by the Wallet to encrypt the authorization response.
    /// 
    /// The ECDSA key MUST have a KeyId set - this will be used as the 'kid' in the JWKS.
    /// </summary>
    /// <param name="ecdsaPrivateKey">ECDSA private key from which to extract the public key. Must have KeyId set.</param>
    /// <param name="alg">The key encryption algorithm (e.g., ECDH-ES+A256KW). Default: ECDH-ES+A256KW</param>
    /// <param name="enc">The content encryption algorithm (e.g., A256GCM). Default: A256GCM</param>
    public ClientMetadataBuilderContext WithPublicKeyFromEcdsaPrivateKey(
        ECDsaSecurityKey? ecdsaPrivateKey,
        string alg = "ECDH-ES+A256KW",
        string enc = "A256GCM")
    {
        if (ecdsaPrivateKey == null)
        {
            _errors.Add(new ValidationError("ECDSA private key cannot be null", "validation_error"));
            return this;
        }

        if (string.IsNullOrWhiteSpace(ecdsaPrivateKey.KeyId))
        {
            _errors.Add(new ValidationError("ECDSA private key must have a KeyId set", "missing_key_id"));
            return this;
        }

        var jwkResult = JwksBuilder.CreatePublicKey(ecdsaPrivateKey, ecdsaPrivateKey.KeyId, keyUsage: "enc");
        if (!jwkResult.IsSuccess)
        {
            _errors.AddRange(jwkResult.Errors);
            return this;
        }

        try
        {
            // Add the key to the collection
            _jwks ??= new JsonWebKeySet();
            var jwk = jwkResult.Value;
            jwk.Alg = alg;
            _jwks.Keys.Add(jwk);
        }
        catch (Exception ex)
        {
            _errors.Add(new ValidationError($"Failed to add ECDSA key to JWKS: {ex.Message}", "key_addition_error"));
        }

        // Add the explicit enc algorithm
        AddEncryptedResponseEncValue(enc);

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
            return _errors.Cast<Error>().ToArray();

        JsonElement? finalJwks = null;

        // Validate the JWKS if any keys were added
        if (_jwks != null && _jwks.Keys.Count > 0)
        {
            // Validate the JWKS
            if (ValidateNoPrivateKeysInJwks(_jwks))
            {
                return new ValidationError("JWKS contains private keys - only public keys allowed", "private_keys_in_jwks");
            }

            if (!ValidateAllKeysHaveKid(_jwks))
            {
                return new ValidationError("All keys in JWKS must have a 'kid' (Key ID) parameter. The kid is used by the wallet to identify which key to use for encrypting the response.", "missing_kid_in_jwks");
            }

            if (!ValidateAllKeysHaveAlg(_jwks))
            {
                return new ValidationError("All keys in JWKS must have an 'alg' (Algorithm) parameter. The alg specifies which algorithm this key can be used with (e.g., RS256, ES256, RSA-OAEP).", "missing_alg_in_jwks");
            }

            if (!ValidateAllKeysHaveUseEncryption(_jwks))
            {
                return new ValidationError("All keys in JWKS must have 'use' (Key Usage) set to 'enc' (encryption). These keys are used to encrypt the authorization response.", "invalid_key_use_in_jwks");
            }

            // Convert to JsonElement for storage
            try
            {
                finalJwks = JwksBuilder.ConvertToJsonElement(_jwks);
            }
            catch (Exception ex)
            {
                return new ValidationError($"Failed to convert JWKS: {ex.Message}", "jwks_conversion_error");
            }
        }

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
            Jwks = finalJwks,
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
