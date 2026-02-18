using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using OpenID4VP.Models;
using OpenID4VC.Core.Results;

namespace OpenID4VP.Builders;

/// <summary>
/// Context builder for fluently configuring ClientMetadata within AuthorizationRequestBuilder.
/// 
/// This builder is designed to work inline with WithClientMetadata(), providing a fluent API
/// for constructing metadata with all available options (name, URI, JWKS, encryption preferences, etc.).
/// 
/// Pattern: .WithClientMetadata(metadata => metadata.WithName(...).WithJwksUri(...))
/// </summary>
public sealed class ClientMetadataBuilderContext
{
    private string? _clientName;
    private string? _logoUri;
    private string? _jwksUri;
    private JsonElement? _jwks;
    private List<string>? _encryptedResponseEncValues;
    private JsonElement? _vpFormatsSupported;
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
    /// Sets the JWKS (JSON Web Key Set) with public keys.
    /// The JWKS must contain ONLY public keys.
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
    /// </summary>
    /// <param name="rsaPrivateKey">RSA private key from which to extract the public key</param>
    /// <param name="keyId">Optional key ID. If not provided, a random ID will be generated.</param>
    public ClientMetadataBuilderContext WithPublicKeysFromRsaPrivateKey(RsaSecurityKey? rsaPrivateKey, string? keyId = null)
    {
        if (rsaPrivateKey == null)
        {
            _errors.Add(new ValidationError("RSA private key cannot be null", "validation_error"));
            return this;
        }

        var jwksResult = JwksBuilder.CreatePublicKeySet(rsaPrivateKey, keyId);
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

        return this;
    }

    /// <summary>
    /// Sets the JWKS by extracting the public key from an ECDSA private key.
    /// </summary>
    /// <param name="ecdsaPrivateKey">ECDSA private key from which to extract the public key</param>
    /// <param name="keyId">Optional key ID. If not provided, a random ID will be generated.</param>
    public ClientMetadataBuilderContext WithPublicKeysFromEcdsaPrivateKey(ECDsaSecurityKey? ecdsaPrivateKey, string? keyId = null)
    {
        if (ecdsaPrivateKey == null)
        {
            _errors.Add(new ValidationError("ECDSA private key cannot be null", "validation_error"));
            return this;
        }

        var jwksResult = JwksBuilder.CreatePublicKeySet(ecdsaPrivateKey, keyId);
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

        return this;
    }

    /// <summary>
    /// Sets the JWKS by extracting public keys from multiple private keys.
    /// </summary>
    /// <param name="privateKeys">Collection of private keys from which to extract public keys</param>
    public ClientMetadataBuilderContext WithPublicKeysFromPrivateKeys(IEnumerable<SecurityKey>? privateKeys)
    {
        if (privateKeys == null || !privateKeys.Any())
        {
            _errors.Add(new ValidationError("Private keys collection cannot be null or empty", "validation_error"));
            return this;
        }

        var jwksResult = JwksBuilder.CreatePublicKeySet(privateKeys);
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

        return this;
    }

    /// <summary>
    /// Adds an encryption algorithm to the supported encrypted response enc values.
    /// </summary>
    public ClientMetadataBuilderContext AddEncryptedResponseEncValue(string encAlgorithm)
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
    public ClientMetadataBuilderContext WithVpFormatsSupported(JsonElement vpFormatsSupported)
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

        var clientMetadata = new ClientMetadata
        {
            ClientName = _clientName,
            LogoUri = _logoUri,
            JwksUri = _jwksUri,
            Jwks = _jwks,
            EncryptedResponseEncValuesSupported = _encryptedResponseEncValues?.AsReadOnly(),
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
}
