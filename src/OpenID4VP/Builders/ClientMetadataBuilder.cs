using System.Text.Json;
using OpenID4VP.Models;

namespace OpenID4VP.Builders;

/// <summary>
/// Builder for creating ClientMetadata objects.
/// Supports building complete metadata with JWKS, encryption preferences, and format support.
/// </summary>
public sealed class ClientMetadataBuilder
{
    private string? _clientName;
    private string? _logoUri;
    private string? _jwksUri;
    private JsonElement? _jwks;
    private List<string>? _encryptedResponseEncValues;
    private JsonElement? _vpFormatsSupported;
    private Dictionary<string, JsonElement>? _extensionData;

    public static ClientMetadataBuilder Create() => new();

    public ClientMetadataBuilder WithClientName(string? clientName)
    {
        _clientName = clientName;
        return this;
    }

    public ClientMetadataBuilder WithLogoUri(string? logoUri)
    {
        _logoUri = logoUri;
        return this;
    }

    public ClientMetadataBuilder WithJwksUri(string? jwksUri)
    {
        _jwksUri = jwksUri;
        return this;
    }

    public ClientMetadataBuilder WithJwks(JsonElement jwks)
    {
        _jwks = jwks;
        return this;
    }

    public ClientMetadataBuilder AddEncryptedResponseEncValue(string encAlgorithm)
    {
        if (string.IsNullOrWhiteSpace(encAlgorithm))
            throw new ArgumentException("Encryption algorithm cannot be null or empty", nameof(encAlgorithm));

        _encryptedResponseEncValues ??= [];
        _encryptedResponseEncValues.Add(encAlgorithm);
        return this;
    }

    public ClientMetadataBuilder WithVpFormatsSupported(JsonElement vpFormatsSupported)
    {
        _vpFormatsSupported = vpFormatsSupported;
        return this;
    }

    public ClientMetadata Build()
    {
        return new ClientMetadata
        {
            ClientName = _clientName,
            LogoUri = _logoUri,
            JwksUri = _jwksUri,
            Jwks = _jwks,
            EncryptedResponseEncValuesSupported = _encryptedResponseEncValues?.AsReadOnly(),
            VpFormatsSupported = _vpFormatsSupported,
            ExtensionData = _extensionData
        };
    }
}
